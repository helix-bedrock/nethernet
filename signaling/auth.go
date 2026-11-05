package signaling

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is defined as a SHA-1 thumbprint, not used for security
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pkcs12"
)

const (
	// CertificateFile is the file BDS reads its certificate from, in its working folder.
	CertificateFile = "AppCertificate.pfx"
	// DefaultDiscoveryURL is Minecraft's service discovery.
	DefaultDiscoveryURL = "https://client.discovery.minecraft-services.net"
	// signalingScope is what BDS asks Azure AD for in production.
	signalingScope = "api://mcsignaling/.default"
	// defaultTokenURL is Azure AD's token endpoint, {} being the tenant.
	defaultTokenURL = "https://login.microsoftonline.com"
	// assertionLifetime is how long the signed request to Azure AD lasts.
	assertionLifetime = time.Hour
	// tokenMargin renews a token this long before it expires.
	tokenMargin = time.Minute
	// maxReply caps replies read from Microsoft's services.
	maxReply = 1 << 20
	// assertionType is the kind of client assertion sent.
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// AzureAuth gets access tokens from Azure AD with a client assertion, as BDS's AuthHelper does.
// ApplicationID, TenantID and the certificate are the server owner's: BDS's application-id,
// application-tenant-id and AppCertificate.pfx. Microsoft decides whether that application may use
// the signaling service.
type AzureAuth struct {
	ApplicationID, TenantID string
	Key                     *rsa.PrivateKey
	Certificate             *x509.Certificate
	// TokenURL replaces Azure AD's address, for tests.
	TokenURL string
	// HTTPClient makes the requests. If nil, one with a 15 second timeout.
	HTTPClient *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// LoadCertificate reads a key and certificate from a PKCS#12 file without a password, or from PEM.
func LoadCertificate(path string) (*rsa.PrivateKey, *x509.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // a path the server owner configures
	if err != nil {
		return nil, nil, fmt.Errorf("signaling: certificate: %w", err)
	}
	blocks := []*pem.Block{}
	for rest := data; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		if blocks, err = pkcs12.ToPEM(data, ""); err != nil {
			return nil, nil, fmt.Errorf("signaling: certificate %s: %w", path, err)
		}
	}
	var key *rsa.PrivateKey
	var cert *x509.Certificate
	for _, b := range blocks {
		if strings.HasSuffix(b.Type, "PRIVATE KEY") && key == nil {
			key = parseRSAKey(b.Bytes)
		}
		if b.Type == "CERTIFICATE" && cert == nil {
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				cert = c
			}
		}
	}
	if key == nil || cert == nil {
		return nil, nil, fmt.Errorf("signaling: certificate %s: no RSA key and certificate in it", path)
	}
	return key, cert, nil
}

// parseRSAKey parses an RSA key in either form, or returns nil.
func parseRSAKey(der []byte) *rsa.PrivateKey {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if r, ok := k.(*rsa.PrivateKey); ok {
			return r
		}
	}
	return nil
}

// Token returns an access token for the signaling service, kept until near its expiry.
func (a *AzureAuth) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Now().Before(a.expires) {
		return a.token, nil
	}
	base := a.TokenURL
	if base == "" {
		base = defaultTokenURL
	}
	endpoint := strings.TrimRight(base, "/") + "/" + url.PathEscape(a.TenantID) + "/oauth2/v2.0/token"
	assertion, err := a.assertion(endpoint)
	if err != nil {
		return "", err
	}
	form := "client_id=" + url.QueryEscape(a.ApplicationID) + "&scope=" + url.QueryEscape(signalingScope) +
		"&grant_type=client_credentials&client_assertion_type=" + url.QueryEscape(assertionType) +
		"&client_assertion=" + url.QueryEscape(assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form))
	if err != nil {
		return "", fmt.Errorf("signaling: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("signaling: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	if err != nil {
		return "", fmt.Errorf("signaling: token reply: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signaling: Azure AD said %s: %s", resp.Status, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("signaling: token reply: %w", err)
	}
	if out.AccessToken == "" {
		return "", errors.New("signaling: Azure AD gave no token")
	}
	a.token = out.AccessToken
	a.expires = time.Now().Add(time.Duration(out.ExpiresIn)*time.Second - tokenMargin)
	return a.token, nil
}

// assertion is the signed request: a JWT with aud, iss, sub, nbf, exp and jti, as BDS's. RS256 and
// x5t are what Azure AD asks for; BDS's header was not read field by field.
func (a *AzureAuth) assertion(audience string) (string, error) {
	if a.Key == nil || a.Certificate == nil {
		return "", errors.New("signaling: no certificate")
	}
	jti, err := newUUID()
	if err != nil {
		return "", err
	}
	thumb := sha1.Sum(a.Certificate.Raw) //nolint:gosec // see the import
	enc := base64.RawURLEncoding
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "x5t": enc.EncodeToString(thumb[:])})
	if err != nil {
		return "", fmt.Errorf("signaling: assertion: %w", err)
	}
	now := time.Now().Unix()
	claims, err := json.Marshal(map[string]any{
		"aud": audience, "iss": a.ApplicationID, "sub": a.ApplicationID, "nbf": now,
		"exp": now + int64(assertionLifetime/time.Second), "jti": jti,
	})
	if err != nil {
		return "", fmt.Errorf("signaling: assertion: %w", err)
	}
	signed := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("signaling: assertion: %w", err)
	}
	return signed + "." + enc.EncodeToString(sig), nil
}

// Discover asks Minecraft's service discovery for the signaling service's address, as a dedicated
// server, for a game version and environment such as "prod".
func Discover(ctx context.Context, client *http.Client, discoveryURL, build, environment string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	u, err := url.Parse(discoveryURL)
	if err != nil {
		return "", fmt.Errorf("signaling: discovery: %w", err)
	}
	u = u.JoinPath("/api/v1.0/discovery/MinecraftDedicatedServer/builds", build)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("signaling: discovery: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("signaling: discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	if err != nil {
		return "", fmt.Errorf("signaling: discovery: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signaling: discovery said %s", resp.Status)
	}
	var out struct {
		Result struct {
			ServiceEnvironments map[string]map[string]struct {
				ServiceURI string `json:"serviceUri"`
			} `json:"serviceEnvironments"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("signaling: discovery: %w", err)
	}
	uri := out.Result.ServiceEnvironments["signaling"][environment].ServiceURI
	if uri == "" {
		return "", errors.New("signaling: discovery names no signaling service")
	}
	return uri, nil
}
