package endpoint

import "testing"

// parseRequest reads whatever a client sends before the handler sees it. It must never panic.
func FuzzParseRequest(f *testing.F) {
	f.Add([]byte("GET /v1/join HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Add([]byte("POST /v1/join/1 HTTP/1.1\r\nContent-Length: 3\r\n\r\nv=0"))
	f.Add([]byte("\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = parseRequest(b)
	})
}
