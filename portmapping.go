package nethernet

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/pion/webrtc/v4"
)

// maxPortMappings is how many entries BDS takes in server-udp-ports and server-port-mappings.
const maxPortMappings = 16

// PortMapping says that local UDP ports are reached from outside at other ports and maybe another
// address, as an entry of BDS's server-udp-ports does. A connection whose local port it covers
// offers that address as a server-reflexive candidate, which BDS gets from a STUN server of its
// own inside the process.
type PortMapping struct {
	// LocalIP limits the mapping to one local address. If not valid, any.
	LocalIP netip.Addr
	// Min and Max are the local ports covered.
	Min, Max uint16
	// PublicIP is the address seen from outside. If not valid, the local one.
	PublicIP netip.Addr
	// Offset added to a local port gives the port seen from outside.
	Offset int32
}

// Map returns the address seen from outside for a local one, if the mapping covers it.
func (m PortMapping) Map(local netip.AddrPort) (netip.AddrPort, bool) {
	if m.LocalIP.IsValid() && !m.LocalIP.IsUnspecified() && m.LocalIP != local.Addr() {
		return netip.AddrPort{}, false
	}
	port := int32(local.Port()) + m.Offset
	if local.Port() < m.Min || local.Port() > m.Max || port < 0 || port >= 1<<16 {
		return netip.AddrPort{}, false
	}
	ip := m.PublicIP
	if !ip.IsValid() || ip.IsUnspecified() {
		ip = local.Addr()
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}

// ParsePortMappings parses BDS's server-udp-ports: entries split by commas, each a port or a
// range a-b, or public:local where both have the same length. A public address may come first as
// ip: or [ipv6]:, and all entries must agree on it. publicIP applies to entries without one, as
// BDS's server-public-ip does.
func ParsePortMappings(s string, publicIP netip.Addr) ([]PortMapping, error) {
	var mappings []PortMapping
	var entryIP netip.Addr
	for entry := range strings.SplitSeq(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		rest, ip, err := cutIPPrefix(entry)
		if err != nil {
			return nil, err
		}
		if ip.IsValid() {
			if entryIP.IsValid() && entryIP != ip {
				return nil, fmt.Errorf("conflicting per-entry IPs ('%s' vs '%s')", entryIP, ip)
			}
			entryIP = ip
		}
		public, local, mapped := strings.Cut(rest, ":")
		if !mapped {
			local = public
		}
		pubMin, pubMax, err := parsePortRange(public, entry)
		if err != nil {
			return nil, err
		}
		locMin, locMax, err := parsePortRange(local, entry)
		if err != nil {
			return nil, err
		}
		if pubMax-pubMin != locMax-locMin {
			return nil, fmt.Errorf("entry '%s' has mismatched range lengths", entry)
		}
		mappings = append(mappings, PortMapping{Min: locMin, Max: locMax, Offset: int32(pubMin) - int32(locMin)})
	}
	if len(mappings) > maxPortMappings {
		return nil, fmt.Errorf("too many port mappings (max %d)", maxPortMappings)
	}
	if !entryIP.IsValid() {
		entryIP = publicIP
	}
	for i := range mappings {
		mappings[i].PublicIP = entryIP
	}
	return mappings, nil
}

// cutIPPrefix takes the public address off the front of an entry, if it has one.
func cutIPPrefix(entry string) (rest string, ip netip.Addr, err error) {
	if strings.HasPrefix(entry, "[") {
		v6, after, ok := strings.Cut(entry[1:], "]:")
		if !ok {
			return "", netip.Addr{}, errors.New("malformed bracketed IPv6 prefix")
		}
		if ip, err = netip.ParseAddr(v6); err != nil {
			return "", netip.Addr{}, fmt.Errorf("malformed bracketed IPv6 prefix: %w", err)
		}
		return after, ip, nil
	}
	first, after, ok := strings.Cut(entry, ":")
	if !ok || !strings.Contains(first, ".") {
		return entry, netip.Addr{}, nil
	}
	if ip, err = netip.ParseAddr(first); err != nil {
		return "", netip.Addr{}, fmt.Errorf("entry '%s': %w", entry, err)
	}
	return after, ip, nil
}

// parsePortRange parses a port or a range a-b.
func parsePortRange(s, entry string) (lo, hi uint16, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("entry '%s' has empty port token", entry)
	}
	first, last, isRange := strings.Cut(s, "-")
	if !isRange {
		last = first
	}
	a, err := strconv.ParseUint(first, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("entry '%s': %w", entry, err)
	}
	b, err := strconv.ParseUint(last, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("entry '%s': %w", entry, err)
	}
	if b < a {
		return 0, 0, fmt.Errorf("reversed port range '%s'", s)
	}
	return uint16(a), uint16(b), nil
}

// PortRange returns the lowest and highest local port of the mappings, for
// [webrtc.SettingEngine.SetEphemeralUDPPortRange].
func PortRange(mappings []PortMapping) (lo, hi uint16) {
	for i, m := range mappings {
		if i == 0 || m.Min < lo {
			lo = m.Min
		}
		hi = max(hi, m.Max)
	}
	return lo, hi
}

// srflxTypePreference is the ICE type preference of a server-reflexive candidate (RFC 8445).
const srflxTypePreference = 100

// mappedCandidates returns the server-reflexive candidates the mappings give for local host
// candidates, without repeats, as answers from BDS's STUN server inside the process would.
func mappedCandidates(mappings []PortMapping, candidates []webrtc.ICECandidate) []webrtc.ICECandidate {
	var out []webrtc.ICECandidate
	for _, c := range candidates {
		out = append(out, mappedCandidate(mappings, c, out)...)
	}
	return out
}

// mappedCandidate is [mappedCandidates] for one local candidate, skipping those in seen.
func mappedCandidate(mappings []PortMapping, c webrtc.ICECandidate, seen []webrtc.ICECandidate) []webrtc.ICECandidate {
	if c.Typ != webrtc.ICECandidateTypeHost || c.Protocol != webrtc.ICEProtocolUDP {
		return nil
	}
	addr, err := netip.ParseAddr(c.Address)
	if err != nil {
		return nil
	}
	var out []webrtc.ICECandidate
	local := netip.AddrPortFrom(addr.Unmap(), c.Port)
	for _, m := range mappings {
		public, ok := m.Map(local)
		if !ok || public == local {
			continue
		}
		same := func(o webrtc.ICECandidate) bool {
			return o.Address == public.Addr().String() && o.Port == public.Port()
		}
		if slices.ContainsFunc(seen, same) || slices.ContainsFunc(out, same) {
			continue
		}
		// The rest of the priority keeps the host candidate's place among candidates.
		priority := srflxTypePreference<<24 | c.Priority&0x00FFFFFF
		out = append(out, webrtc.ICECandidate{
			Foundation:     "s" + c.Foundation,
			Priority:       priority,
			Address:        public.Addr().String(),
			Protocol:       webrtc.ICEProtocolUDP,
			Port:           public.Port(),
			Typ:            webrtc.ICECandidateTypeSrflx,
			Component:      c.Component,
			RelatedAddress: c.Address,
			RelatedPort:    c.Port,
		})
	}
	return out
}
