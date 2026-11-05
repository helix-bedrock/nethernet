package discovery

import (
	"net"
	"net/netip"
)

const (
	// maxPeers is how many senders a Listener remembers at once. Senders choose their own IDs, so
	// without it one host could fill memory with made-up ones.
	maxPeers = 1024
)

// sharedAddressSpace is 100.64.0.0/10, used by carrier NAT and by VPNs such as Tailscale.
var sharedAddressSpace = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)

// localNetworks are the networks of this host's interfaces.
func localNetworks() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		if p, err := ip.Unmap().Prefix(ones); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// isLocal reports whether a packet from addr can come from this network: a loopback, private,
// link-local or shared address, or one on a network of this host. LAN discovery is broadcast on
// the local network, so anything else is someone on the internet, who could otherwise use the
// replies to flood a forged source address.
func (l *Listener) isLocal(addr net.Addr) bool {
	if l.conf.AllowPublic {
		return true
	}
	u, ok := addr.(*net.UDPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(u.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || sharedAddressSpace.Contains(ip) {
		return true
	}
	for _, p := range l.networks {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
