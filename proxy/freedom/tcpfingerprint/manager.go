package tcpfingerprint

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

type backend interface {
	Start() error
	Close() error
	SocketControl(*Fingerprint) (func(string, string, syscall.RawConn) error, func(net.Conn))
}

type Manager struct {
	backend
	trusted []netip.Prefix
}

func New(queue uint32, trusted []string) (*Manager, error) {
	if queue == 0 || queue > 65535 || len(trusted) == 0 {
		return nil, fmt.Errorf("tcpFingerprint requires a queue from 1 to 65535 and trustedPeers")
	}
	peers := make([]netip.Prefix, 0, len(trusted))
	for _, source := range trusted {
		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			if addr, parseErr := netip.ParseAddr(source); parseErr == nil && addr.Zone() == "" {
				addr = addr.Unmap()
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		}
		if !prefix.IsValid() || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid tcpFingerprint trusted peer %q", source)
		}
		peers = append(peers, prefix.Masked())
	}
	b, err := newBackend(uint16(queue))
	if err != nil {
		return nil, err
	}
	return &Manager{backend: b, trusted: peers}, nil
}

func (m *Manager) Read(conn net.Conn) *Fingerprint {
	return FromConnection(conn, m.trusted)
}
