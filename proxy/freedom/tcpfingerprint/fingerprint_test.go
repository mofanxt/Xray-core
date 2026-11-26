package tcpfingerprint

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"

	"github.com/pires/go-proxyproto"
)

var apple = []byte{
	1, 64, 1, 255, 255, 20,
	2, 4, 5, 180, 1, 3, 3, 6,
	1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0,
}

func TestDecodeCompatibility(t *testing.T) {
	for _, input := range [][]byte{apple, []byte("v1:" + hex.EncodeToString(apple))} {
		got := decode(input)
		if got == nil || got.window != 65535 || !got.zeroID || got.windowClamp() != 65535<<6 {
			t.Fatalf("unexpected fingerprint: %+v", got)
		}
	}
	for _, input := range [][]byte{nil, []byte("v1:abcdZ"), apple[:len(apple)-1]} {
		if decode(input) != nil {
			t.Fatalf("accepted invalid sample %x", input)
		}
	}
	for _, field := range []int{0, 1, 2, 5, 7, 13, 18} {
		data := bytes.Clone(apple)
		data[field] = 254
		if decode(data) != nil {
			t.Fatalf("accepted malformed byte %d", field)
		}
	}
}

func TestFromConnectionUsesPhysicalPeer(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	claimed := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 1234}
	header := proxyproto.HeaderProxyFromAddrs(2, claimed, listener.Addr())
	if err := header.SetTLVs([]proxyproto.TLV{{Type: privateTLV, Value: apple}}); err != nil {
		t.Fatal(err)
	}
	if _, err := header.WriteTo(client); err != nil {
		t.Fatal(err)
	}
	proxied := proxyproto.NewConn(server)
	if FromConnection(proxied, []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}) != nil {
		t.Fatal("trusted the address in the header instead of the actual peer")
	}
	if FromConnection(proxied, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}) == nil {
		t.Fatal("discarded the fingerprint from a trusted peer")
	}
	if err := header.SetTLVs([]proxyproto.TLV{
		{Type: privateTLV, Value: nil},
		{Type: privateTLV, Value: apple},
	}); err != nil {
		t.Fatal(err)
	}
	if fromHeader(header) != nil {
		t.Fatal("accepted duplicate fingerprint TLVs")
	}
}

func TestRewritePreservesKernelNegotiation(t *testing.T) {
	f := decode(apple)
	// 内核 SYN 的 MSS、时间戳和选项顺序与样本不同。
	p := make([]byte, 60)
	p[0], p[4], p[6], p[8], p[9], p[32], p[33] = 0x45, 12, 0x40, 60, 6, 0xa0, 0xc2
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	copy(p[24:28], []byte{1, 2, 3, 4})
	copy(p[40:], []byte{2, 4, 5, 120, 4, 2, 8, 10, 7, 6, 5, 4, 0, 0, 0, 0, 1, 3, 3, 6})

	got := f.rewriteSYN(p)
	if len(got) != len(p) {
		t.Fatalf("packet has length %d", len(got))
	}
	if got[8] != 64 || binary.BigEndian.Uint16(got[4:6]) != 0 ||
		binary.BigEndian.Uint16(got[34:36]) != 65535 || got[33] != 0xc2 ||
		!bytes.Equal(got[24:28], p[24:28]) {
		t.Fatalf("incorrect SYN fields: %x", got[:40])
	}
	want := bytes.Clone(apple[6:])
	copy(want[2:4], p[42:44])
	copy(want[12:16], p[48:52])
	if checksum(got[:20]) != 0 || checksum(got[12:20], []byte{0, 6, 0, 40}, got[20:]) != 0 ||
		!bytes.Equal(got[40:], want) {
		t.Fatalf("invalid checksum or TCP options: %x", got)
	}
	p[59] = 9
	if f.rewriteSYN(p) != nil {
		t.Fatal("rewrote an incompatible socket window scale")
	}
	p[59] = 6
	if f.rewriteSYN(append(p, 123)) != nil {
		t.Fatal("discarded SYN payload")
	}
}
