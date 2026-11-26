package tcpfingerprint

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const privateTLV = 0xe0

type Fingerprint struct {
	ttl     byte
	window  uint16
	zeroID  bool
	options []byte
}

// FromConnection 在入站完成认证后读取 PROXY v2 指纹，按真实套接字对端校验来源。
func FromConnection(conn net.Conn, peers []netip.Prefix) *Fingerprint {
	conn = stat.TryUnwrapStatsConn(conn)
	if tls, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = tls.NetConn()
	}
	proxied, ok := conn.(*proxyproto.Conn)
	if !ok {
		return nil
	}
	peer, ok := proxied.Raw().RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	addr := peer.AddrPort().Addr().Unmap()
	for _, prefix := range peers {
		if prefix.Contains(addr) {
			return fromHeader(proxied.ProxyHeader())
		}
	}
	return nil
}

func fromHeader(header *proxyproto.Header) *Fingerprint {
	if header == nil || header.Version != 2 || header.Command != proxyproto.PROXY || header.TransportProtocol != proxyproto.TCPv4 {
		return nil
	}
	tlvs, err := header.TLVs()
	if err != nil {
		return nil
	}
	var value []byte
	seen := false
	for _, tlv := range tlvs {
		if tlv.Type != privateTLV {
			continue
		}
		if seen {
			return nil
		}
		seen = true
		value = tlv.Value
	}
	return decode(value)
}

// 兼容现用的 v1: 十六进制格式和旧版二进制格式。空字段表示未采集到指纹。
func decode(value []byte) *Fingerprint {
	if bytes.HasPrefix(value, []byte("v1:")) {
		if len(value) > 95 {
			return nil
		}
		var err error
		value, err = hex.DecodeString(string(value[3:]))
		if err != nil {
			return nil
		}
	}
	if len(value) < 6 || len(value) > 46 || value[0] != 1 || value[2] > 1 || int(value[5]) != len(value)-6 {
		return nil
	}
	window := binary.BigEndian.Uint16(value[3:5])
	opts := value[6:]
	if len(opts)%4 != 0 || window == 0 {
		return nil
	}
	switch value[1] {
	case 32, 64, 128, 255:
	default:
		return nil
	}
	mss := false
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case 0:
			for _, b := range opts[i:] {
				if b != 0 {
					return nil
				}
			}
			i = len(opts)
			continue
		case 1:
			i++
			continue
		}
		size := optionSize(kind)
		if size == 0 || i+size > len(opts) || int(opts[i+1]) != size {
			return nil
		}
		switch kind {
		case 2:
			mss = binary.BigEndian.Uint16(opts[i+2:]) >= 536
		case 3:
			if opts[i+2] > 14 {
				return nil
			}
		case 8:
			if binary.BigEndian.Uint64(opts[i+2:]) != 0 {
				return nil
			}
		}
		i += size
	}
	if _, ok := indexOptions(opts); !ok || !mss {
		return nil
	}
	return &Fingerprint{ttl: value[1], window: window, zeroID: value[2] != 0, options: bytes.Clone(opts)}
}

func optionSize(kind byte) int {
	switch kind {
	case 2:
		return 4
	case 3:
		return 3
	case 4:
		return 2
	case 8:
		return 10
	default:
		return 0
	}
}

// indexOptions 提取已知协商选项，重复的已知选项无法确定其含义。
func indexOptions(data []byte) (found [9][]byte, ok bool) {
	for i := 0; i < len(data); {
		kind := data[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+2 > len(data) {
			return found, false
		}
		size := int(data[i+1])
		if size < 2 || size > len(data)-i {
			return found, false
		}
		if expected := optionSize(kind); expected != 0 {
			if size != expected || found[kind] != nil {
				return found, false
			}
			found[kind] = data[i : i+size]
		}
		i += size
	}
	return found, true
}

func (f *Fingerprint) windowClamp() int {
	opts, _ := indexOptions(f.options)
	if scale := opts[3]; scale != nil {
		return 65535 << scale[2]
	}
	return 0
}

// rewriteSYN 保留出口路径和本次 TCP 状态相关的协商值，并跳过携带数据的 SYN。
func (f *Fingerprint) rewriteSYN(packet []byte) []byte {
	if len(packet) < 40 || packet[0] != 0x45 || packet[9] != 6 || packet[33]&0x3f != 2 ||
		binary.BigEndian.Uint16(packet[6:8]) & ^uint16(0x4000) != 0 {
		return nil
	}
	headerEnd := 20 + int(packet[32]>>4)*4
	if headerEnd < 40 || headerEnd != len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != headerEnd {
		return nil
	}
	original, ok := indexOptions(packet[40:headerEnd])
	if !ok {
		return nil
	}
	options := bytes.Clone(f.options)
	desired, _ := indexOptions(options)
	if !bytes.Equal(original[3], desired[3]) {
		return nil
	}
	for _, kind := range []byte{2, 4, 8} {
		if desired[kind] != nil && original[kind] == nil {
			return nil
		}
	}
	copy(desired[2], original[2])
	if ts := desired[8]; ts != nil {
		copy(ts[2:6], original[8][2:6])
	}

	out := make([]byte, 40+len(options))
	copy(out, packet[:40])
	copy(out[40:], options)
	out[8] = f.ttl
	if f.zeroID && out[6]&0x40 != 0 {
		clear(out[4:6])
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[32] = byte((len(out)-20)/4)<<4 | (out[32] & 15)
	binary.BigEndian.PutUint16(out[34:36], f.window)
	clear(out[10:12])
	clear(out[36:38])
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	pseudo := [4]byte{0, 6, 0, byte(len(out) - 20)}
	binary.BigEndian.PutUint16(out[36:38], checksum(out[12:20], pseudo[:], out[20:]))
	return out
}

func checksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, part := range parts {
		for len(part) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(part))
			part = part[2:]
		}
		if len(part) == 1 {
			sum += uint32(part[0]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}
