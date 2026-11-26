package tcpfingerprint

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	xerrors "github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

type linuxBackend struct {
	queue uint16
	table string

	lifecycle sync.Mutex
	owner     *net.UnixConn
	handle    *nfqueue.Nfqueue
	cancel    context.CancelFunc

	mu     sync.Mutex
	active bool
	next   uint16
	syn    map[uint32]*Fingerprint
}

func newBackend(queue uint16) (backend, error) {
	return &linuxBackend{
		queue: queue,
		table: fmt.Sprintf("xray_tcp_fingerprint_%d", queue),
		syn:   make(map[uint32]*Fingerprint),
	}, nil
}

func (b *linuxBackend) Start() error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	if b.owner != nil {
		return nil
	}

	owner, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "@" + b.table, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("claim fingerprint queue %d: %w", b.queue, err)
	}
	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      b.queue,
		AfFamily:     unix.AF_INET,
		MaxPacketLen: 65531,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagGSO,
		WriteTimeout: time.Second,
	})
	if err != nil {
		owner.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := false
	defer func() {
		if !ready {
			cancel()
			q.Close()
			owner.Close()
		}
	}()
	err = q.RegisterWithErrorFunc(ctx, func(packet nfqueue.Attribute) int {
		if err := b.verdict(q, packet); err != nil && ctx.Err() == nil {
			xerrors.LogWarningInner(ctx, err, "TCP fingerprint queue verdict")
		}
		return 0
	}, func(err error) int {
		if ctx.Err() == nil {
			xerrors.LogWarningInner(ctx, err, "TCP fingerprint queue")
		}
		return 0
	})
	if err != nil {
		return fmt.Errorf("register fingerprint queue %d: %w", b.queue, err)
	}
	if err = b.install(); err != nil {
		return err
	}
	b.owner, b.handle, b.cancel = owner, q, cancel
	b.mu.Lock()
	b.active = true
	b.mu.Unlock()
	ready = true
	return nil
}

func (b *linuxBackend) verdict(q *nfqueue.Nfqueue, packet nfqueue.Attribute) error {
	if packet.PacketID == nil {
		return nil
	}
	if packet.Mark != nil && packet.Payload != nil &&
		(packet.CapLen == nil || int(*packet.CapLen) == len(*packet.Payload)) {
		b.mu.Lock()
		fingerprint := b.syn[*packet.Mark]
		b.mu.Unlock()
		if fingerprint != nil {
			if rewritten := fingerprint.rewriteSYN(*packet.Payload); rewritten != nil {
				return q.SetVerdictWithOption(*packet.PacketID, nfqueue.NfAccept, nfqueue.WithAlteredPacket(rewritten))
			}
		}
	}
	return q.SetVerdict(*packet.PacketID, nfqueue.NfAccept)
}

func (b *linuxBackend) install() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rules := fmt.Sprintf(
		"create table inet %s\nadd chain inet %s syn { type filter hook postrouting priority 110; policy accept; }\n"+
			"add rule inet %s syn ip protocol tcp tcp flags & (syn | ack) == syn meta mark & 0xffff0000 == 0x%08x counter queue num %d bypass\n",
		b.table, b.table, b.table, uint32(b.queue)<<16, b.queue)
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil && !b.ownsRules(ctx) {
		return fmt.Errorf("install TCP fingerprint rules: %w: %s", err, out)
	}
	return nil
}

func (b *linuxBackend) ownsRules(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "nft", "-s", "-y", "list", "table", "inet", b.table).Output()
	if err != nil {
		return false
	}
	prefix := fmt.Sprintf("table inet %s { chain syn { type filter hook postrouting priority 110; policy accept; ip protocol tcp tcp flags & (syn | ack) == syn meta mark & 0xffff0000 == 0x%08x counter queue ", b.table, uint32(b.queue)<<16)
	listed := strings.Join(strings.Fields(string(out)), " ")
	return listed == fmt.Sprintf("%sflags bypass to %d } }", prefix, b.queue) ||
		listed == fmt.Sprintf("%snum %d bypass } }", prefix, b.queue)
}

func (b *linuxBackend) Close() error {
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	if b.owner == nil {
		return nil
	}
	b.mu.Lock()
	b.active = false
	clear(b.syn)
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var ruleErr error
	if b.ownsRules(ctx) {
		ruleErr = exec.CommandContext(ctx, "nft", "delete", "table", "inet", b.table).Run()
	} else {
		ruleErr = fmt.Errorf("cannot verify TCP fingerprint table %s", b.table)
	}
	b.cancel()
	err := errors.Join(ruleErr, b.handle.Close(), b.owner.Close())
	b.owner, b.handle, b.cancel = nil, nil, nil
	return err
}

func (b *linuxBackend) SocketControl(f *Fingerprint) (func(string, string, syscall.RawConn) error, func(net.Conn)) {
	b.mu.Lock()
	var mark uint32
	if b.active {
		for range 65535 {
			b.next++
			if b.next == 0 {
				b.next = 1
			}
			candidate := uint32(b.queue)<<16 | uint32(b.next)
			if b.syn[candidate] == nil {
				mark = candidate
				b.syn[mark] = f
				break
			}
		}
	}
	b.mu.Unlock()
	if mark == 0 {
		return nil, nil
	}
	clamp := f.windowClamp()
	control := func(network, _ string, socket syscall.RawConn) error {
		if network != "tcp4" {
			return nil
		}
		var err error
		if controlErr := socket.Control(func(fd uintptr) {
			// 已有策略路由标记的连接继续使用原生 SYN。
			current, getErr := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
			if getErr != nil || current != 0 {
				return
			}
			if setErr := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)); setErr != nil {
				return
			}
			if clamp != 0 {
				window, getErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP)
				if getErr == nil && (window == 0 || window > clamp) {
					getErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, clamp)
				}
				if getErr != nil {
					err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0)
				}
			}
		}); controlErr != nil {
			return controlErr
		}
		return err
	}
	release := func(conn net.Conn) {
		b.mu.Lock()
		delete(b.syn, mark)
		b.mu.Unlock()
		if tcp, ok := conn.(*net.TCPConn); ok {
			if socket, err := tcp.SyscallConn(); err == nil {
				_ = socket.Control(func(fd uintptr) {
					current, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
					if err == nil && uint32(current) == mark {
						_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0)
					}
				})
			}
		}
	}
	return control, release
}
