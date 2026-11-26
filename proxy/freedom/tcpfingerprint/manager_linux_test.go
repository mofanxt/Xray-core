package tcpfingerprint

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareSocketDisablesFastOpenOnlyWhenMarked(t *testing.T) {
	const fingerprintMark = 0x4c4a0051
	for _, tt := range []struct {
		name         string
		initialMark  int
		wantMark     int
		wantFastOpen int
	}{
		{name: "fingerprint", wantMark: fingerprintMark},
		{name: "policy mark", initialMark: 42, wantMark: 42, wantFastOpen: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)

			err = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
			if errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) {
				t.Skip("TCP_FASTOPEN_CONNECT is unavailable")
			}
			if err != nil {
				t.Fatal(err)
			}
			err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, tt.initialMark)
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				t.Skip("SO_MARK requires Linux capabilities")
			}
			if err != nil {
				t.Fatal(err)
			}

			if err := prepareSocket(fd, fingerprintMark, 65535<<6); err != nil {
				t.Fatal(err)
			}
			if mark, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK); err != nil || mark != tt.wantMark {
				t.Fatalf("mark=%d, err=%v, want %d", mark, err, tt.wantMark)
			}
			if fastOpen, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT); err != nil || fastOpen != tt.wantFastOpen {
				t.Fatalf("Fast Open=%d, err=%v, want %d", fastOpen, err, tt.wantFastOpen)
			}
		})
	}
}
