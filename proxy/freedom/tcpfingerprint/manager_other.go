//go:build !linux

package tcpfingerprint

import "errors"

func newBackend(uint16) (backend, error) {
	return nil, errors.New("freedom tcpFingerprint requires Linux")
}
