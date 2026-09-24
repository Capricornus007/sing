package exceptions

import (
	"errors"
	"net"
)

type TimeoutError interface {
	Timeout() bool
}

func IsTimeout(err error) bool {
	if netErr, ok := errors.AsType[net.Error](err); ok {
		//nolint:staticcheck
		return netErr.Temporary() && netErr.Timeout()
	}
	if timeoutErr, isTimeout := Cast[TimeoutError](err); isTimeout {
		return timeoutErr.Timeout()
	}
	return false
}
