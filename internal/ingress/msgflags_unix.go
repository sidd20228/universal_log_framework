//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ingress

import "syscall"

const supportsDatagramTruncationFlag = true

func datagramWasTruncated(flags int) bool {
	return flags&syscall.MSG_TRUNC != 0
}
