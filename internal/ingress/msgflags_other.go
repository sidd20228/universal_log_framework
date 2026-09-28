//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package ingress

const supportsDatagramTruncationFlag = false

func datagramWasTruncated(int) bool {
	return false
}
