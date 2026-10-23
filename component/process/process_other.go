//go:build !darwin && !linux && !windows && (!freebsd || !amd64)

package process

import "net/netip"

func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
	return 0, "", ErrPlatformNotSupport
}

func resolveSocketByNetlink(network string, ip netip.Addr, srcPort int) (uint32, uint32, error) {
	return 0, 0, ErrPlatformNotSupport
}


// findProcessNamePort 非目标平台 stub：仅 Windows 实现按端口-only 反查（TUN 专用）。
func findProcessNamePort(network string, srcPort int) (uint32, string, error) {
	return 0, "", ErrPlatformNotSupport
}

