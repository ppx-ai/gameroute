package process

import (
	"errors"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")
)

const (
	TCP = "tcp"
	UDP = "udp"
)

func FindProcessName(network string, srcIP netip.Addr, srcPort int) (uint32, string, error) {
	return findProcessName(network, srcIP, srcPort)
}

// FindProcessNameByPort 仅按源端口反查进程归属（忽略源 IP 匹配）。
// 供 TUN 模式使用：TUN 包源 IP 为虚拟网段（198.18.x.x），与系统套接字
// 真实绑定地址不匹配，常规按 (srcIP, srcPort) 反查必然失败；客户端随机
// 端口在系统内基本唯一，仅凭端口反查 UDP 表即可定位游戏进程。
// 非 Windows 平台返回 ErrPlatformNotSupport。
func FindProcessNameByPort(network string, srcPort int) (uint32, string, error) {
	return findProcessNamePort(network, srcPort)
}

// PackageNameResolver
// never change type traits because it's used in CMFA
type PackageNameResolver func(metadata *C.Metadata) (string, error)

// DefaultPackageNameResolver
// never change type traits because it's used in CMFA
var DefaultPackageNameResolver PackageNameResolver

func FindPackageName(metadata *C.Metadata) (string, error) {
	if resolver := DefaultPackageNameResolver; resolver != nil {
		return resolver(metadata)
	}
	return "", ErrPlatformNotSupport
}
