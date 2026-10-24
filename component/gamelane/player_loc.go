package gamelane

// 玩家位置定位：内核启动时直连公网查一次出口 IP → GeoIP 判玩家国家，
// 作为候选池构建的"玩家侧就近优先"依据（配合服务器 GeoIP 地区补充，
// 避免"亚洲玩家连北美服务器却无美加候选"这类无解场景）。
//
// 硬约束：
//   - 必须直连（不走代理）：查询请求显式禁用系统/环境代理，保证拿到的是
//     玩家真实出口 IP 而非某个节点 IP；
//   - 只查一次（sync.Once），超时 3-5s，失败静默退化（候选池按服务器侧
//     引导，与旧逻辑一致），绝不影响内核启动与代理主流程。

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// playerLocator 全局玩家位置（启动时异步刷新一次）。
type playerLocator struct {
	mu      sync.RWMutex
	country string // 大写国家代码（CN/US/JP...），未知为 ""
	ip      string // 公网出口 IP（仅日志/调试）
	done    bool
}

var playerLoc = &playerLocator{}

// queryPublicIP 直连查询玩家公网出口 IP（返回纯 IPv4/IPv6 字符串，
// 失败返回 ""）。包级变量便于单测注入替换。
var queryPublicIP = func() string {
	// Proxy=nil 强制不走系统/环境代理：玩家位置必须用真实出口 IP 判定。
	// 注意：mihomo main.go 会把 net.DefaultResolver.Dial 替换为防御性退出，
	// 这里必须显式挂独立 Resolver 的 DialContext，否则任何默认解析都会触发
	// "should never be called" 进程退出。
	client := &http.Client{
		Timeout: 4 * time.Second, // 3-5s 窗口内
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: 4 * time.Second,
				Resolver: &net.Resolver{
					PreferGo: true,
					// F5 加固：显式 Dial，彻底切断对 net.DefaultResolver 的
					// 任何可能引用（main.go:87 将其 Dial 设为防御性 panic，
					// 2026-10-15 09:37 曾四连触发启动即崩溃）。address 为
					// 系统 DNS 服务器地址（IP:port），直接拨号不经任何解析器。
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := &net.Dialer{Timeout: 4 * time.Second}
						return d.DialContext(ctx, network, address)
					},
				},
			}).DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          1,
			IdleConnTimeout:       5 * time.Second,
			TLSHandshakeTimeout:   4 * time.Second,
			ExpectContinueTimeout: 0,
		},
	}
	// 主源：api.ipify.org（纯文本 IP，最轻量）
	if ip := fetchPublicIP(client, "https://api.ipify.org"); ip != "" {
		return ip
	}
	// 兜底源：ipinfo.io/ip（同样纯文本 IP）
	return fetchPublicIP(client, "https://ipinfo.io/ip")
}

// fetchPublicIP 发起一次 GET 并截取响应体中的 IP 文本。
func fetchPublicIP(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

var startPlayerLocatorOnce sync.Once

// StartPlayerLocator 启动玩家位置定位（配置解析阶段调用；幂等）。
// 异步执行：不阻塞内核启动；定位完成前 PlayerRegion 返回 ""，
// 候选池按服务器侧引导构建（与 v6.1 行为一致）。
func StartPlayerLocator() {
	startPlayerLocatorOnce.Do(func() {
		go func() {
			ip := queryPublicIP()
			if ip == "" {
				log.Infoln("[GameRoute] player locator: public ip query failed, server-side only")
				return
			}
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				log.Infoln("[GameRoute] player locator: bad public ip %q", ip)
				return
			}
			country := geoipCountryFor(addr)
			playerLoc.mu.Lock()
			playerLoc.country = country
			playerLoc.ip = ip
			playerLoc.done = true
			playerLoc.mu.Unlock()
			log.Infoln("[GameRoute] player location = %s (public ip %s)", displayPlayerCountry(country), ip)
		}()
	})
}

// PlayerCountry 返回玩家国家代码（大写；定位未完成/未知返回 ""）。
func PlayerCountry() string {
	playerLoc.mu.RLock()
	defer playerLoc.mu.RUnlock()
	return playerLoc.country
}

// PlayerIP 返回玩家公网出口 IP（定位未完成返回 ""）。
func PlayerIP() string {
	playerLoc.mu.RLock()
	defer playerLoc.mu.RUnlock()
	return playerLoc.ip
}

// PlayerRegion 返回玩家所属大区（Asia/EU/NA/OC/ME；未知返回 ""）。
// 复用服务器大区映射：玩家所在国家按同一套大区归属判定。
func PlayerRegion() string {
	c := PlayerCountry()
	if c == "" {
		return ""
	}
	return serverRegionOf(c)
}

func displayPlayerCountry(c string) string {
	if c == "" {
		return "unknown"
	}
	return c
}

// setPlayerCountryForTest 单测注入：直接设置玩家国家（模拟定位完成）。
func setPlayerCountryForTest(c string) {
	playerLoc.mu.Lock()
	playerLoc.country = c
	playerLoc.done = true
	playerLoc.mu.Unlock()
}
