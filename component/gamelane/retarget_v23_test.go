package gamelane

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// ---- 2026-10-18 v2.3：段表补全 / IsGameDomain 域名注册 / IsStatelessProbePort ----

// 修改①：9 条新段 MatchIP 全命中（真实 IP 首包 0ms 注册）；非云段
// RegionTrustedFor=true（GeoIP 区判定可信）；云段 216.244 保持不可信回归。
func TestGameBuiltInCIDRs_V23Segments(t *testing.T) {
	for _, ip := range []string{
		"18.162.1.1", "18.166.5.5",
		"52.220.1.1", "13.228.1.1", "13.250.1.1",
		"13.112.1.1", "52.192.1.1",
		"18.232.1.1", "15.184.192.233",
	} {
		if !SegmentTable().MatchIP(netip.MustParseAddr(ip)) {
			t.Fatalf("v2.3 segment miss: %s must hit gameBuiltInCIDRs", ip)
		}
	}
	if !SegmentTable().RegionTrustedFor(netip.MustParseAddr("18.162.1.1")) {
		t.Fatal("18.162.0.0/15 is not a cloud segment: GeoIP region must be trusted")
	}
	if SegmentTable().RegionTrustedFor(netip.MustParseAddr("216.244.12.165")) {
		t.Fatal("cloud segment 216.244.0.0/16 must stay untrusted (红线 2 回归)")
	}
}

// 衔接 2：域名匹配升级 IsGameDomain——不在规则集树的 EA QoS ELB 域名
// （*.amazonaws.com 等 13 条内置后缀）纳入首包域名自动注册。
// 端口用 10200（APEX 动态对局端口，不在 skipAutoRegPorts；443/8125 被跳过）。
func TestRegisterGameTargetIfNeeded_GameDomainSuffix(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	md := &C.Metadata{
		DstIP:   netip.MustParseAddr("93.184.216.34"), // 非段表 IP，逼走域名路径
		DstPort: 10200,
		Host:    "qos-ea.example.amazonaws.com",
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 54321,
	}
	if !m.RegisterGameTargetIfNeeded(md, true) {
		t.Fatal("game-domain suffix (amazonaws.com) must register via IsGameDomain path")
	}
	md2 := &C.Metadata{
		DstIP:   netip.MustParseAddr("93.184.216.35"),
		DstPort: 10200,
		Host:    "www.bilibili.com",
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 54321,
	}
	if m.RegisterGameTargetIfNeeded(md2, true) {
		t.Fatal("non-game domain must not register")
	}
}

// 修改④（Q-H1 反转）：IsStatelessProbePort 白名单口径——7770/已学习模板
// 端口为 true；真实对局端口（gamePortRanges 全集，含 1024-1124）永远 false。
func TestIsStatelessProbePort(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	if !m.IsStatelessProbePort(netip.MustParseAddr("1.2.3.4"), 7770) {
		t.Fatal("7770 (GameLift UDP Ping Beacon) must be stateless-probe")
	}
	if m.IsStatelessProbePort(netip.MustParseAddr("1.2.3.4"), 27015) {
		t.Fatal("gamePortRanges port must never be stateless-probe")
	}
	if m.IsStatelessProbePort(netip.MustParseAddr("1.2.3.4"), 1100) {
		t.Fatal("1024-1124 (APEX game port) must never be stateless-probe")
	}
	// 已学习模板端口：仅对该目标 IP 生效
	m.preheatMu.Lock()
	if m.probeTemplates == nil {
		m.probeTemplates = make(map[string]*probeTemplate)
	}
	m.probeTemplates["5.6.7.8"] = &probeTemplate{DstPort: 7771}
	m.preheatMu.Unlock()
	if !m.IsStatelessProbePort(netip.MustParseAddr("5.6.7.8"), 7771) {
		t.Fatal("learned template port must be stateless-probe for its target")
	}
	if m.IsStatelessProbePort(netip.MustParseAddr("9.9.9.9"), 7771) {
		t.Fatal("learned template port must not leak to other targets")
	}
}
