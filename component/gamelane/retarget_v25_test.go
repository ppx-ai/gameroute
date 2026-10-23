package gamelane

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// ---- 2026-10-19 v2.5：排除层洗白 / 巴林禁靶 / STUN 保底探针（含强制修正一/二）----

// 第一刀 1：排除层洗白矩阵——三个误杀游戏段 + 七个 CDN 段全部放行；
// 基础设施段（私网/环回/CGNAT/链路本地/组播/本网/TUN 198.18.0.0/15）保留。
func TestExcludedLayer_V25Rewrite(t *testing.T) {
	for _, ip := range []string{
		"155.133.238.178", // Valve SDR（27051 对局实锤）
		"162.254.193.99",  // Valve SDR（27120）
		"89.222.117.200",  // G-Core Labs（27052）
		"54.230.1.1",      // 原 CloudFront 排除段
		"20.43.1.1",       // 原 Azure CDN 排除段
		"3.66.1.1",
		"20.196.1.1",
	} {
		if isExcludedIP(netip.MustParseAddr(ip)) {
			t.Fatalf("%s must NOT be excluded after v2.5 rewrite (毒瘤铲除)", ip)
		}
	}
	for _, ip := range []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
		"100.64.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.1",
		"198.18.0.45", // TUN 虚拟网段（fake-ip）保留排除
	} {
		if !isExcludedIP(netip.MustParseAddr(ip)) {
			t.Fatalf("%s must stay excluded (基础设施段保留)", ip)
		}
	}
}

// 第一刀 2：四个新白名单段 MatchIP 命中（首包 T=0ms 段表注册）。
func TestGameBuiltInCIDRs_V25Segments(t *testing.T) {
	for _, ip := range []string{
		"155.133.238.178", "162.254.193.99", "89.222.117.200", "15.185.1.1",
	} {
		if !SegmentTable().MatchIP(netip.MustParseAddr(ip)) {
			t.Fatalf("v2.5 whitelist miss: %s must hit gameBuiltInCIDRs", ip)
		}
	}
}

// 第一刀 2 + 1.3：Valve/G-Core 对局端口首包 T=0ms 同步注册；铁令 C 回归。
func TestRegisterGameTargetIfNeeded_V25ValveSegment(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	if !m.RegisterGameTargetIfNeeded(gameMetadataPort("155.133.238.178", 27051), true) {
		t.Fatal("Valve SDR 27051 must register at T=0ms (segment path)")
	}
	if !m.RegisterGameTargetIfNeeded(gameMetadataPort("89.222.117.200", 27052), true) {
		t.Fatal("G-Core Labs 27052 must register at T=0ms")
	}
	if m.RegisterGameTargetIfNeeded(gameMetadataPort("155.133.238.178", 8125), true) {
		t.Fatal("excluded port 8125 must stay vetoed (铁令 C 回归)")
	}
}

// 第二刀 2.1：巴林死区严禁当测速模板（亚太候选不含 15.184.0.0/15）。
func TestAsianTemplateTargets_BahrainBanned(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	m.preheatMu.Lock()
	if m.probeTemplates == nil {
		m.probeTemplates = make(map[string]*probeTemplate)
	}
	m.probeTemplates["15.184.192.233"] = &probeTemplate{PayloadHex: "ffffffff0102", DstPort: 7770}
	m.probeTemplates["18.162.1.10"] = &probeTemplate{PayloadHex: "ffffffff0102", DstPort: 7770}
	m.preheatMu.Unlock()
	targets := m.asianTemplateTargets([]string{"15.184.192.233", "18.162.1.10"}, 2)
	if len(targets) != 1 || targets[0].Addr().String() != "18.162.1.10" {
		t.Fatalf("bahrain dead zone must be banned from template selection, got %v", targets)
	}
}

// 强制修正一：静态 Anycast 靶点恒在（域名不可解析时兜底）；域名解析成功
// 则与静态靶点去重并入。
func TestStunTargets_StaticFallbackAlwaysPresent(t *testing.T) {
	orig := stunProbeServers
	stunProbeServers = []string{"invalid.invalid:3478"} // 必然解析失败
	defer func() { stunProbeServers = orig }()
	targets := stunProbeTargets()
	if len(targets) != len(stunStaticTargets) {
		t.Fatalf("static anycast targets must always be present, got %v", targets)
	}
	for _, want := range stunStaticTargets {
		found := false
		for _, got := range targets {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("static target %s missing", want)
		}
	}
}

// 强制修正一（配套）：STUN 域名进免 Fake-IP 名单。
func TestIsGameDomain_StunDomains(t *testing.T) {
	m := newDefaultManager()
	if !m.IsGameDomain("stun.cloudflare.com") {
		t.Fatal("stun.cloudflare.com must hit the builtin list (修正一)")
	}
	if !m.IsGameDomain("stun.l.google.com") {
		t.Fatal("stun.l.google.com must hit the builtin list (修正一)")
	}
	if m.IsGameDomain("stun2.l.google.com") {
		t.Fatal("sibling host stun2.l.google.com is out of the approved scope")
	}
}

// 第二刀 2 + 强制修正二：STUN 保底——无 7770 模板时经节点通道产出
// rttTable(Source="race") 与 bestRaceWinner；且 STUN 节点集合仅 HK/TW
// （Anycast 就近响应严禁跨区抢全局最优）。
func TestStunFallback_WhenNoTemplates(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	m.SetAllProxies([]string{"HK-01", "HK-02", "HK-03", "HK-04", "TW-01", "SG-01"})
	origServers := stunProbeServers
	stunProbeServers = []string{"203.0.113.10:3478"} // IP 直连（单测免 DNS）
	defer func() { stunProbeServers = origServers }()
	var dialed atomic.Int32
	var mu atomic.Value
	mu.Store(make(map[string]bool))
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		dialed.Add(1)
		mu.Load().(map[string]bool)[name] = true
		return newFakeRaceConn(25 * time.Millisecond), nil
	})
	if n := m.PreheatRegionFanout(nil); n == 0 {
		t.Fatal("STUN fallback must fire when no asian 7770 template exists")
	}
	if dialed.Load() == 0 {
		t.Fatal("STUN fallback must dial via node UDP channels")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := m.bestRaceWinnerProxy(); ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	px, ok := m.bestRaceWinnerProxy()
	if !ok || px == "" {
		t.Fatal("bestRaceWinner must be produced by the STUN fallback (绝不留空)")
	}
	// 强制修正二：STUN 竞争集合仅 HK/TW——SG-01 不得上 STUN 跑道
	got := mu.Load().(map[string]bool)
	if got["SG-01"] {
		t.Fatalf("SG-01 must NOT race via STUN (Anycast 跨区防篡位), seen=%v", got)
	}
	if !got["HK-01"] {
		t.Fatalf("HK nodes must race via STUN, seen=%v", got)
	}
	// race 源数据入表（Source="race"）
	m.mu.RLock()
	raceEntries := 0
	for _, src := range m.rttSource {
		if src == "race" {
			raceEntries++
		}
	}
	m.mu.RUnlock()
	if raceEntries == 0 {
		t.Fatal("STUN probe RTTs must be tagged Source=race in rttTable")
	}
}

// 回归：对局端口红线 / 铁令 C。
func TestV25_Regressions(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	if !isMatchServerPort(27015) {
		t.Fatal("27015 stays a game port (红线 2 回归)")
	}
	if m.RegisterGameTargetIfNeeded(gameMetadataPort("216.244.12.165", 8125), true) {
		t.Fatal("8125 stays vetoed (铁令 C 回归)")
	}
	_ = C.Metadata{}
}
