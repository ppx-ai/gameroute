package gamelane

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// ---- 2026-10-18 v2.4：铁令 A/C + bestRaceWinner + race-only 进场 + 扇出 ----

// 修改①1.1：216.244.0.0/16 双保险入白名单；RegionTrustedFor 仍 false（区判定口径不变）。
func TestGameBuiltInCIDRs_216CloudDual(t *testing.T) {
	if !SegmentTable().MatchIP(netip.MustParseAddr("216.244.26.60")) {
		t.Fatal("216.244.0.0/16 must hit gameBuiltInCIDRs (dual insurance)")
	}
	if SegmentTable().RegionTrustedFor(netip.MustParseAddr("216.244.26.60")) {
		t.Fatal("cloud segment must stay RegionTrustedFor=false (红线 2)")
	}
}

// 铁令 A：trusted 注册绕过黑名单并移除；非 trusted 照拦。
func TestRegisterTargetIPTrusted_BypassesBlacklist(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	m.watchesMu.Lock()
	m.writeBlacklistLocked("203.0.113.77")
	m.watchesMu.Unlock()
	if bl, _ := m.isBlacklisted("203.0.113.77"); !bl {
		t.Fatal("precondition: IP must be blacklisted")
	}
	if m.RegisterTargetIP("203.0.113.77") {
		t.Fatal("non-trusted register must be rejected by blacklist")
	}
	if !m.RegisterTargetIPTrusted("203.0.113.77", true) {
		t.Fatal("trusted register must bypass the blacklist (铁令 A)")
	}
	if bl, _ := m.isBlacklisted("203.0.113.77"); bl {
		t.Fatal("trusted register must remove the blacklist entry (铁令 A)")
	}
}

// 铁令 C：排除端口（8125/443）在 RegisterGameTargetIfNeeded 顶层一票否决，
// 即便段表命中（216.244.12.165:8125）；非排除端口段表命中照常注册。
func TestExcludedPortGate(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	if m.RegisterGameTargetIfNeeded(gameMetadataPort("216.244.12.165", 8125), true) {
		t.Fatal("excluded port 8125 must be vetoed at the top gate (铁令 C)")
	}
	if !m.RegisterGameTargetIfNeeded(gameMetadataPort("216.244.12.165", 10200), true) {
		t.Fatal("non-excluded port segment hit must register (1.3 无条件放行)")
	}
	if IsExcludedAutoRegPort(53) == false || IsExcludedAutoRegPort(443) == false || IsExcludedAutoRegPort(8125) == false {
		t.Fatal("IsExcludedAutoRegPort must cover 53/443/8125")
	}
	if IsExcludedAutoRegPort(10200) {
		t.Fatal("10200 (APEX dynamic game port) must NOT be an excluded port")
	}
}

// 第二刀 2.1：bestRaceWinner 择优更新 + 10min 过期覆盖（防晚回包篡位）。
func TestBestRaceWinner_UpdateAndExpiry(t *testing.T) {
	m := newDefaultManager()
	if !m.bestRaceEmpty() {
		t.Fatal("fresh manager must have empty bestRace")
	}
	m.updateBestRaceWinner("JP 05", "JP", 160)
	if px, ok := m.bestRaceWinnerProxy(); !ok || px != "JP 05" {
		t.Fatalf("first winner must install, got %q ok=%v", px, ok)
	}
	m.updateBestRaceWinner("HK 02", "HK", 28)
	if px, _ := m.bestRaceWinnerProxy(); px != "HK 02" {
		t.Fatalf("lower rtt must overwrite, got %q", px)
	}
	m.updateBestRaceWinner("US 01", "US", 160)
	if px, _ := m.bestRaceWinnerProxy(); px != "HK 02" {
		t.Fatalf("higher rtt late winner must NOT overwrite (防篡位), got %q", px)
	}
	// 过期：手动回拨 At 到 11 分钟前 → 下一位赢家无条件覆盖
	m.bestRaceMu.Lock()
	m.bestRace.At = time.Now().UnixMilli() - 11*60*1000
	m.bestRaceMu.Unlock()
	m.updateBestRaceWinner("SG 01", "SG", 90)
	if px, _ := m.bestRaceWinnerProxy(); px != "SG 01" {
		t.Fatalf("expired best must be replaced unconditionally, got %q", px)
	}
}

// 第二刀 2.3/2.5：进场裁决 bestRaceWinner 第一优先；无 bestRace 时仅认
// race 源数据——Cloudflare urltest 数据（HK 01=90）不得参与选主。
func TestPickPrimary_BestRaceWinnerAndRaceOnly(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	m.SetAllProxies([]string{"HK-01", "HK-02", "TW-01", "SG-01", "JP-01", "KR-01"})
	// rttTable：JP-01=33（urltest 源，Cloudflare 假裁判）——若 Cloudflare
	// 数据参与选主，JP-01（33ms 全场最低）必被选中；race-only 口径下
	// JP-01 不可达（可判别断言：JP-01 不是池首位，池序回退不会选它）。
	m.mu.Lock()
	m.rttTable = map[string]int{"JP-01": 33}
	m.rttSource = map[string]string{"JP-01": "urltest"}
	m.mu.Unlock()
	tgt := Target{CIDR: []netip.Prefix{netip.MustParsePrefix("216.244.26.60/32")}}
	m.ensureAutoPrimary(&tgt, netip.MustParseAddr("216.244.26.60"), "", m.allProxies, m.rttTable)
	if got := tgt.currentPrimary; got == "JP-01" {
		t.Fatal("Cloudflare urltest data must NOT decide entry primary (反向验收)")
	}
	// bestRace HK-02=28 → 下一轮进场选 HK-02
	m.updateBestRaceWinner("HK-02", "HK", 28)
	tgt2 := Target{CIDR: []netip.Prefix{netip.MustParsePrefix("216.244.26.61/32")}}
	m.ensureAutoPrimary(&tgt2, netip.MustParseAddr("216.244.26.61"), "", m.allProxies, m.rttTable)
	if got := tgt2.currentPrimary; got != "HK-02" {
		t.Fatalf("best-race-winner must be entry primary (25ms 级), got %q", got)
	}
}

// 第二刀 2.2：HK/TW 全量节点上 7770 跑道（≠五区各 1 代表），race 源入表。
func TestPreheatRegionFanout_HKTWFullSquad(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	pool := []string{
		"HK-01", "HK-02", "HK-03", "HK-04", "HK-05", "HK-06", "HK-07", "HK-08",
		"TW-01", "TW-02", "TW-03", "TW-04",
		"SG-01", "JP-01", "KR-01",
	}
	m.SetAllProxies(pool)
	// 模板目标：亚太可信段 IP（RegionTrustedFor 经修改① 段表为 true）
	m.preheatMu.Lock()
	if m.probeTemplates == nil {
		m.probeTemplates = make(map[string]*probeTemplate)
	}
	m.probeTemplates["18.162.1.10"] = &probeTemplate{PayloadHex: "ffffffff010203040500", DstPort: 7770, LearnedAt: time.Now().UnixMilli()}
	m.preheatMu.Unlock()
	var dialed atomic.Int32
	var mu atomic.Value
	mu.Store(make(map[string]bool))
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		dialed.Add(1)
		mu.Load().(map[string]bool)[name] = true
		return newFakeRaceConn(30 * time.Millisecond), nil
	})
	m.PreheatRegionFanout(m.probeTemplateKeys())
	got := mu.Load().(map[string]bool)
	if dialed.Load() < 15 {
		t.Fatalf("fanout must race the full HK/TW squad (8+4+3), dialed=%d seen=%v", dialed.Load(), got)
	}
	for _, name := range []string{"HK-02", "HK-08", "TW-04"} {
		if !got[name] {
			t.Fatalf("non-champion node %s must be on the 7770 track (打破代表死锁), seen=%v", name, got)
		}
	}
}

// 漏洞三：四个游戏特征事件任一触发 → 60s 临战活跃态。
func TestMarkGameActive(t *testing.T) {
	m := newDefaultManager()
	if m.GameActive() {
		t.Fatal("fresh manager must not be game-active")
	}
	m.MarkGameActive()
	if !m.GameActive() {
		t.Fatal("MarkGameActive must arm the 60s active window")
	}
}

// 漏洞四：注册即初始化 currentPrimary（proxy 字段第 1ms 起不空）。
func TestRegisterTargetIP_InitializesPrimary(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	m.SetAllProxies([]string{"HK-01", "HK-02", "TW-01", "SG-01", "JP-01", "KR-01"})
	m.updateBestRaceWinner("HK-02", "HK", 28)
	if !m.RegisterTargetIP("216.244.26.60") {
		t.Fatal("register must succeed")
	}
	ts := m.GetTargets()
	found := false
	for _, s := range ts {
		if s.CIDR[0].String() == "216.244.26.60/32" {
			found = true
			if s.currentPrimary == "" {
				t.Fatal("registered target must have currentPrimary initialized at birth (漏洞四)")
			}
		}
	}
	if !found {
		t.Fatal("target missing")
	}
}

func gameMetadataPort(dst string, port uint16) *C.Metadata {
	return &C.Metadata{
		DstIP:   netip.MustParseAddr(dst),
		DstPort: port,
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 54321,
	}
}

var _ = time.Now
