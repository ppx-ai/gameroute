package gamelane

// v2.13「Fortnite 189ms 根治三刀」验收单测（2026-10-22）。
// 覆盖：
//   第一刀 1.2  bestRaceWinnerProxy 过期软降级（Stale-While-Revalidate）
//   第一刀 1.1  STUN 周期刷新去重（in-flight + 最小间隔）
//   第二刀 2.2  进场链禁盲选（只认 rtt>0 实测值，全空返回空串）
//   第二刀 2.1  第 5 档全量实测港台最低（urltest-lowest）
//   第三刀 3.1  情况 B（curRtt==0 可替换）阈值与候选口径

import (
	"net/netip"
	"testing"
	"time"
)

// 第一刀 1.2：冠军过期但不在 badNode → 仍返回旧冠军（软降级），绝不再掉进
// pickPrimaryTemp 的盲选分支；冠军进 badNode → 返回 false 交后续档位。
func TestV213StaleChampionSoftDegrade(t *testing.T) {
	m := newDefaultManager()
	now := time.Now().UnixMilli()
	m.bestRace = &bestRaceEntry{Proxy: "香港-01", Region: "HK", RTTMs: 28, At: now - bestRaceTTL - 60000}

	got, ok := m.bestRaceWinnerProxy()
	if !ok || got != "香港-01" {
		t.Fatalf("stale-but-healthy champion must be reused, got (%q,%v)", got, ok)
	}

	// 劣迹节点绝不复用（熔断期内的冠军必须被丢弃）
	m.markBadNode("香港-01")
	if got, ok := m.bestRaceWinnerProxy(); ok || got != "" {
		t.Fatalf("stale champion in badNode must be dropped, got (%q,%v)", got, ok)
	}
}

// 第一刀 1.2：新鲜冠军行为不变（直接返回，不涉及刷新路径）
func TestV213FreshChampionUnchanged(t *testing.T) {
	m := newDefaultManager()
	m.bestRace = &bestRaceEntry{Proxy: "香港-02", Region: "HK", RTTMs: 31, At: time.Now().UnixMilli() - 1000}
	if got, ok := m.bestRaceWinnerProxy(); !ok || got != "香港-02" {
		t.Fatalf("fresh champion want (香港-02,true), got (%q,%v)", got, ok)
	}
}

// 第一刀 1.1：异步刷新去重——首轮放行，紧随其后的重复触发必须被最小间隔挡掉。
func TestV213STUNRefreshDedup(t *testing.T) {
	m := newDefaultManager()
	if !m.triggerSTUNRefreshAsync("test-first") {
		t.Fatal("first refresh trigger should be accepted")
	}
	if m.triggerSTUNRefreshAsync("test-dup") {
		t.Fatal("duplicate refresh trigger within min gap must be rejected")
	}
	// 最小间隔过后再次允许（清空 lastAt 模拟间隔已过）
	m.stunRefreshLastAt.Store(0)
	_ = m.triggerSTUNRefreshAsync("test-after-gap")
}

// 第二刀 2.2：全表无任何实测值 → 禁盲选返回空串（Fortnite Japan 06 rtt=0 根因）
func TestV213PickPrimary_NoBlindPick(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-06", "美国-01"}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string { return "JP" }

	// 目标 IP GeoIP=JP，区内节点存在但全部无实测值（rtt=0 或缺表）
	rtt := map[string]int{"日本-06": 0}
	if got := m.pickPrimaryTempFull(netip.MustParseAddr("35.72.16.34"), all, rtt, rtt); got != "" {
		t.Fatalf("no measured node must defer (empty), got %q", got)
	}
}

// 第二刀 2.1：race 源空窗 + urltest 有 HK 10ms → 必须选 HK（reason=urltest-lowest），
// 而不是 GeoIP 区内的 rtt=0 节点。这也是"大陆玩家近距约束"的落地断言。
func TestV213PickPrimary_UrltestLowestHK(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "香港-02", "日本-06", "美国-01"}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string { return "JP" }

	race := map[string]int{} // 7770 赛马源空窗（Fortnite 无测速模板）
	full := map[string]int{"香港-01": 18, "香港-02": 10, "日本-06": 0}
	got := m.pickPrimaryTempFull(netip.MustParseAddr("35.72.16.34"), all, race, full)
	if got != "香港-02" {
		t.Fatalf("want urltest-lowest HK node 香港-02, got %q", got)
	}
}

// 第二刀 2.1/2.2：服务器区不可信 → 退避链只认 race 实测值（全局最低）；
// 并反向锁定"urltest 不得决定进场主节点"（retarget_v24 红线）。
func TestV213PickPrimary_GlobalMeasuredLowest(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-06", "美国-01"}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string { return "AE" } // 非信任区 → 直接退避链

	race := map[string]int{"日本-06": 120, "美国-01": 260}
	if got := m.pickPrimaryTempFull(netip.MustParseAddr("20.40.1.1"), all, race, race); got != "日本-06" {
		t.Fatalf("want race measured lowest 日本-06, got %q", got)
	}
	// race 空、仅有 urltest 数据 → 不得据此进场（返回空串，走先测再进）
	full := map[string]int{"日本-06": 120, "美国-01": 260}
	if got := m.pickPrimaryTempFull(netip.MustParseAddr("20.40.1.1"), all, nil, full); got != "" {
		t.Fatalf("urltest must not decide entry primary, want \"\", got %q", got)
	}
}

// 第三刀 3.1：候选口径——bestProbeCandidate 只认 rtt>0，绝不返回未测节点
func TestV213BestProbeCandidateMeasuredOnly(t *testing.T) {
	pool := []string{"香港-01", "香港-02", "日本-06"}
	rtt := map[string]int{"香港-01": 0, "香港-02": 30, "日本-06": 0}
	got, gotRtt := bestProbeCandidate(pool, rtt)
	if got != "香港-02" || gotRtt != 30 {
		t.Fatalf("want (香港-02,30), got (%q,%d)", got, gotRtt)
	}
	// 全无实测值 → 空，交由"先测再进"或保持空主节点
	if got, gotRtt := bestProbeCandidate(pool, map[string]int{"香港-01": 0}); got != "" || gotRtt != 0 {
		t.Fatalf("no measured candidate want (\"\",0), got (%q,%d)", got, gotRtt)
	}
}

// 第三刀 3.1 情况 B：阈值常量锁定（curRtt==0 时只有 <80ms 实测节点才换主）
func TestV213ProbeZeroCurRttThreshold(t *testing.T) {
	if probeZeroCurRttMaxRttMs != 80 {
		t.Fatalf("probeZeroCurRttMaxRttMs want 80, got %d", probeZeroCurRttMaxRttMs)
	}
	// 79ms 通过、80ms 不通过（严格小于，避免边界抖动反复换主）
	if !(79 < probeZeroCurRttMaxRttMs) {
		t.Fatal("79ms must be allowed")
	}
	if 80 < probeZeroCurRttMaxRttMs {
		t.Fatal("80ms must not be allowed")
	}
}

// 第二刀 2.1：lowestRttByRegions 只认实测值，且 HK 优先于 TW（大陆玩家近距约束）
func TestV213LowestRttByRegionsHKFirst(t *testing.T) {
	all := []string{"香港-01", "台湾-01"}
	rtt := map[string]int{"台湾-01": 5, "香港-01": 40}
	best, bestRtt, region := lowestRttByRegions(all, rtt, "HK", "TW")
	if best != "香港-01" || bestRtt != 40 || region != "HK" {
		t.Fatalf("want HK first (香港-01,40,HK), got (%q,%d,%q)", best, bestRtt, region)
	}
	// HK 全部无实测值 → 退到 TW 实测值
	if best, _, region := lowestRttByRegions(all, map[string]int{"香港-01": 0, "台湾-01": 45}, "HK", "TW"); best != "台湾-01" || region != "TW" {
		t.Fatalf("want TW fallback 台湾-01, got (%q,%q)", best, region)
	}
}
