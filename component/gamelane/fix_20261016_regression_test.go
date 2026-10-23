package gamelane

import (
	"net/netip"
	"testing"
	"time"
)

// 2026-10-16 诊断方案 F1-F12 回归测试（方案确认后实施）。

// newFixManager 带 map 初始化的测试用 Manager（newManager 不初始化内页 map）。
func newFixManager(enabled bool, targets []Target) *Manager {
	m := newManager(enabled, targets)
	m.memories = make(map[string]*GameMemory)
	m.rttFailStreak = make(map[string]int)
	m.lastURLTest = make(map[string]int)
	m.probeOffset = make(map[string]int)
	m.lastProxyByTarget = make(map[string]string)
	m.switchCooldown = make(map[string]int64)
	return m
}

// F5 回归：记忆区节点全灭（rttTable 全 0）+ 记忆 RegionActual 存在时，
// pickPrimaryTemp 不得 panic（2026-10-16 02:42 rand.Intn(0) 崩溃实锤，RC5a）。
func TestPickPrimaryTemp_AllRegionNodesDead_NoPanic(t *testing.T) {
	m := newFixManager(true, nil)
	m.SetAllProxies([]string{"港-A", "台-B", "美-C"})
	// 全部节点已被探测判死（rtt=0，liveNodes 过滤后记忆区池为空）
	m.SetRTTTable(map[string]int{"港-A": 0, "台-B": 0, "美-C": 0})
	m.memories["216.244.12.50/32"] = &GameMemory{Key: "216.244.12.50/32", Status: "active", Source: "process", RegionActual: "TW", LastHitAt: time.Now().UnixMilli()}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("pickPrimaryTemp must not panic on empty region pool: %v", r)
		}
	}()
	px := m.pickPrimaryTemp(netip.MustParseAddr("216.244.12.50"), []string{"港-A", "台-B", "美-C"}, map[string]int{"港-A": 0, "台-B": 0, "美-C": 0})
	t.Logf("picked %q (empty pool safe)", px)
}

// F5：safeRandomPick 空池必须返回 false，不得 panic。
func TestSafeRandomPick_EmptyPool(t *testing.T) {
	if px, ok := safeRandomPick(nil); ok || px != "" {
		t.Fatalf("empty pool must return (\"\", false), got (%q, %v)", px, ok)
	}
	px, ok := safeRandomPick([]string{"A"})
	if !ok || px != "A" {
		t.Fatalf("single pool must return the element, got (%q, %v)", px, ok)
	}
}

// F2：SwitchToBestFallback 每目标 30s 冷却——切换落地后冷却期内再次调用必须拒绝。
// v2.7 同区铁律：候选池必须与当前主节点同区（跨区候选一律过滤），
// 故用同区双港节点验证冷却门卫。
// v2.8 第一刀：curRtt>=150ms 劣迹节点只标记 badNode 不切换（命中直接
// return false），故本用例用 140ms（<150 不触发熔断路径）验证冷却门卫。
func TestSwitchToBestFallback_CooldownGate(t *testing.T) {
	m := newFixManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("45.56.120.0/24")},
			Proxy: "auto", Fallbacks: []string{"港-A", "港-B"},
			autoPrimary: true, currentPrimary: "港-A"},
	})
	m.SetRTTTable(map[string]int{"港-A": 140, "港-B": 45})
	if !m.SwitchToBestFallback("45.56.120.33") {
		t.Fatalf("first switch must succeed")
	}
	if m.SwitchToBestFallback("45.56.120.33") {
		t.Fatalf("second switch within cooldown must be rejected")
	}
	if until := m.switchCooldownUntil("45.56.120.33"); until <= time.Now().UnixMilli() {
		t.Fatalf("cooldown must be armed, until=%d", until)
	}
}

// F7（2026-10-17 移除）：region_actual 横跳冻结机制随五区锁死一并删除
// （需求 E3④/Q5④ 裁决：写入侧已限定 HK/TW/SG/JP/KR，冻结失去意义）。
// 替代回归见 memory_lane_test.go 的 TestRegionLock_WriteRejectsNonLane
// （非五区值写入被拒）。

// F7：last_proxies 写入侧区校验——与记忆区冲突的出口拒绝写入（诊断 E12）。
func TestRememberTargetProxy_RegionMismatchRejected(t *testing.T) {
	m := newFixManager(true, nil)
	m.memories["216.244.9.168/32"] = &GameMemory{Key: "216.244.9.168/32", Status: "active", Source: "process", RegionActual: "HK", LastHitAt: time.Now().UnixMilli()}
	m.rememberTargetProxy("216.244.9.168/32", "🇨🇦 Canada | 01")
	if got := m.lastProxyByTarget["216.244.9.168/32"]; got != "" {
		t.Fatalf("region-mismatched proxy must be rejected, got %q", got)
	}
	m.rememberTargetProxy("216.244.9.168/32", "🇭🇰 Hong Kong | 01")
	if got := m.lastProxyByTarget["216.244.9.168/32"]; got == "" {
		t.Fatalf("region-consistent proxy must be accepted")
	}
}

// F1：探测样本合并——EMA 平滑 + 失败连击判死 + 会话实测回写与开销校准。
func TestMergeProbeResults_SmoothingAndFailStreak(t *testing.T) {
	m := newFixManager(true, nil)
	// 成功样本 245ms 直接入表
	m.MergeProbeResults(map[string]probeSample{"港-A": {RttMs: 245, Samples: 3, OK: true}})
	if got := m.SnapshotRTT()["港-A"]; got != 245 {
		t.Fatalf("first sample must be written, got %d", got)
	}
	// 第二轮 90ms → EMA (245+90)/2=167
	m.MergeProbeResults(map[string]probeSample{"港-A": {RttMs: 90, Samples: 3, OK: true}})
	if got := m.SnapshotRTT()["港-A"]; got != 167 {
		t.Fatalf("EMA smoothing wrong, got %d want 167", got)
	}
	// 失败 1 轮：不清零、不判死（旧值保留）
	m.MergeProbeResults(map[string]probeSample{"港-A": {OK: false}})
	if got := m.SnapshotRTT()["港-A"]; got != 167 {
		t.Fatalf("single failure must keep old value, got %d", got)
	}
	if m.rttFailStreak["港-A"] != 1 {
		t.Fatalf("fail streak must be 1, got %d", m.rttFailStreak["港-A"])
	}
	// 会话实测 RTT 40ms → 直写真实值，并学习 URLTest 开销（lastURLTest=90）
	m.RecordSessionRTT("港-A", 40)
	if got := m.SnapshotRTT()["港-A"]; got != 40 {
		t.Fatalf("session rtt must overwrite with truth, got %d", got)
	}
	if off := m.probeOffset["港-A"]; off != 50 { // 90-40=50
		t.Fatalf("probe offset must be learned, got %d want 50", off)
	}
	// 下一轮 URLTest 95ms：95-50=45（>=10 生效）→ EMA (40+45)/2=42
	m.MergeProbeResults(map[string]probeSample{"港-A": {RttMs: 95, Samples: 3, OK: true}})
	if got := m.SnapshotRTT()["港-A"]; got != 42 {
		t.Fatalf("offset-corrected EMA wrong, got %d want 42", got)
	}
}

// F1：连续 3 轮失败才判死（单轮失败不触发整池灭活，RC5a 成因封堵）。
func TestMergeProbeResults_FailStreakDead(t *testing.T) {
	m := newFixManager(true, nil)
	m.MergeProbeResults(map[string]probeSample{"港-A": {RttMs: 30, Samples: 3, OK: true}})
	fail := map[string]probeSample{"港-A": {OK: false}}
	m.MergeProbeResults(fail)
	m.MergeProbeResults(fail)
	if got := m.SnapshotRTT()["港-A"]; got != 30 {
		t.Fatalf("two failures must keep value, got %d", got)
	}
	m.MergeProbeResults(fail)
	if got := m.SnapshotRTT()["港-A"]; got != 0 {
		t.Fatalf("three failures must mark dead (0), got %d", got)
	}
}

// F4：新注册队列——入队 / 去重保序取走 / 取空。
func TestNewRegistrationQueue(t *testing.T) {
	m := newFixManager(true, nil)
	m.pushNewRegistration("1.1.1.1")
	m.pushNewRegistration("1.1.1.1")
	m.pushNewRegistration("2.2.2.2")
	got := m.DrainNewRegistrations()
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2.2.2.2" {
		t.Fatalf("drain wrong: %v", got)
	}
	if got := m.DrainNewRegistrations(); len(got) != 0 {
		t.Fatalf("second drain must be empty, got %v", got)
	}
}

// F10：端口归一——27022 必须可注册（红线 11），8125 必须排除，双表合一。
func TestAutoRegPortUnification(t *testing.T) {
	if !skipAutoRegPorts[443] || !skipAutoRegPorts[8081] || !skipAutoRegPorts[8125] {
		t.Fatalf("443/8081/8125 must be excluded")
	}
	if skipAutoRegPorts[27022] {
		t.Fatalf("27022 must NOT be excluded (red line: APEX 对局端口段必须注册)")
	}
	for k := range skipAutoRegPorts {
		if !flowSkipPorts[k] {
			t.Fatalf("flowSkipPorts must contain %d (single source)", k)
		}
	}
	if len(flowSkipPorts) != len(skipAutoRegPorts) {
		t.Fatalf("flowSkipPorts must be the same table as skipAutoRegPorts")
	}
}

// F11：段表接线——云段命中但区不可信；内置段命中且区可信；未知 IP 不命中。
func TestSegmentTableBuiltInAndCloud(t *testing.T) {
	cloud := netip.MustParseAddr("216.244.12.50")
	if !SegmentTable().MatchIP(cloud) {
		t.Fatalf("216.244.0.0/16 must hit (known game cloud segment)")
	}
	if SegmentTable().RegionTrustedFor(cloud) {
		t.Fatalf("cloud segment must NOT be region-trusted (red line 2)")
	}
	builtin := netip.MustParseAddr("103.28.54.116")
	if !SegmentTable().MatchIP(builtin) || !SegmentTable().RegionTrustedFor(builtin) {
		t.Fatalf("103.28.54.0/24 must hit and be region-trusted")
	}
	unknown := netip.MustParseAddr("93.184.216.34")
	if SegmentTable().MatchIP(unknown) || SegmentTable().RegionTrustedFor(unknown) {
		t.Fatalf("unknown IP must not hit segment table")
	}
}

// F8：非 QUIC 综合分权重 0.6/0.4——零丢包 + 高 RTT 不再判坏窗口。
func TestNonQUICScore_NoBadWindowOnRttAlone(t *testing.T) {
	cfg := DefaultConfig()
	// 零丢包 + RTT 400ms：新口径 0.6*100 + 0.4*0 = 60，不低于 ScoreBad(60)
	w := &windowStats{isQUIC: false}
	w.recv = 10
	w.rttMs = append(w.rttMs, 400)
	if s := w.score(cfg); s < cfg.ScoreBad {
		t.Fatalf("zero-loss high-rtt non-QUIC must not be bad window, score=%v", s)
	}
	// 满分口径：零丢包 + RTT 40ms → 100
	w2 := &windowStats{isQUIC: false}
	w2.recv = 10
	w2.rttMs = append(w2.rttMs, 40)
	if s := w2.score(cfg); s < 99.9 {
		t.Fatalf("perfect non-QUIC window must score ~100, got %v", s)
	}
}
