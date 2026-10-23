package gamelane

import (
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// ===== MatchTCP：TCP 固定快速通道（PUBG 大厅 TCP 流量接入） =====
// 语义约束（与 Match 的 UDP 预测式切换严格隔离）：
//   - TCP 命中只取固定出口快照，绝不参与预测式切换 / 劣化自动切换；
//   - 不计 switch_count / last_switch_at（切换语义只属于 UDP 预测式切换）；
//   - 命中回报 current_proxy 即可，不触发候选池探测与换优逻辑。

// TCP 命中 CIDR auto 目标：返回固定出口并回报 current_proxy，切换计数保持 0。
func TestMatchTCP_HitsCIDR_ReturnsFixedExit_AndReportsCurrentProxy(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)

	m := newAutoManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("103.28.54.0/24")}, Proxy: "auto"},
	})
	m.SetAllProxies([]string{"HK-A", "SG", "JP-B"})
	m.SetRTTTable(map[string]int{"HK-A": 120, "SG": 40, "JP-B": 90})

	md := testMetadata("", "103.28.54.102")
	md.NetWork = C.TCP // TCP 形态元数据（大厅/登录仅 TCP 流量）

	proxy, ok := m.MatchTCP(md, true) // TUN 下仅 CIDR 命中
	if !ok {
		t.Fatal("TCP CIDR hit must match fastlane target")
	}
	if proxy != "HK-A" {
		t.Fatalf("fixed exit want HK-A (geoip server-region lowest, dst=103.28.54.102 -> HK), got %q", proxy)
	}
	snap := GetM3Snapshot()
	if snap.CurrentProxy != "HK-A" {
		t.Fatalf("current_proxy must be reported for TCP hit, want HK-A got %q", snap.CurrentProxy)
	}
	if snap.SwitchCount != 0 {
		t.Fatalf("TCP hit must not count switch, got switch_count=%d", snap.SwitchCount)
	}
	if !snap.LastSwitchAt.IsZero() {
		t.Fatalf("TCP hit must not touch last_switch_at, got %v", snap.LastSwitchAt)
	}
}

// TCP 显式配置目标：返回配置出口并回报，不选临时主节点。
func TestMatchTCP_ExplicitProxy_ReturnsConfiguredProxy(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)

	m := newAutoManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("35.71.163.0/24")}, Proxy: "HK-A"},
	})

	md := testMetadata("", "35.71.163.61")
	md.NetWork = C.TCP

	proxy, ok := m.MatchTCP(md, true)
	if !ok {
		t.Fatal("TCP CIDR hit must match explicit target")
	}
	if proxy != "HK-A" {
		t.Fatalf("explicit exit want HK-A, got %q", proxy)
	}
	snap := GetM3Snapshot()
	if snap.CurrentProxy != "HK-A" {
		t.Fatalf("current_proxy must report configured exit, got %q", snap.CurrentProxy)
	}
	if snap.SwitchCount != 0 {
		t.Fatalf("TCP explicit hit must not count switch, got %d", snap.SwitchCount)
	}
}

// TCP 未命中：返回 false 且不触碰 current_proxy。
func TestMatchTCP_NoHit_ReturnsFalse_NoReport(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)
	M3Default().RecordM3Active("SG") // 预置已有出口，模拟对局内 UDP 已回报

	m := newAutoManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("103.28.54.0/24")}, Proxy: "auto"},
	})
	m.SetAllProxies([]string{"HK-A", "SG"})
	m.SetRTTTable(map[string]int{"HK-A": 80, "SG": 40})

	md := testMetadata("", "8.8.8.8")
	md.NetWork = C.TCP

	if proxy, ok := m.MatchTCP(md, true); ok || proxy != "" {
		t.Fatalf("non-target TCP must not match, got (%q,%v)", proxy, ok)
	}
	if got := GetM3Snapshot().CurrentProxy; got != "SG" {
		t.Fatalf("non-hit must not overwrite current_proxy, want SG got %q", got)
	}
}

// TCP 命中 auto 目标但无可用节点池：保持 DIRECT（空串），不回报空值。
func TestMatchTCP_NoPool_Direct_NoReport(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)

	m := newAutoManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("45.56.120.0/24")}, Proxy: "auto"},
	})
	m.SetAllProxies(nil)
	m.SetRTTTable(nil)

	md := testMetadata("", "45.56.120.40")
	md.NetWork = C.TCP

	proxy, ok := m.MatchTCP(md, true)
	if !ok {
		t.Fatal("TCP hit with empty pool must still return hit=true (DIRECT semantics)")
	}
	if proxy != "" {
		t.Fatalf("empty pool want DIRECT (\"\"), got %q", proxy)
	}
	if got := GetM3Snapshot().CurrentProxy; got != "" {
		t.Fatalf("empty pool must not report current_proxy, got %q", got)
	}
}

// TCP 固定性核心约束：命中后即使 RTT/节点池变化（劣化场景），
// TCP 出口保持不变、不生成候选池、不触发任何切换（switch_count 不变、
// last_switch_at 零值）——TCP 绝不参与预测式切换/劣化自动切换。
func TestMatchTCP_Degrade_NoSwitch_NoPoolGeneration(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)

	m := newAutoManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("103.28.54.0/24")}, Proxy: "auto"},
	})
	m.SetAllProxies([]string{"HK-A", "SG", "JP-B"})
	m.SetRTTTable(map[string]int{"HK-A": 120, "SG": 40, "JP-B": 90})

	md := testMetadata("", "103.28.54.102")
	md.NetWork = C.TCP

	first, ok := m.MatchTCP(md, true)
	if !ok {
		t.Fatal("first TCP hit must match")
	}
	// 劣化：原固定出口 RTT 恶化到最差、节点池变化，模拟候选池重新圈选条件成熟
	m.SetRTTTable(map[string]int{"HK-A": 30, "SG": 300, "JP-B": 200})
	m.SetAllProxies([]string{"HK-A", "JP-B"})

	second, ok2 := m.MatchTCP(md, true)
	if !ok2 {
		t.Fatal("second TCP hit must still match")
	}
	if second != first {
		t.Fatalf("TCP exit must stay fixed under degrade: first=%q second=%q", first, second)
	}

	targets := m.GetTargets()
	if len(targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(targets))
	}
	if len(targets[0].Fallbacks) != 0 {
		t.Fatalf("TCP hit must not generate candidate pool, got fallbacks=%v", targets[0].Fallbacks)
	}

	snap := GetM3Snapshot()
	if snap.SwitchCount != 0 {
		t.Fatalf("TCP degrade must not trigger switch, got switch_count=%d", snap.SwitchCount)
	}
	if !snap.LastSwitchAt.IsZero() {
		t.Fatalf("TCP degrade must not touch last_switch_at, got %v", snap.LastSwitchAt)
	}
}

// TCP 进程名命中（非 TUN）：同样返回固定出口并回报。
func TestMatchTCP_ProcessNameHit(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)

	m := newAutoManager(true, []Target{
		{ProcessName: "tslgame.exe", Proxy: "auto"},
	})
	m.SetAllProxies([]string{"HK-A", "SG"})
	m.SetRTTTable(map[string]int{"HK-A": 80, "SG": 40})

	md := testMetadata("tslgame.exe", "1.2.3.4")
	md.NetWork = C.TCP

	proxy, ok := m.MatchTCP(md, false)
	if !ok {
		t.Fatal("TCP process hit must match")
	}
	if proxy != "SG" {
		t.Fatalf("process hit fixed exit want SG, got %q", proxy)
	}
	if got := GetM3Snapshot().CurrentProxy; got != "SG" {
		t.Fatalf("current_proxy must report for process hit, got %q", got)
	}
}

// TCP 命中并回报后，时间轴不变：last_switch_at 保持零值（无任何切换语义）。
func TestMatchTCP_ReportsActive_NotSwitch(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)

	m := newAutoManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("119.28.227.0/24")}, Proxy: "auto"},
	})
	m.SetAllProxies([]string{"HK-A", "SG"})
	m.SetRTTTable(map[string]int{"HK-A": 40, "SG": 100})

	md := testMetadata("", "119.28.227.198")
	md.NetWork = C.TCP

	if _, ok := m.MatchTCP(md, true); !ok {
		t.Fatal("TCP hit must match")
	}
	if got := GetM3Snapshot().CurrentProxy; got != "HK-A" {
		t.Fatalf("want HK-A reported, got %q", got)
	}
	if !GetM3Snapshot().LastSwitchAt.IsZero() {
		t.Fatalf("MatchTCP must never set last_switch_at, got %v",
			GetM3Snapshot().LastSwitchAt.Format(time.RFC3339))
	}
}

// 关闭 game-lane 后 TCP 命中一律不匹配，current_proxy 保持原值。
func TestMatchTCP_Disabled_NoMatch(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)
	M3Default().RecordM3Active("SG")

	m := newAutoManager(false, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("103.28.54.0/24")}, Proxy: "auto"},
	})

	md := testMetadata("", "103.28.54.102")
	md.NetWork = C.TCP

	if proxy, ok := m.MatchTCP(md, true); ok || proxy != "" {
		t.Fatalf("disabled lane must not match TCP, got (%q,%v)", proxy, ok)
	}
	if got := GetM3Snapshot().CurrentProxy; got != "SG" {
		t.Fatalf("disabled lane must not touch current_proxy, want SG got %q", got)
	}
}

// 无目标注册表时 TCP 命中一律不匹配。
func TestMatchTCP_NoTargets_NoMatch(t *testing.T) {
	m := newAutoManager(true, nil)

	md := testMetadata("", "103.28.54.102")
	md.NetWork = C.TCP

	if proxy, ok := m.MatchTCP(md, true); ok || proxy != "" {
		t.Fatalf("empty targets must not match TCP, got (%q,%v)", proxy, ok)
	}
}

// TCP 进程反查回退：非 TUN 且 Process 未填充时经 findProcess 反查命中。
func TestMatchTCP_ProcessFallback(t *testing.T) {
	M3Default().ResetM3Stats()
	M3Default().SetM3Enabled(true)

	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) {
		return 4242, "tslgame.exe"
	}
	defer func() { findProcess = old }()

	m := newAutoManager(true, []Target{
		{ProcessName: "tslgame.exe", Proxy: "auto"},
	})
	m.SetAllProxies([]string{"HK-A", "SG"})
	m.SetRTTTable(map[string]int{"HK-A": 80, "SG": 40})

	md := testMetadata("", "1.2.3.4") // Process 为空 → 反查
	md.NetWork = C.TCP

	proxy, ok := m.MatchTCP(md, false)
	if !ok {
		t.Fatal("TCP process fallback must match")
	}
	if proxy != "SG" {
		t.Fatalf("fallback exit want SG, got %q", proxy)
	}
	if got := GetM3Snapshot().CurrentProxy; got != "SG" {
		t.Fatalf("current_proxy must report fallback hit, got %q", got)
	}
}
