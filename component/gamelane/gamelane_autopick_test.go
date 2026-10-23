package gamelane

import (
	"reflect"
	"testing"
)

// newAutoManager 构造带默认圈选参数（candidateTopN=5）的 Manager，供 MatchTarget 自动圈选测试使用。
func newAutoManager(enabled bool, targets []Target) *Manager {
	m := newDefaultManager()
	m.SetEnabled(enabled)
	m.SetTargets(targets)
	return m
}

// 自动圈选：主代理 HK，从混合地区节点池中只圈出 HK 节点，按 RTT 升序，硬上限 5。
func TestAutoPickFallbacks_RegionalTopN(t *testing.T) {
	m := newDefaultManager()
	all := []string{
		"香港-01", "香港-02", "香港-03", "香港-04", "香港-05", "香港-06", // 6 个 HK
		"日本-01", "日本-02", "美国-01", "新加坡-01",
	}
	rtt := map[string]int{
		"香港-01": 120, "香港-02": 15, "香港-03": 45,
		"香港-04": 80, "香港-05": 200, "香港-06": 30,
		"日本-01": 10, "日本-02": 20, "美国-01": 300, "新加坡-01": 90,
	}

	got := m.autoPickFallbacks("香港-01", all, rtt)
	// 只圈 HK，最多 5 个
	if len(got) != 5 {
		t.Fatalf("autoPick(HK) len = %d, want 5 (topN cap)", len(got))
	}
	for _, n := range got {
		if r, ok := extractRegionTag(n); !ok || r != "HK" {
			t.Fatalf("autoPick(HK) returned non-HK node: %s", n)
		}
	}
	// 按 RTT 升序（期望 02/06/03/04/01，15/30/45/80/120）
	want := []string{"香港-02", "香港-06", "香港-03", "香港-04", "香港-01"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("autoPick(HK) = %v, want %v", got, want)
	}
}

// 自动圈选：同地区节点不足 5 时全量返回（不虚构）。
func TestAutoPickFallbacks_RegionalShort(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "香港-02", "日本-01"}
	rtt := map[string]int{"香港-01": 10, "香港-02": 20, "日本-01": 5}

	got := m.autoPickFallbacks("香港-01", all, rtt)
	if len(got) != 2 {
		t.Fatalf("autoPick(HK short) len = %d, want 2", len(got))
	}
}

// 自动圈选：主代理无地区标签 → 不圈选（退回配置优先，保持单 fallback 行为）。
func TestAutoPickFallbacks_NoRegionTag(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01"}
	rtt := map[string]int{"香港-01": 10, "日本-01": 5}

	got := m.autoPickFallbacks("GAME-01", all, rtt)
	if got != nil {
		t.Fatalf("autoPick(no region) = %v, want nil", got)
	}
}

// 自动圈选：无同地区节点 → 退化到全局 RTT top N，且不含 RTT 缺失节点。
func TestAutoPickFallbacks_NoSameRegionDegradesGlobalRTT(t *testing.T) {
	m := newDefaultManager()
	all := []string{"日本-01", "日本-02", "美国-01", "新加坡-01", "韩国-01"}
	rtt := map[string]int{
		"日本-01": 10, "日本-02": 20, "美国-01": 30,
		"新加坡-01": 40, // 韩国-01 无 RTT，应被剔除
	}

	got := m.autoPickFallbacks("香港-01", all, rtt)
	if len(got) != 4 {
		t.Fatalf("autoPick(no HK, global rtt) len = %d, want 4 (韩国-01 无 RTT 剔除)", len(got))
	}
	for i := 1; i < len(got); i++ {
		if rtt[got[i]] < rtt[got[i-1]] {
			t.Fatalf("global rtt topN not sorted: %v", got)
		}
	}
	if got[0] != "日本-01" {
		t.Fatalf("global rtt topN first = %s, want 日本-01 (最低 RTT)", got[0])
	}
}

// 配置优先：配置写了 fallbacks 时，MatchTarget 不得用自动圈选覆盖。
func TestMatchTarget_ConfigFallbacksWins(t *testing.T) {
	m := newAutoManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "香港-01", Fallbacks: []string{"日本-01"}},
	})
	m.SetAllProxies([]string{"香港-01", "香港-02", "香港-03", "日本-01"})
	m.SetRTTTable(map[string]int{"香港-01": 10, "香港-02": 5, "香港-03": 8, "日本-01": 3})

	tgt, ok := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok {
		t.Fatal("MatchTarget miss")
	}
	if !reflect.DeepEqual(tgt.Fallbacks, []string{"日本-01"}) {
		t.Fatalf("config fallbacks overwritten: %v", tgt.Fallbacks)
	}
}

// 自动圈选注入：fallbacks 为空且主出口为香港节点 → 命中后自动圈出香港候选池。
// 对应验收"真实场景：主出口用香港节点 → 自动圈出香港候选池（≥1 个真实节点）"。
func TestMatchTarget_AutoPickOnEmptyFallbacks(t *testing.T) {
	m := newAutoManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "香港-01"},
	})
	m.SetAllProxies([]string{"香港-01", "香港-02", "香港-03", "日本-01", "美国-01"})
	m.SetRTTTable(map[string]int{
		"香港-01": 12, "香港-02": 30, "香港-03": 20,
		"日本-01": 8, "美国-01": 100,
	})

	tgt, ok := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok {
		t.Fatal("MatchTarget miss")
	}
	for _, n := range tgt.Fallbacks {
		if r, has := extractRegionTag(n); !has || r != "HK" {
			t.Fatalf("auto picked non-HK node: %s", n)
		}
	}
	// 香港-01 自身 RTT 12 也应在池中（同地区圈选含主出口）
	if tgt.Fallbacks[0] != "香港-01" {
		t.Fatalf("auto pick order = %v, want 香港-01 first", tgt.Fallbacks)
	}
}

// 刷新淘汰补入：RTT 表更新且刷新间隔到达后再次 MatchTarget，候选池按新 RTT 重排（淘汰劣化节点、补入优节点）。
func TestMatchTarget_RTTRefreshReplacesPool(t *testing.T) {
	m := newAutoManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "香港-01"},
	})
	m.refreshMinInterval = 0 // 强制每次命中都允许刷新
	m.SetAllProxies([]string{"香港-01", "香港-02", "香港-03"})
	m.SetRTTTable(map[string]int{"香港-01": 50, "香港-02": 10, "香港-03": 100})

	tgt1, _ := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if tgt1.Fallbacks[0] != "香港-02" {
		t.Fatalf("first pool head = %s, want 香港-02", tgt1.Fallbacks[0])
	}

	// 懒测刷新：香港-02 劣化到 300，香港-03 优化到 5
	m.SetRTTTable(map[string]int{"香港-01": 50, "香港-02": 300, "香港-03": 5})
	tgt2, _ := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if tgt2.Fallbacks[0] != "香港-03" {
		t.Fatalf("refreshed pool head = %s, want 香港-03 (淘汰 香港-02)", tgt2.Fallbacks[0])
	}
}

// 刷新冷却：默认 60s 懒测间隔内，RTT 变化不触发重新圈选（沿用旧池，避免高频重圈）。
func TestMatchTarget_RefreshCooldownSkips(t *testing.T) {
	m := newAutoManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "香港-01"},
	})
	m.SetAllProxies([]string{"香港-01", "香港-02", "香港-03"})
	m.SetRTTTable(map[string]int{"香港-01": 50, "香港-02": 10, "香港-03": 100})

	tgt1, _ := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if tgt1.Fallbacks[0] != "香港-02" {
		t.Fatalf("first pool head = %s, want 香港-02", tgt1.Fallbacks[0])
	}

	// 冷却期内 RTT 变化：不应重圈，仍沿用旧池
	m.SetRTTTable(map[string]int{"香港-01": 50, "香港-02": 300, "香港-03": 5})
	tgt2, _ := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if tgt2.Fallbacks[0] != "香港-02" {
		t.Fatalf("cooldown violated: pool head = %s, want still 香港-02", tgt2.Fallbacks[0])
	}
}
