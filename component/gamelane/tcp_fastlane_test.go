package gamelane

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// TCP 快速通道回归：auto 目标首次命中（TCP 形态元数据，如大厅/登录仅 TCP 流量）
// 即触发 Auto-Pick Primary 并回报全局 current_proxy —— 面板"当前出口节点"依赖
// 此链路显示实际节点；此前快速通道仅挂载 UDP 路径，TCP 命中无法触发回报，
// 面板出口恒为空（hits=[] 之外的第二根因）。
func TestMatch_TCPFastlane_ReportsCurrentProxy(t *testing.T) {
	// 清理全局统计，避免历史测试残留污染断言
	M3Default().currentProxy.Store("")

	m := newAutoManager(true, []Target{{ProcessName: "game.exe", Proxy: ""}})
	m.SetAllProxies([]string{"香港-01", "日本-01"})
	m.SetRTTTable(map[string]int{"香港-01": 120, "日本-01": 40})

	md := testMetadata("game.exe", "1.2.3.4")
	md.NetWork = C.TCP // TCP 形态连接

	proxy, ok := m.Match(md, false)
	if !ok {
		t.Fatal("TCP metadata must hit fastlane target")
	}
	if proxy != "日本-01" {
		t.Fatalf("temporary primary want 日本-01 (lowest RTT), got %q", proxy)
	}
	if got := GetM3Snapshot().CurrentProxy; got != proxy {
		t.Fatalf("current_proxy must be reported for TCP hit, want %q got %q", proxy, got)
	}
}

// TCP 快速通道回退：命中 auto 目标但无可用节点时保持 DIRECT（空串），
// 且不回报空 current_proxy（RecordM3Active 忽略空值），保证面板不显示
// 错误的"空节点已选"。
func TestMatch_TCPFastlane_NoPool_Direct_NoReport(t *testing.T) {
	M3Default().currentProxy.Store("")

	m := newAutoManager(true, []Target{{ProcessName: "game.exe", Proxy: ""}})
	m.SetAllProxies(nil)
	m.SetRTTTable(nil)

	md := testMetadata("game.exe", "1.2.3.4")
	md.NetWork = C.TCP

	proxy, ok := m.Match(md, false)
	if !ok {
		t.Fatal("TCP metadata must still hit target even without pool")
	}
	// Match 返回 EffectiveProxy() 原值：空池即空串，tunnel 层据此回退常规 rules（直连），
	// 与显式 DIRECT 目标（proxy="DIRECT"）在语义上一致但返回值形态不同。
	if proxy != "" {
		t.Fatalf("empty pool want DIRECT (\"\"), got %q", proxy)
	}
	if got := GetM3Snapshot().CurrentProxy; got != "" {
		t.Fatalf("empty pool must not report current_proxy, got %q", got)
	}
}
