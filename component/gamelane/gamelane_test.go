package gamelane

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func testMetadata(process string, dst string) *C.Metadata {
	addr, err := netip.ParseAddr(dst)
	if err != nil {
		panic(err)
	}
	return &C.Metadata{
		Process: process,
		DstIP:   addr,
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 54321,
	}
}

func newManager(enabled bool, targets []Target) *Manager {
	m := &Manager{}
	m.SetEnabled(enabled)
	m.SetTargets(targets)
	return m
}

// 进程名命中（非 TUN）
func TestMatch_ProcessName(t *testing.T) {
	m := newManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "GAME-PROXY"},
	})
	proxy, ok := m.Match(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok || proxy != "GAME-PROXY" {
		t.Fatalf("want (GAME-PROXY,true), got (%s,%v)", proxy, ok)
	}
}

// PID 反查命中（Process 为空时经 findProcess 注入反查）
func TestMatch_PIDFallback(t *testing.T) {
	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) {
		return 1234, "game.exe"
	}
	defer func() { findProcess = old }()

	m := newManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "GAME-PROXY"},
	})
	proxy, ok := m.Match(testMetadata("", "1.2.3.4"), false)
	if !ok || proxy != "GAME-PROXY" {
		t.Fatalf("want (GAME-PROXY,true), got (%s,%v)", proxy, ok)
	}
}

// CIDR 命中（非 TUN）
func TestMatch_CIDR(t *testing.T) {
	m := newManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}, Proxy: "GAME-PROXY"},
	})
	proxy, ok := m.Match(testMetadata("", "1.2.3.9"), false)
	if !ok || proxy != "GAME-PROXY" {
		t.Fatalf("want (GAME-PROXY,true), got (%s,%v)", proxy, ok)
	}
}

// TUN 下仅 CIDR 命中，进程名不参与匹配
func TestMatch_TUN_ProcessIgnored(t *testing.T) {
	m := newManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "BY-PROC"},
		{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}, Proxy: "BY-CIDR"},
	})
	proxy, ok := m.Match(testMetadata("game.exe", "1.2.3.9"), true)
	if !ok || proxy != "BY-CIDR" {
		t.Fatalf("TUN want (BY-CIDR,true), got (%s,%v)", proxy, ok)
	}

	proxy, ok = m.Match(testMetadata("game.exe", "8.8.8.8"), true)
	if ok {
		t.Fatalf("TUN process-name must not hit, got (%s,true)", proxy)
	}
}

// TUN 下 CIDR 直配命中
func TestMatch_TUN_CIDRDirect(t *testing.T) {
	m := newManager(true, []Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}, Proxy: "GAME-PROXY"},
	})
	proxy, ok := m.Match(testMetadata("", "1.2.3.200"), true)
	if !ok || proxy != "GAME-PROXY" {
		t.Fatalf("want (GAME-PROXY,true), got (%s,%v)", proxy, ok)
	}
}

// 未命中零影响
func TestMatch_NoHit(t *testing.T) {
	m := newManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "GAME-PROXY"},
		{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}, Proxy: "BY-CIDR"},
	})
	proxy, ok := m.Match(testMetadata("browser.exe", "8.8.8.8"), false)
	if ok {
		t.Fatalf("want miss, got (%s,true)", proxy)
	}
}

// 未启用零影响
func TestMatch_Disabled(t *testing.T) {
	m := newManager(false, []Target{
		{ProcessName: "game.exe", Proxy: "GAME-PROXY"},
	})
	proxy, ok := m.Match(testMetadata("game.exe", "1.2.3.4"), false)
	if ok {
		t.Fatalf("disabled must miss, got (%s,true)", proxy)
	}
}

// MatchTarget 返回完整 Target（含 Fallback），供预测式切换接线使用
func TestMatchTarget_ReturnsFallback(t *testing.T) {
	m := newManager(true, []Target{
		// 2026-10-17（需求 A/Q9）：显式 fallbacks 五区过滤，节点名改 tagger
		// 可解析的 "HK-GOOD"（原 "GOOD" 无区标签会被滤除，池变空）。
		{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}, Proxy: "FAST", Fallbacks: []string{"HK-GOOD"}},
	})
	tgt, ok := m.MatchTarget(testMetadata("", "1.2.3.9"), false)
	if !ok || tgt == nil {
		t.Fatalf("want hit, got miss")
	}
	if tgt.Proxy != "FAST" || len(tgt.Fallbacks) != 1 || tgt.Fallbacks[0] != "HK-GOOD" {
		t.Fatalf("want (FAST,[HK-GOOD]), got (%s,%v)", tgt.Proxy, tgt.Fallbacks)
	}
}

// MatchTarget 未命中返回 nil,false
func TestMatchTarget_Miss(t *testing.T) {
	m := newManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "FAST"},
	})
	tgt, ok := m.MatchTarget(testMetadata("browser.exe", "8.8.8.8"), false)
	if ok || tgt != nil {
		t.Fatalf("want miss, got (%v,%v)", tgt, ok)
	}
}

// 进程名优先于 CIDR
func TestMatch_Priority(t *testing.T) {
	m := newManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "BY-PROC"},
		{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}, Proxy: "BY-CIDR"},
	})
	proxy, ok := m.Match(testMetadata("game.exe", "1.2.3.9"), false)
	if !ok || proxy != "BY-PROC" {
		t.Fatalf("want (BY-PROC,true), got (%s,%v)", proxy, ok)
	}
}

// Default 单例与 GetTargets 副本语义
func TestManagerDefaultAndGetTargets(t *testing.T) {
	if Default() == nil {
		t.Fatal("Default must not be nil")
	}
	if Default() != defaultManager {
		t.Fatal("Default must return package singleton")
	}

	m := newManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "GAME-PROXY"},
	})
	got := m.GetTargets()
	if len(got) != 1 || got[0].Proxy != "GAME-PROXY" {
		t.Fatalf("GetTargets must return registered copy, got %+v", got)
	}
	// 副本隔离：修改返回切片不影响注册表
	got[0].Proxy = "HACKED"
	if m.GetTargets()[0].Proxy != "GAME-PROXY" {
		t.Fatal("GetTargets must return a defensive copy")
	}
}
