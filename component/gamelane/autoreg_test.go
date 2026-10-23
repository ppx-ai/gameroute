package gamelane

import (
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func autoregManager(enabled bool) *Manager {
	m := &Manager{}
	m.SetEnabled(enabled)
	return m
}

func gameMetadata(dst string, dstPort uint16) *C.Metadata {
	addr, err := netip.ParseAddr(dst)
	if err != nil {
		panic(err)
	}
	return &C.Metadata{
		DstIP:   addr,
		DstPort: dstPort,
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 54321,
	}
}

// 注册单 IP：首次成功、重复幂等、auto 空串语义（M3 managed）、/32 CIDR
func TestRegisterTargetIP_AddAndIdempotent(t *testing.T) {
	m := autoregManager(true)
	if !m.RegisterTargetIP("20.198.217.103") {
		t.Fatal("first register should add")
	}
	if m.RegisterTargetIP("20.198.217.103") {
		t.Fatal("duplicate register should be idempotent (return false)")
	}
	ts := m.GetTargets()
	if len(ts) != 1 {
		t.Fatalf("want 1 target, got %d", len(ts))
	}
	if ts[0].Proxy != "" {
		t.Fatalf("auto-registered target must be auto (empty proxy), got %q", ts[0].Proxy)
	}
	if len(ts[0].CIDR) != 1 || ts[0].CIDR[0] != netip.MustParsePrefix("20.198.217.103/32") {
		t.Fatalf("unexpected CIDR: %v", ts[0].CIDR)
	}
}

// 已被现有 CIDR 覆盖的 IP 不重复注册
func TestRegisterTargetIP_CoveredByExisting(t *testing.T) {
	m := autoregManager(true)
	m.SetTargets([]Target{{CIDR: []netip.Prefix{netip.MustParsePrefix("20.198.0.0/16")}, Proxy: "X"}})
	if m.RegisterTargetIP("20.198.1.2") {
		t.Fatal("IP already covered by existing CIDR, should not add")
	}
	if len(m.GetTargets()) != 1 {
		t.Fatalf("targets should stay 1, got %d", len(m.GetTargets()))
	}
}

// 动态删除
func TestUnregisterTargetIP(t *testing.T) {
	m := autoregManager(true)
	m.RegisterTargetIP("20.198.217.103")
	if !m.UnregisterTargetIP("20.198.217.103") {
		t.Fatal("unregister should remove")
	}
	if m.UnregisterTargetIP("20.198.217.103") {
		t.Fatal("second unregister should be false")
	}
	if len(m.GetTargets()) != 0 {
		t.Fatalf("targets should be empty, got %d", len(m.GetTargets()))
	}
}

// 游戏进程 UDP 目标 → 识别即注册，首包 Match 命中 auto 空串（由 M3 动态分配）
func TestRegisterGameTargetIfNeeded_GameProcess(t *testing.T) {
	old := findProcess
	oldPort := findProcessByPort
	findProcess = func(m *C.Metadata) (uint32, string) { return 100, "TslGame.exe" }
	findProcessByPort = func(m *C.Metadata) (uint32, string) { return 100, "TslGame.exe" }
	defer func() { findProcess = old; findProcessByPort = oldPort }()

	m := autoregManager(true)
	md := gameMetadata("20.198.217.103", 29817)
	if !m.RegisterGameTargetIfNeeded(md, true) {
		t.Fatal("game UDP target should auto-register")
	}
	proxy, ok := m.Match(md, true)
	if !ok || proxy != "" {
		t.Fatalf("want (\"\",true), got (%s,%v)", proxy, ok)
	}
}

// 非游戏进程不注册
func TestRegisterGameTargetIfNeeded_NonGameProcess(t *testing.T) {
	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) { return 200, "chrome.exe" }
	defer func() { findProcess = old }()

	m := autoregManager(true)
	if m.RegisterGameTargetIfNeeded(gameMetadata("20.198.217.103", 29817), true) {
		t.Fatal("non-game process should not register")
	}
	if len(m.GetTargets()) != 0 {
		t.Fatal("targets should stay empty")
	}
}

// 关闭状态不注册
func TestRegisterGameTargetIfNeeded_Disabled(t *testing.T) {
	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) { return 100, "TslGame.exe" }
	defer func() { findProcess = old }()

	m := autoregManager(false)
	if m.RegisterGameTargetIfNeeded(gameMetadata("20.198.217.103", 29817), true) {
		t.Fatal("disabled should not register")
	}
}

// 大厅/CDN/Steam 探测端口跳过（443 / 8081 / 27022）
func TestRegisterGameTargetIfNeeded_SkipProbePorts(t *testing.T) {
	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) { return 100, "TslGame.exe" }
	defer func() { findProcess = old }()

	m := autoregManager(true)
	for _, p := range []uint16{443, 8081, 27022} {
		if m.RegisterGameTargetIfNeeded(gameMetadata("20.196.246.195", p), true) {
			t.Fatalf("probe port %d should not auto-register", p)
		}
	}
	if len(m.GetTargets()) != 0 {
		t.Fatal("no probe targets should be registered")
	}
}

// 私网 / IPv6 跳过
func TestRegisterGameTargetIfNeeded_SkipNonPublic(t *testing.T) {
	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) { return 100, "TslGame.exe" }
	defer func() { findProcess = old }()

	m := autoregManager(true)
	if m.RegisterGameTargetIfNeeded(gameMetadata("192.168.1.5", 29817), true) {
		t.Fatal("private IP should not register")
	}
	if m.RegisterGameTargetIfNeeded(gameMetadata("2001:db8::1", 29817), true) {
		t.Fatal("IPv6 should not register")
	}
}

// 已注册幂等：不重复添加
func TestRegisterGameTargetIfNeeded_AlreadyRegistered(t *testing.T) {
	old := findProcess
	oldPort := findProcessByPort
	findProcess = func(m *C.Metadata) (uint32, string) { return 100, "TslGame.exe" }
	findProcessByPort = func(m *C.Metadata) (uint32, string) { return 100, "TslGame.exe" }
	defer func() { findProcess = old; findProcessByPort = oldPort }()

	m := autoregManager(true)
	md := gameMetadata("20.198.217.103", 29817)
	if !m.RegisterGameTargetIfNeeded(md, true) {
		t.Fatal("first call should register")
	}
	if m.RegisterGameTargetIfNeeded(md, true) {
		t.Fatal("second call should be idempotent")
	}
}

// 进程反查失败（无法识别）不注册
func TestRegisterGameTargetIfNeeded_ProcessUnavailable(t *testing.T) {
	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) { return 0, "" }
	defer func() { findProcess = old }()

	m := autoregManager(true)
	if m.RegisterGameTargetIfNeeded(gameMetadata("20.198.217.103", 29817), true) {
		t.Fatal("process unavailable should not register")
	}
}

// 非 UDP 元数据（进程反查按 UDP 语义）仍按目标特征注册——仅作进程判定，无协议分支
func TestRegisterGameTargetIfNeeded_PUBGKeyword(t *testing.T) {
	old := findProcess
	oldPort := findProcessByPort
	findProcess = func(m *C.Metadata) (uint32, string) { return 300, "ExecPubg-Win64-Shipping.exe" }
	findProcessByPort = func(m *C.Metadata) (uint32, string) { return 300, "ExecPubg-Win64-Shipping.exe" }
	defer func() { findProcess = old; findProcessByPort = oldPort }()

	m := autoregManager(true)
	if !m.RegisterGameTargetIfNeeded(gameMetadata("103.28.54.102", 25000), true) {
		t.Fatal("pubg keyword process should register")
	}
}
