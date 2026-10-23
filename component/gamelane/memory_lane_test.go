package gamelane

// Shadow Forking 改造回归：需求 E（五区锁死/网段级记忆/启动清洗）+ 需求 D（预热）。

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---- 需求 E2：RegionActual 五区锁死 ----

func TestRegionLock_WriteRejectsNonLane(t *testing.T) {
	m := newDefaultManager()
	m.remember("203.0.113.9", 0)
	m.rememberRegionActual("203.0.113.9", "DE")
	if got := m.lookUpRegionActual("203.0.113.9"); got != "" {
		t.Fatalf("non-lane region must be rejected (five-region lock), got %q", got)
	}
	m.rememberRegionActual("203.0.113.9", "HK")
	if got := m.lookUpRegionActual("203.0.113.9"); got != "HK" {
		t.Fatalf("lane region must be accepted, got %q", got)
	}
}

// ---- 需求 E4：网段级记忆（≥2 样本 / race 单样本 / /16 兜底） ----

func TestSegmentMemory_TwoSamplesRequired(t *testing.T) {
	m := newDefaultManager()
	m.remember("1.2.3.9", 0)
	m.rememberPreferredProxy("1.2.3.9", "HK-01")
	if _, _, level := m.lookUpSegmentPreferred("1.2.3.7"); level != "" {
		t.Fatalf("single passive sample must not be trusted, got level %q", level)
	}
	m.remember("1.2.3.10", 0)
	m.rememberPreferredProxy("1.2.3.10", "HK-01")
	px, _, level := m.lookUpSegmentPreferred("1.2.3.7")
	if px != "HK-01" || level != "/24" {
		t.Fatalf("two distinct IP samples must trust /24, got (%q,%q)", px, level)
	}
	m.mu.RLock()
	mem := m.memories["1.2.3.0/24"]
	m.mu.RUnlock()
	if mem == nil || mem.SegmentSamples != 2 || len(mem.SegmentIPs) != 2 {
		t.Fatalf("segment entry must carry 2 samples, got %+v", mem)
	}
}

func TestSegmentMemory_RaceWinnerSingleSample(t *testing.T) {
	m := newDefaultManager()
	m.rememberSegmentWinner("5.6.7.0/24", "KR-01", "KR")
	px, region, level := m.lookUpSegmentPreferred("5.6.7.200")
	if px != "KR-01" || region != "KR" || level != "/24" {
		t.Fatalf("race winner single sample must be trusted (Q10), got (%q,%q,%q)", px, region, level)
	}
}

func TestSegmentMemory_Fallback16(t *testing.T) {
	m := newDefaultManager()
	m.memMu.Lock()
	m.memories["9.9.0.0/16"] = &GameMemory{
		Key: "9.9.0.0/16", SegmentLevel: "/16", SegmentSamples: 2,
		SegmentSource: "passive", PreferredProxy: "HK-01", Status: "active",
		LastHitAt: time.Now().UnixMilli(),
	}
	m.memMu.Unlock()
	px, _, level := m.lookUpSegmentPreferred("9.9.1.7")
	if px != "HK-01" || level != "/16" {
		t.Fatalf("/16 fallback only when /24 absent, got (%q,%q)", px, level)
	}
}

// ---- 死六二：启动清洗（只清字段值，不删条目） ----

func TestMemoryStartupCleanup(t *testing.T) {
	m := newDefaultManager()
	m.memMu.Lock()
	m.memories["203.0.113.9/32"] = &GameMemory{
		Key: "203.0.113.9/32", Status: "active", Source: "process",
		ProcessName: "apex.exe", RegionActual: "DE", PreferredProxy: "美国01",
		LastHitAt: time.Now().UnixMilli(),
	}
	m.memMu.Unlock()

	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})

	m.memMu.Lock()
	mem := m.memories["203.0.113.9/32"]
	m.memMu.Unlock()
	if mem == nil {
		t.Fatal("startup cleanup must never delete whole entries (死六二)")
	}
	if mem.RegionActual != "" || mem.PreferredProxy != "" {
		t.Fatalf("non-lane region / out-of-pool proxy must be cleared, got %+v", mem)
	}
	if mem.ProcessName != "apex.exe" || mem.Source != "process" {
		t.Fatalf("process identification must be preserved, got %+v", mem)
	}
}

// ---- 需求 D：模板学习 / 节流 / 预算 / 回包不进 TUN ----

func TestPreheat_TemplateThrottleBudget(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	var connsMu sync.Mutex
	conns := 0
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		connsMu.Lock()
		conns++
		connsMu.Unlock()
		return newFakeRaceConn(20 * time.Millisecond), nil
	})

	payload := []byte{0xff, 0xff, 0xff, 0xff, 9, 9, 9, 9, 1, 0, 0, 0}
	m.LearnProbeTemplate("198.51.100.9", 7770, payload)

	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, 9}), 7770)
	budget := int32(20)
	if n := m.PreheatTarget(dst, &budget); n <= 0 {
		t.Fatalf("first preheat must send probes, got %d", n)
	}
	if n := m.PreheatTarget(dst, &budget); n != 0 {
		t.Fatalf("throttle: second preheat within 5s must be skipped, got %d lanes", n)
	}

	// 预算上限：预算 3 时最多 3 条旁路（五区 5 冠军被截断）
	m.LearnProbeTemplate("198.51.100.10", 7770, payload)
	dst2 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, 10}), 7770)
	small := int32(3)
	if n := m.PreheatTarget(dst2, &small); n > 3 {
		t.Fatalf("budget must cap lanes, got %d > 3", n)
	}
	time.Sleep(300 * time.Millisecond) // 让回包进入 RTT 统计（不写 TUN）
	connsMu.Lock()
	defer connsMu.Unlock()
	if conns == 0 {
		t.Fatal("preheat must dial bypass lanes")
	}
}

func TestPreheat_NoTemplateNoProbe(t *testing.T) {
	m := newDefaultManager()
	var dialed int
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		dialed++
		return newFakeRaceConn(time.Millisecond), nil
	})
	budget := int32(20)
	if n := m.PreheatTarget(netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 99}), 7770), &budget); n != 0 || dialed != 0 {
		t.Fatalf("no template = no probe (需求 D5), got lanes=%d dialed=%d", n, dialed)
	}
}
