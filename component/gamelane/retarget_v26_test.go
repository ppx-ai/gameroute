package gamelane

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// ---- 2026-10-19 v2.6 收官：第一刀/第二刀联动用例 ----

// 联动 A（终批复修正一/二）：Fake-IP + 游戏域名会话的 4 级选路。
func TestMatchTarget_FakeIPGameDomain_FourLevels(t *testing.T) {
	// ④ 五区池第 1 个可用节点（无 rtt/无 bestRace/无段锁——开机初期保底）
	m := newDefaultManager()
	m.SetEnabled(true)
	m.SetAllProxies([]string{"HK-01", "HK-02", "TW-01"})
	meta := &C.Metadata{DNSMode: C.DNSFakeIP, Host: "xxx.ea.com", DstPort: 3074}
	tgt, ok := m.MatchTarget(meta, true)
	if !ok || tgt.EffectiveProxy() != "HK-01" {
		t.Fatalf("level-4 pool-first expected HK-01, got %q ok=%v", tgt.EffectiveProxy(), ok)
	}

	// ③ HK 区冠军（race 源 RTT：HK-02=25 < HK-01=90）
	m.mu.Lock()
	m.rttTable = map[string]int{"HK-01": 90, "HK-02": 25}
	m.rttSource = map[string]string{"HK-01": "race", "HK-02": "race"}
	m.mu.Unlock()
	tgt, ok = m.MatchTarget(meta, true)
	if !ok || tgt.EffectiveProxy() != "HK-02" {
		t.Fatalf("level-3 HK champion expected HK-02, got %q ok=%v", tgt.EffectiveProxy(), ok)
	}

	// ② bestRaceWinner 压过 ③（全局最优优先）
	m.updateBestRaceWinner("TW-01", "TW", 20)
	tgt, ok = m.MatchTarget(meta, true)
	if !ok || tgt.EffectiveProxy() != "TW-01" {
		t.Fatalf("level-2 bestRace expected TW-01, got %q ok=%v", tgt.EffectiveProxy(), ok)
	}

	// ① 域名段锁压过 ②（锁定优先）
	m.lockSegment("18.162.1.0/24", "xxx.ea.com", "HK-02", "HK", 25)
	tgt, ok = m.MatchTarget(meta, true)
	if !ok || tgt.EffectiveProxy() != "HK-02" {
		t.Fatalf("level-1 host segment lock expected HK-02, got %q ok=%v", tgt.EffectiveProxy(), ok)
	}

	// 非 GameLane 管理的 fake-ip 会话不进域分支（落规则路径）
	m2 := newDefaultManager()
	m2.SetEnabled(true)
	m2.SetAllProxies([]string{"HK-01"})
	if _, ok := m2.MatchTarget(&C.Metadata{DNSMode: C.DNSFakeIP, Host: "example.com", DstPort: 3074}, true); ok {
		t.Fatal("non-game fake-ip session must NOT hit the lane domain branch")
	}

	// master=false：Enabled 门拦截，域分支不生效（验收 4 两状态机制）
	m3 := newDefaultManager()
	m3.SetAllProxies([]string{"HK-01"})
	if _, ok := m3.MatchTarget(meta, true); ok {
		t.Fatal("disabled manager must not match")
	}

	// ⑤ 五区池空（Q8 极端）：弃权落规则
	m4 := newDefaultManager()
	m4.SetEnabled(true)
	if _, ok := m4.MatchTarget(meta, true); ok {
		t.Fatal("empty pool must abstain (fall to rules)")
	}
}

// 联动 B：Fake-IP 会话绝不注册（198.18.x.x 防污染）。
func TestRegisterGameTargetIfNeeded_RejectsFakeIP(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	meta := &C.Metadata{DstIP: netip.MustParseAddr("198.18.0.45"), Host: "xxx.ea.com", DstPort: 3074}
	if m.RegisterGameTargetIfNeeded(meta, true) {
		t.Fatal("fake-ip DstIP must NEVER be registered (v2.3 铁令复活前移)")
	}
	m.mu.RLock()
	n := len(m.targets)
	m.mu.RUnlock()
	if n != 0 {
		t.Fatalf("targets must stay empty, got %d", n)
	}
}

// 联动 C：赛马旁路解析出 realIP 后注册 realIP/32（替代被删的 tunnel 衔接1）。
func TestStartShadowForkingForFakeHost_RegistersRealIP(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		return newFakeRaceConn(30 * time.Millisecond), nil
	})
	m.SetRealIPResolver(func(host string) (netip.Addr, error) {
		return netip.AddrFrom4([4]byte{203, 0, 113, 9}), nil
	})
	var mu sync.Mutex
	writeBack := func([]byte) bool {
		mu.Lock()
		defer mu.Unlock()
		return true
	}
	payload := []byte{0xff, 0xff, 0xff, 0xff, 5, 5, 5, 5, 1, 0, 0, 0}
	m.StartShadowForkingForFakeHost("dc-eu.example.com", 7770, payload, writeBack)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.getSegmentLock("203.0.113.0/24") != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 赛马认出的真实服务器 IP 必须已入 targets（真实 IP 会话可被 Match 命中）
	realMeta := &C.Metadata{DstIP: netip.MustParseAddr("203.0.113.9"), DstPort: 7770}
	tgt, ok := m.MatchTarget(realMeta, true)
	if !ok || tgt.EffectiveProxy() == "" {
		t.Fatal("race-registered realIP/32 must be matchable (联动 C)")
	}
	// 域名索引锁同时可查（联动 A 第 1 级的数据源）
	if e := m.getSegmentLockByHost("dc-eu.example.com"); e == nil || e.Proxy == "" {
		t.Fatal("host-index segment lock must be queryable (联动 A level-1)")
	}
}
