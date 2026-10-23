package tunnel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/gamelane"
	C "github.com/metacubex/mihomo/constant"
)

// ---- 2026-10-18 v2.2：Retarget 活跃会话保护（铁律一/二，code:house 根因）----

const retargetTestDst = "216.244.12.165"

func setRetargetTestTarget(t *testing.T, proxy string) {
	t.Helper()
	gamelane.Default().SetTargets([]gamelane.Target{{
		ProcessName: "retarget-test",
		CIDR:        []netip.Prefix{netip.MustParsePrefix(retargetTestDst + "/32")},
		Proxy:       proxy,
	}})
}

func retargetTestEntry(dst, proxy string, recv int, lastRecvAt int64) *laneEntry {
	return &laneEntry{
		onLane:       true,
		dst:          dst,
		activeProxy:  proxy,
		recvCount:    recv,
		lastRecvAt:   lastRecvAt,
		pendingRetry: false,
	}
}

// 场景 1（Apex）：recv>=1（已握手）且 5s 内有回包的活跃会话遇 auto-register
// 新目标 → 不掐断，新目标只影响下一个新建会话。
func TestRetargetUDPFor_ProtectsHandshakedSession(t *testing.T) {
	setRetargetTestTarget(t, "SG 01")
	defer gamelane.Default().SetTargets(nil)
	now := time.Now().UnixMilli()
	laneCache.Store("k1", retargetTestEntry(retargetTestDst, "HK 03", 1, now-1000))
	defer laneCache.Delete("k1")
	if n := RetargetUDPFor(retargetTestDst); n != 0 {
		t.Fatalf("handshaked session must be protected (zero rebuilds), got %d", n)
	}
	if _, ok := laneCache.Load("k1"); !ok {
		t.Fatal("protected session entry must survive")
	}
}

// 场景 2：同节点 retarget（HK 03→HK 03）→ 铁律一短路跳过，会话零重建
// （重建 = 出口新随机源端口 = 已握手五元组绑定失效 = 自杀）。
func TestRetargetUDPFor_ShortCircuitSameProxy(t *testing.T) {
	setRetargetTestTarget(t, "SG 01")
	defer gamelane.Default().SetTargets(nil)
	now := time.Now().UnixMilli()
	laneCache.Store("k2", retargetTestEntry(retargetTestDst, "SG 01", 0, now))
	defer laneCache.Delete("k2")
	if n := RetargetUDPFor(retargetTestDst); n != 0 {
		t.Fatalf("same-proxy session must short-circuit (zero rebuilds), got %d", n)
	}
	if _, ok := laneCache.Load("k2"); !ok {
		t.Fatal("same-proxy session entry must survive")
	}
}

// 场景 3：5s 无回包死链 / 从未握手 → 允许 Retarget 兜底重建。
func TestRetargetUDPFor_AllowsDeadSession(t *testing.T) {
	setRetargetTestTarget(t, "SG 01")
	defer gamelane.Default().SetTargets(nil)
	now := time.Now().UnixMilli()
	laneCache.Store("k3a", retargetTestEntry(retargetTestDst, "HK 03", 1, now-11000)) // 死链（10s 窗口外）
	laneCache.Store("k3b", retargetTestEntry(retargetTestDst, "HK 03", 0, now))      // 从未握手
	defer func() {
		laneCache.Delete("k3a")
		laneCache.Delete("k3b")
	}()
	if n := RetargetUDPFor(retargetTestDst); n != 2 {
		t.Fatalf("dead and never-bound sessions must be rebuilt, got %d", n)
	}
	if _, ok := laneCache.Load("k3a"); ok {
		t.Fatal("dead session (11s no-recv) must be removed")
	}
	if _, ok := laneCache.Load("k3b"); ok {
		t.Fatal("never-bound session (recv=0) must be removed")
	}
}

// 场景 5：全局 RetargetUDP 非空分支同保护。
func TestRetargetUDP_GlobalProtectsActive(t *testing.T) {
	setRetargetTestTarget(t, "SG 01")
	defer gamelane.Default().SetTargets(nil)
	now := time.Now().UnixMilli()
	natTable.GetOrCreate("kg1", func() C.PacketSender { return newPacketSender() })
	natTable.GetOrCreate("kg2", func() C.PacketSender { return newPacketSender() })
	defer func() {
		natTable.Delete("kg1")
		natTable.Delete("kg2")
	}()
	laneCache.Store("kg1", retargetTestEntry(retargetTestDst, "HK 03", 1, now-1000))
	laneCache.Store("kg2", retargetTestEntry(retargetTestDst, "HK 03", 0, now))
	defer func() {
		laneCache.Delete("kg1")
		laneCache.Delete("kg2")
	}()
	RetargetUDP()
	if _, ok := laneCache.Load("kg1"); !ok {
		t.Fatal("handshaked session must survive global retarget")
	}
	if _, ok := laneCache.Load("kg2"); ok {
		t.Fatal("never-bound session must be rebuilt by global retarget")
	}
}

// 一键清空（targets==0）保持无条件全清（用户显式动作，语义不变）。
func TestRetargetUDP_FullClearUnconditional(t *testing.T) {
	gamelane.Default().SetTargets(nil)
	laneCache.Store("kc", retargetTestEntry("1.2.3.4", "HK 03", 1, time.Now().UnixMilli()))
	defer laneCache.Delete("kc")
	RetargetUDP()
	if _, ok := laneCache.Load("kc"); ok {
		t.Fatal("full-clear must wipe all lane sessions unconditionally (user intent)")
	}
}

// 铁律一/二数据基座：activeProxy 写回/读取、recvCount 递增、5s 保护边界。
func TestLaneEntry_HandshakeState(t *testing.T) {
	e := &laneEntry{onLane: true, dst: retargetTestDst}
	e.setActiveProxy("HK 03")
	if got := e.snapshotActiveProxy(); got != "HK 03" {
		t.Fatalf("activeProxy roundtrip, got %q", got)
	}
	base := time.Now().UnixMilli()
	e.markRecv(base)
	e.markRecv(base - 1000) // 旧时间戳不回退，但 recvCount 仍递增
	if e.recvCount != 2 {
		t.Fatalf("recvCount must count every response, got %d", e.recvCount)
	}
	if !e.handshakeProtected(base + 4000) {
		t.Fatal("recv>=1 within 10s must be protected")
	}
	if !e.handshakeProtected(base + 6000) {
		t.Fatal("recv>=1 within 10s must still be protected (v2.7: 6s is not a dead link)")
	}
	if e.handshakeProtected(base + 11000) {
		t.Fatal("11s without recv must NOT be protected (dead link, v2.7 confirm: >10s zero-recv)")
	}
	e2 := &laneEntry{onLane: true, dst: retargetTestDst, lastRecvAt: base}
	if e2.handshakeProtected(base + 100) {
		t.Fatal("recv=0 (never handshaked) must NOT be protected")
	}
}
