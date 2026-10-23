package tunnel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/gamelane"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

// ---- 2026-10-18 v2.3：Fake-IP 首包放行 + 抢回权（Q-H1 反转口径）----

func restoreLookup(host string, ok bool) func(netip.Addr) (string, bool) {
	return func(netip.Addr) (string, bool) { return host, ok }
}

// stubEnhancer 测试用 HostMapper：仅 IsFakeIP 按 198.18.0.0/15 判定，
// 使 ①′ 分支在无真实 fake-ip 池的单测环境可触发（生产走 mapper 实际网段）。
type stubEnhancer struct{}

func (stubEnhancer) FakeIPEnabled() bool  { return true }
func (stubEnhancer) MappingEnabled() bool { return true }
func (stubEnhancer) IsFakeIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.Is4() && ip.As4()[0] == 198 && ip.As4()[1] == 18
}
func (stubEnhancer) IsFakeBroadcastIP(netip.Addr) bool { return false }
func (stubEnhancer) IsExistFakeIP(netip.Addr) bool     { return false }
func (stubEnhancer) FindHostByIP(netip.Addr) (string, bool) {
	return "", false // ①′ 走 fakeIPHostLookup 注入，不经此
}
func (stubEnhancer) FlushFakeIP() error                { return nil }
func (stubEnhancer) InsertHostByIP(netip.Addr, string) {}
func (stubEnhancer) StoreFakePoolState()               {}

// 修改②：fake-ip + 游戏域名首包 → onLane=true 进 hi 队列，不注册 Target。
func TestSelectUDPQueue_FakeIPGameDomainFirstPacket(t *testing.T) {
	udpInit.Do(initUDP) // 队列/钩子初始化（生产由 HandleUDPPacket 触发）
	origMapper := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = stubEnhancer{}
	defer func() { resolver.DefaultHostMapper = origMapper }()
	gamelane.Default().SetEnabled(true)
	defer gamelane.Default().SetEnabled(false)
	defer gamelane.Default().SetTargets(nil)
	orig := fakeIPHostLookup
	defer func() { fakeIPHostLookup = orig }()

	md := netMetadata()
	// 正例：反查 host 命中内置云后缀 → hi 队列 + onLane 条目（dst=fake-ip、dport 记录）
	fakeIPHostLookup = restoreLookup("apx.ea.example.amazonaws.com", true)
	got := selectUDPQueue("fk1", md, 0)
	if got != udpQueuesHi[0] {
		t.Fatal("fake-ip game-domain first packet must enter the hi queue")
	}
	e, ok := laneCache.Load("fk1")
	if !ok || !e.onLane || e.snapshotDst() != "198.18.0.45" || e.snapshotDport() != 10200 {
		t.Fatalf("lane entry must be onLane with fake dst and dport recorded, got %+v", e)
	}
	laneCache.Delete("fk1")

	// 反例 1：反查 host 非游戏域名 → 原路径（normal 队列、onLane=false）
	fakeIPHostLookup = restoreLookup("www.example.com", true)
	got = selectUDPQueue("fk2", md, 0)
	if got != udpQueuesNormal[0] {
		t.Fatal("non-game fake-ip domain must take the normal queue")
	}
	if e, ok := laneCache.Load("fk2"); !ok || e.onLane {
		t.Fatal("non-game fake-ip entry must not be onLane")
	}
	laneCache.Delete("fk2")

	// 反例 2：反查失败（cache.db 残留映射池内不存在）→ 原路径
	fakeIPHostLookup = restoreLookup("", false)
	got = selectUDPQueue("fk3", md, 0)
	if got != udpQueuesNormal[0] {
		t.Fatal("failed host lookup must fall back to the normal queue")
	}
	laneCache.Delete("fk3")
}

func netMetadata() *C.Metadata {
	return &C.Metadata{
		DstIP:   netip.MustParseAddr("198.18.0.45"),
		DstPort: 10200,
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 55894,
	}
}

// 修改④（Q-H1 反转口径）四象限：
//
//	27015（对局段）+ recv>=1 → 不抢；10200（动态对局端口，code:house 铁证）+
//	recv>=1 → 不抢（防回归断言！）；7770（无状态测速）+ recv>=1 → 放行；
//	任意端口 + recv==0 → 放行。
func TestRetargetAllowed_GamePortProtection(t *testing.T) {
	setRetargetTestTarget(t, "SG 01")
	defer gamelane.Default().SetTargets(nil)
	now := time.Now().UnixMilli()
	laneCache.Store("g1", retargetTestEntryPort(retargetTestDst, "HK 03", 1, now-1000, 27015))
	laneCache.Store("g2", retargetTestEntryPort(retargetTestDst, "HK 03", 1, now-1000, 10200))
	laneCache.Store("g3", retargetTestEntryPort(retargetTestDst, "HK 03", 1, now-1000, 7770))
	laneCache.Store("g4", retargetTestEntryPort(retargetTestDst, "HK 03", 0, now-1000, 27015))
	defer func() {
		for _, k := range []string{"g1", "g2", "g3", "g4"} {
			laneCache.Delete(k)
		}
	}()
	if n := RetargetUDPFor(retargetTestDst); n != 2 {
		t.Fatalf("only 7770 speedtest and never-bound sessions may be rebuilt, got %d", n)
	}
	for _, k := range []string{"g1", "g2"} {
		if _, ok := laneCache.Load(k); !ok {
			t.Fatalf("handshaked game session %s must survive (27015/10200 绝不抢，10200=code:house 防回归)", k)
		}
	}
	for _, k := range []string{"g3", "g4"} {
		if _, ok := laneCache.Load(k); ok {
			t.Fatalf("session %s (stateless probe / never-bound) must be rebuilt", k)
		}
	}
}

func retargetTestEntryPort(dst, proxy string, recv int, lastRecvAt int64, dport uint16) *laneEntry {
	e := retargetTestEntry(dst, proxy, recv, lastRecvAt)
	e.dport = dport
	return e
}
