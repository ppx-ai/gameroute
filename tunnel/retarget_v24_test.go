package tunnel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/gamelane"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

// ---- 2026-10-18 v2.4：铁令 C 总闸（selectUDPQueue 顶层）+ 1.2 活跃期秒接管 ----

// 非活跃期：同形态首包不触发秒接管（回归 v2.2 行为）。
func TestSelectUDPQueue_NoFastPathWhenInactive(t *testing.T) {
	udpInit.Do(initUDP)
	gamelane.Default().SetEnabled(true)
	defer gamelane.Default().SetEnabled(false)
	defer gamelane.Default().SetTargets(nil)
	gamelane.Default().SetTargets([]gamelane.Target{}) // 清空，避免既有目标干扰

	md := &C.Metadata{
		DstIP:   netip.MustParseAddr("198.51.100.201"),
		DstPort: 10300,
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 53704,
	}
	got := selectUDPQueue("v24-idle", md, 0)
	if got != udpQueuesNormal[0] {
		t.Fatal("inactive period must keep the legacy behavior (normal queue)")
	}
	laneCache.Delete("v24-idle")
}

// 铁令 C：8125 遥测首包走 normal 队列且不产生 onLane 条目（总闸最顶层）。
func TestSelectUDPQueue_ExcludedPortVeto(t *testing.T) {
	udpInit.Do(initUDP)
	origMapper := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = stubEnhancer{}
	defer func() { resolver.DefaultHostMapper = origMapper }()
	gamelane.Default().SetEnabled(true)
	defer gamelane.Default().SetEnabled(false)
	defer gamelane.Default().SetTargets(nil)
	orig := fakeIPHostLookup
	fakeIPHostLookup = restoreLookup("stats.respawn.com", true)
	defer func() { fakeIPHostLookup = orig }()
	gamelane.Default().MarkGameActive() // 即便活跃期，排除端口仍一票否决

	md := &C.Metadata{
		DstIP:   netip.MustParseAddr("216.244.26.60"),
		DstPort: 8125,
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 50870,
	}
	got := selectUDPQueue("v24-8125", md, 0)
	if got != udpQueuesNormal[0] {
		t.Fatal("excluded port 8125 must take the normal queue (铁令 C 总闸)")
	}
	if e, ok := laneCache.Load("v24-8125"); ok && e.onLane {
		t.Fatal("excluded port session must never be onLane")
	}
	laneCache.Delete("v24-8125")
}

// 1.2：游戏活跃期，陌生公网 1024+ 非排除端口首包 → trusted 注册 + hi 队列
// （T=0ms 秒接管，绝不滑进普通规则默认出站）。
func TestSelectUDPQueue_GameActiveFastPath(t *testing.T) {
	udpInit.Do(initUDP)
	gamelane.Default().SetEnabled(true)
	defer gamelane.Default().SetEnabled(false)
	defer gamelane.Default().SetTargets(nil)
	gamelane.Default().MarkGameActive()

	md := &C.Metadata{
		DstIP:   netip.MustParseAddr("198.51.100.200"), // 陌生 IP（非段表）
		DstPort: 10300,                                 // 非排除端口
		SrcIP:   netip.MustParseAddr("192.168.1.100"),
		SrcPort: 53703,
	}
	got := selectUDPQueue("v24-fast", md, 0)
	if got != udpQueuesHi[0] {
		t.Fatal("game-active fast path must put the first packet on the hi queue")
	}
	e, ok := laneCache.Load("v24-fast")
	if !ok || !e.onLane {
		t.Fatal("fast-path session must be onLane")
	}
	laneCache.Delete("v24-fast")
	// 目标已注册（trusted 直注）
	found := false
	for _, tg := range gamelane.Default().GetTargets() {
		if tg.CIDR[0].String() == "198.51.100.200/32" {
			found = true
		}
	}
	if !found {
		t.Fatal("fast-path must register the target (T=0ms)")
	}
}

var _ = time.Now
