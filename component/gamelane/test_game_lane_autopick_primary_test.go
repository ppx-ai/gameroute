package gamelane

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// === Manager 层：临时主节点选择（进场优先） ===

// v2.13 第二刀（2.2）：全表无任何实测值的冷启动**禁止随机盲选**——
// 返回空串，交由 safeProxy（默认出口/上一出口）与 probeAndSettle
// "先测再进"处理。Fortnite 被随机到 Japan 06（rtt=0）即此路径的代价。
func TestPickPrimaryTemp_NoRTT_NoBlindPick(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01"}
	if got := m.pickPrimaryTemp(netip.Addr{}, all, nil); got != "" {
		t.Fatalf("pickPrimaryTemp 无实测数据必须返回空串（禁盲选），got %q", got)
	}
	if got := m.pickPrimaryTempFull(netip.Addr{}, all, nil, nil); got != "" {
		t.Fatalf("pickPrimaryTempFull 无实测数据必须返回空串（禁盲选），got %q", got)
	}
}

// RTT 表有数据 → 选延迟最低的可用节点进场
func TestPickPrimaryTemp_RTTLowest(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01"}
	rtt := map[string]int{"香港-01": 120, "日本-01": 40, "美国-01": 300}
	if got := m.pickPrimaryTemp(netip.Addr{}, all, rtt); got != "日本-01" {
		t.Fatalf("pickPrimaryTemp want 日本-01 (RTT 40 最低), got %q", got)
	}
	// RTT 表缺失的节点不参与选择
	rtt2 := map[string]int{"香港-01": 10}
	if got := m.pickPrimaryTemp(netip.Addr{}, all, rtt2); got != "香港-01" {
		t.Fatalf("pickPrimaryTemp with partial rtt want 香港-01, got %q", got)
	}
}

// 两者皆无 → 保持 DIRECT 直连（返回空串），不阻塞进场
func TestPickPrimaryTemp_EmptyPool_Direct(t *testing.T) {
	m := newDefaultManager()
	if got := m.pickPrimaryTemp(netip.Addr{}, nil, nil); got != "" {
		t.Fatalf("pickPrimaryTemp empty pool want DIRECT (\"\"), got %q", got)
	}
	if got := m.pickPrimaryTemp(netip.Addr{}, []string{}, map[string]int{"x": 10}); got != "" {
		t.Fatalf("pickPrimaryTemp empty allProxies want DIRECT, got %q", got)
	}
}

// GeoIP 地区初选：有地区标签池且 RTT 有数据 → 取该地区池最低（即使全局最低在别的地区）
func TestPickPrimaryTemp_GeoIP_RegionRTTLowest(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01", "新加坡-01"}
	rtt := map[string]int{"香港-01": 120, "日本-01": 40, "美国-01": 300, "新加坡-01": 90}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "JP" // 目标 IP 注册地日本（亚洲信任区）→ 只从日本节点池初选
	}
	if got := m.pickPrimaryTemp(netip.MustParseAddr("133.18.99.1"), all, rtt); got != "日本-01" {
		t.Fatalf("pickPrimaryTemp geoip want 日本-01 (JP pool rtt-lowest), got %q", got)
	}
}

// GeoIP 地区无节点 → 优先亚洲低延迟池（HK/SG/TW）RTT 最优
func TestPickPrimaryTemp_GeoIP_RegionEmpty_AsiaPreferred(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "新加坡-01"}
	rtt := map[string]int{"香港-01": 120, "日本-01": 40, "新加坡-01": 90}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "KR" // 目标 IP 注册地韩国（亚洲信任区）但无韩国节点 → 亚洲池（HK/SG/TW）RTT 最优
	}
	if got := m.pickPrimaryTemp(netip.MustParseAddr("175.126.1.1"), all, rtt); got != "新加坡-01" {
		t.Fatalf("pickPrimaryTemp geoip empty region want 新加坡-01 (asia low-latency rtt-lowest), got %q", got)
	}
}

// 非信任区（US/AE 等非亚洲）不按 GeoIP 定区 → 落入退避链（全局 RTT 最低）
func TestPickPrimaryTemp_GeoIP_UntrustedRegionFallback(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01", "新加坡-01"}
	rtt := map[string]int{"香港-01": 120, "日本-01": 40, "美国-01": 300, "新加坡-01": 90}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "US" // 目标 IP 注册地美国（非信任区）→ 不作定区依据，直接全局 RTT 最低
	}
	if got := m.pickPrimaryTemp(netip.MustParseAddr("216.244.17.198"), all, rtt); got != "日本-01" {
		t.Fatalf("pickPrimaryTemp geoip untrusted want 日本-01 (global rtt-lowest), got %q", got)
	}
}

// 记忆 PreferredProxy → 最高优先直接使用（无论 GeoIP/RTT）
func TestPickPrimaryTemp_MemoryPreferredWins(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01"}
	rtt := map[string]int{"香港-01": 10, "日本-01": 5, "美国-01": 1}
	m.memMu.Lock()
	m.memories["216.244.17.198/32"] = &GameMemory{
		Key:            "216.244.17.198/32",
		Status:         "active",
		ProcessName:    "apex",
		PreferredProxy: "美国-01",
		LastHitAt:      time.Now().UnixMilli(),
	}
	m.memMu.Unlock()
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "US"
	}
	if got := m.pickPrimaryTemp(netip.MustParseAddr("216.244.17.198"), all, rtt); got != "美国-01" {
		t.Fatalf("pickPrimaryTemp memory preferred want 美国-01, got %q", got)
	}
}

// v2.13：默认出口兜底上移到 safeProxy（选主返回空串后仍绝不直连）
func TestPickPrimaryTemp_NoRTT_DefaultViaSafeProxy(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01"}
	m.SetDefaultProxy("美国-01")
	if got := m.pickPrimaryTemp(netip.Addr{}, all, nil); got != "" {
		t.Fatalf("pickPrimaryTemp want \"\" (禁盲选), got %q", got)
	}
	if got := m.safeProxy(""); got != "美国-01" {
		t.Fatalf("safeProxy want default 美国-01, got %q", got)
	}
}

// v2.13：上一出口兜底同样上移到 safeProxy
func TestPickPrimaryTemp_NoRTT_LastViaSafeProxy(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01"}
	m.SetTargets([]Target{{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")}, Proxy: "auto"}})
	if got := m.pickPrimaryTemp(netip.MustParseAddr("1.2.3.4"), all, nil); got != "" {
		t.Fatalf("pickPrimaryTemp want \"\" (禁盲选), got %q", got)
	}
	m.rememberProxy("香港-01")
	if got := m.safeProxy(""); got != "香港-01" {
		t.Fatalf("safeProxy want last 香港-01, got %q", got)
	}
}

// 有 RTT 数据 → 全局 RTT 最低优先于默认出口（rtt-lowest 退避）
func TestPickPrimaryTemp_RTT_BeforeDefault(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01"}
	rtt := map[string]int{"香港-01": 120, "日本-01": 40, "美国-01": 300}
	m.SetDefaultProxy("美国-01")
	if got := m.pickPrimaryTemp(netip.Addr{}, all, rtt); got != "日本-01" {
		t.Fatalf("pickPrimaryTemp want rtt-lowest 日本-01 before default, got %q", got)
	}
}

// v2.13：原随机兜底改为"实测最低"，无实测节点绝不产出
func TestPickPrimaryTemp_MeasuredLowestOnly(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "美国-01", "新加坡-01"}
	rtt := map[string]int{"香港-01": 120, "新加坡-01": 90} // 日本/美国无 RTT → 不参与
	for i := 0; i < 20; i++ {
		if got := m.pickPrimaryTemp(netip.Addr{}, all, rtt); got != "新加坡-01" {
			t.Fatalf("want measured lowest 新加坡-01, got %q", got)
		}
	}
}

// GeoIP 地区无节点（pool=0）→ 亚洲池优先；亚洲池为空 → 完整退避链
func TestPickPrimaryTemp_GeoIP_EmptyPool_AsiaThenFallbackChain(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "日本-01", "新加坡-01"}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "KR" // 目标注册地韩国（亚洲信任区），无对应节点池 → 亚洲池兜底
	}
	m.SetTargets([]Target{{CIDR: []netip.Prefix{netip.MustParsePrefix("185.10.10.10/32")}, Proxy: "auto"}})

	// 1) 亚洲池有 RTT → 亚洲池 RTT 最低优先于 default/last
	m.lastProxyByTargetMu.Lock()
	m.lastProxyByTarget["185.10.10.10/32"] = "日本-01"
	m.lastProxyByTargetMu.Unlock()
	m.SetDefaultProxy("新加坡-01")
	if got := m.pickPrimaryTemp(netip.MustParseAddr("185.10.10.10"), all, map[string]int{"香港-01": 120, "日本-01": 40, "新加坡-01": 300}); got != "香港-01" {
		t.Fatalf("chain want asia rtt-lowest 香港-01 before default/last, got %q", got)
	}

	// 2) v2.13：亚洲池无 RTT 数据 → 禁盲选，返回空串（不得选任何 rtt=0 节点）
	if got := m.pickPrimaryTemp(netip.MustParseAddr("185.10.10.10"), all, nil); got != "" {
		t.Fatalf("asia pool no-rtt must return \"\" (禁盲选), got %q", got)
	}

	// 3) 亚洲池为空 + 全表无实测值 → 选主返回空串，兜底交给 safeProxy（last）
	// （新实例避免残留 default；池不含韩国节点，否则会被 KR 信任区分支选中）
	m2 := newDefaultManager()
	m2.SetTargets([]Target{{CIDR: []netip.Prefix{netip.MustParsePrefix("185.10.10.10/32")}, Proxy: "auto"}})
	m2.lastProxyByTargetMu.Lock()
	m2.lastProxyByTarget["185.10.10.10/32"] = "日本-01"
	m2.lastProxyByTargetMu.Unlock()
	allNoAsia := []string{"日本-01", "美国-01"}
	if got := m2.pickPrimaryTemp(netip.MustParseAddr("185.10.10.10"), allNoAsia, nil); got != "" {
		t.Fatalf("chain no-measured want \"\" (禁盲选), got %q", got)
	}
	m2.rememberProxy("日本-01")
	if got := m2.safeProxy(""); got != "日本-01" {
		t.Fatalf("safeProxy want last 日本-01, got %q", got)
	}

	// 4) safeProxy：默认出口优先于上一出口
	m2.SetDefaultProxy("韩国-01")
	if got := m2.safeProxy(""); got != "韩国-01" {
		t.Fatalf("safeProxy want default 韩国-01 before last, got %q", got)
	}

	// 5) 亚洲池为空 + 有 RTT 数据 → 全局实测最低（不看默认出口）
	m2.SetRTTTable(map[string]int{"日本-01": 40, "韩国-01": 200, "美国-01": 300})
	if got := m2.pickPrimaryTemp(netip.MustParseAddr("185.10.10.10"), allNoAsia, map[string]int{"日本-01": 40, "韩国-01": 200, "美国-01": 300}); got != "日本-01" {
		t.Fatalf("chain want rtt-lowest 日本-01, got %q", got)
	}
}

// 上一出口持久化：rememberTargetProxy 写入后可从 lookupTargetLastProxy 反查
func TestManager_LastProxyByTarget_PersistRoundtrip(t *testing.T) {
	m := newDefaultManager()
	m.SetTargets([]Target{{CIDR: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")}, Proxy: "auto"}})
	m.rememberTargetProxy("1.2.3.4/32", "香港-01")
	if got := m.lookupTargetLastProxy(netip.MustParseAddr("1.2.3.4")); got != "香港-01" {
		t.Fatalf("lookupTargetLastProxy want 香港-01, got %q", got)
	}
	// 未命中目标 → 无 key 返回空
	if got := m.lookupTargetLastProxy(netip.MustParseAddr("5.6.7.8")); got != "" {
		t.Fatalf("lookupTargetLastProxy unknown target want \"\", got %q", got)
	}
	// DIRECT 不入库
	m.rememberTargetProxy("1.2.3.4/32", "DIRECT")
	if got := m.lookupTargetLastProxy(netip.MustParseAddr("1.2.3.4")); got != "香港-01" {
		t.Fatalf("DIRECT must not overwrite last proxy, got %q", got)
	}
}

// autoPrimary：Proxy 为空 → 首次命中立即选临时主节点进场，候选池自动生成
func TestMatchTarget_AutoPrimary_TempPrimarySelected(t *testing.T) {
	m := newAutoManager(true, []Target{{ProcessName: "game.exe", Proxy: ""}})
	m.SetAllProxies([]string{"香港-01", "日本-01", "美国-01"})
	m.SetRTTTable(map[string]int{"香港-01": 120, "日本-01": 40, "美国-01": 300})

	tgt, ok := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok {
		t.Fatal("MatchTarget must hit")
	}
	if !tgt.IsAutoPrimary() {
		t.Fatal("autoPrimary must be marked for empty proxy")
	}
	if tgt.EffectiveProxy() != "日本-01" {
		t.Fatalf("temporary primary want 日本-01 (lowest RTT), got %q", tgt.EffectiveProxy())
	}
	if len(tgt.Fallbacks) == 0 {
		t.Fatal("auto primary pool must not be empty")
	}
	// Match 返回实际临时主节点名（供进场）
	proxy, ok := m.Match(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok || proxy != "日本-01" {
		t.Fatalf("Match want (日本-01,true), got (%q,%v)", proxy, ok)
	}
}

// autoPrimary："auto" 关键字同样触发自动主节点
func TestMatchTarget_AutoPrimary_AutoKeyword(t *testing.T) {
	m := newAutoManager(true, []Target{{ProcessName: "game.exe", Proxy: "auto"}})
	m.SetAllProxies([]string{"香港-01", "日本-01"})
	m.SetRTTTable(map[string]int{"香港-01": 10, "日本-01": 5})
	tgt, ok := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok || !tgt.IsAutoPrimary() {
		t.Fatal("auto keyword must trigger autoPrimary")
	}
	if tgt.EffectiveProxy() != "日本-01" {
		t.Fatalf("want 日本-01, got %q", tgt.EffectiveProxy())
	}
}

// 显式配置优先：Proxy 非空非 auto → autoPrimary 不生效，配置主节点不被覆盖
func TestMatchTarget_AutoPrimary_ExplicitProxyWins(t *testing.T) {
	m := newAutoManager(true, []Target{{ProcessName: "game.exe", Proxy: "香港-01"}})
	m.SetAllProxies([]string{"香港-01", "日本-01"})
	m.SetRTTTable(map[string]int{"香港-01": 300, "日本-01": 5})
	tgt, ok := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok {
		t.Fatal("MatchTarget must hit")
	}
	if tgt.IsAutoPrimary() {
		t.Fatal("explicit proxy must not enable autoPrimary")
	}
	if tgt.EffectiveProxy() != "香港-01" {
		t.Fatalf("explicit proxy must win, got %q", tgt.EffectiveProxy())
	}
	proxy, ok := m.Match(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok || proxy != "香港-01" {
		t.Fatalf("Match want (香港-01,true), got (%q,%v)", proxy, ok)
	}
}

// 空池安全降级：无可用节点 → DIRECT 直连（EffectiveProxy 空串），不崩
func TestMatchTarget_AutoPrimary_EmptyPoolSafeDegrade(t *testing.T) {
	m := newAutoManager(true, []Target{{ProcessName: "game.exe", Proxy: ""}})
	m.SetAllProxies(nil)
	tgt, ok := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	if !ok || tgt == nil {
		t.Fatal("MatchTarget must hit even with empty pool")
	}
	if !tgt.IsAutoPrimary() {
		t.Fatal("autoPrimary must be marked")
	}
	if tgt.EffectiveProxy() != "" {
		t.Fatalf("empty pool want DIRECT (\"\"), got %q", tgt.EffectiveProxy())
	}
	if len(tgt.Fallbacks) != 0 {
		t.Fatalf("empty pool want no fallbacks, got %v", tgt.Fallbacks)
	}
}

// 候选池：autoPrimary 模式地区无法判定（geoip 注入为空）→ v6.1 全球代表
// 分支（2026-10-17 需求 A 五区锁死后：美/俄节点在池加载层即被滤除，
// 代表池只含五区节点；断言相应收敛为五区语义）。
func TestMatchTarget_AutoPrimary_PoolAsiaPreferred(t *testing.T) {
	m := newAutoManager(true, []Target{{ProcessName: "game.exe", Proxy: ""}})
	m.SetAllProxies([]string{"香港-01", "台湾-01", "日本-01", "美国-01", "新加坡-01", "韩国-01", "俄罗斯-01"})
	m.SetRTTTable(map[string]int{
		"香港-01": 120, "台湾-01": 150, "日本-01": 40, "美国-01": 300,
		"新加坡-01": 90, "韩国-01": 200,
		// 俄罗斯-01 无 RTT → 不作为代表（且已被五区过滤）
	})
	tgt, _ := m.MatchTarget(testMetadata("game.exe", "1.2.3.4"), false)
	laneNodes := map[string]bool{"香港-01": true, "台湾-01": true, "日本-01": true, "新加坡-01": true, "韩国-01": true}
	if len(tgt.Fallbacks) < 5 || len(tgt.Fallbacks) > maxCandidatePool {
		t.Fatalf("pool len want >=5 (five-region reps) <=%d, got %d -> %v", maxCandidatePool, len(tgt.Fallbacks), tgt.Fallbacks)
	}
	seen := map[string]bool{}
	for _, n := range tgt.Fallbacks {
		if !laneNodes[n] {
			t.Fatalf("pool must only contain five-region nodes, got %v (pool=%v)", n, tgt.Fallbacks)
		}
		seen[n] = true
	}
	for n := range laneNodes {
		if !seen[n] {
			t.Fatalf("every five-region node must have at least one representative, missing %s (pool=%v)", n, tgt.Fallbacks)
		}
	}
	if tgt.Fallbacks[0] != "香港-01" {
		t.Fatalf("HK (港台全量靠前) must lead the pool, got %v", tgt.Fallbacks)
	}
}

// === SessionConn 层：进场后自动探测（mirrorProbe 候选评分） ===

// autoPick：临时主节点 A，候选探测后 B 更优 → 自动切到 B，更新当前主节点
func TestSessionConn_AutoPick_SwitchToBetter(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	var mu sync.Mutex
	var switchedTo string
	var toFallbackCalls int
	var sc *SessionConn
	sc = NewSessionConn(pcP, "kap", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls++
			switchedTo = sc.SelectedFallback()
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证探测完成后的自动切换
	sc.SetAutoPick(true)
	sc.SetCurrentPrimary("临时A")
	sc.SetFallbacks([]string{"临时A", "最优B"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		switch name {
		case "临时A":
			return newCandidateFakeConn(150*time.Millisecond, 0), nil
		case "最优B":
			return newCandidateFakeConn(20*time.Millisecond, 0), nil
		}
		return nil, net.ErrClosed
	})

	// 首次上行触发自动探测
	if _, err := sc.WriteTo([]byte("up"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// 等待候选探测完成（期间持续喂上行包提供镜像样本）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sc.candMu.Lock()
		done := sc.candProbe == nil
		sc.candMu.Unlock()
		if done {
			break
		}
		_, _ = sc.WriteTo([]byte("up"), peer.LocalAddr())
		time.Sleep(20 * time.Millisecond)
	}
	sc.candMu.Lock()
	done := sc.candProbe == nil
	sc.candMu.Unlock()
	if !done {
		t.Fatal("auto pick probe must finish")
	}
	if got := sc.SelectedFallback(); got != "最优B" {
		t.Fatalf("want selected 最优B, got %q", got)
	}
	mu.Lock()
	st, tf := switchedTo, toFallbackCalls
	mu.Unlock()
	if st != "最优B" || tf != 1 {
		t.Fatalf("want switch to 最优B once, got (%q,%d)", st, tf)
	}
	if got := sc.CurrentPrimary(); got != "最优B" {
		t.Fatalf("current primary want 最优B after auto switch, got %q", got)
	}
}

// autoPick：临时主节点 A 即候选最优 → 探测完成不切换
func TestSessionConn_AutoPick_NoSwitchWhenBestIsCurrent(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	var toFallbackCalls int
	sc := NewSessionConn(pcP, "kap1", false, cfg, func(toPrimary bool) error {
		if !toPrimary {
			toFallbackCalls++
		}
		return nil
	})
	defer sc.Close()
	sc.SetAutoPick(true)
	sc.SetCurrentPrimary("临时A")
	sc.SetFallbacks([]string{"临时A", "劣化C"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		switch name {
		case "临时A":
			return newCandidateFakeConn(20*time.Millisecond, 0), nil
		case "劣化C":
			return newCandidateFakeConn(200*time.Millisecond, 3), nil // 高延迟 + 丢包
		}
		return nil, net.ErrClosed
	})

	if _, err := sc.WriteTo([]byte("up"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sc.candMu.Lock()
		done := sc.candProbe == nil
		sc.candMu.Unlock()
		if done {
			break
		}
		_, _ = sc.WriteTo([]byte("up"), peer.LocalAddr())
		time.Sleep(20 * time.Millisecond)
	}
	if toFallbackCalls != 0 {
		t.Fatalf("must not switch when current primary is best, calls=%d", toFallbackCalls)
	}
	if got := sc.CurrentPrimary(); got != "临时A" {
		t.Fatalf("current primary must stay 临时A, got %q", got)
	}
}

// v2.8 第一刀回归：非 autoPick 模式同样受会话活跃门卫约束——只要
// 10s 内有回包（连接存活）就严禁 degraded 切换/rebuild session（APEX
// 20Hz 回包下 recv/sent 比例低是健康帧率比，不是丢包）；唯一允许切换
// 条件 = 连续 10s recvDelta==0（真死链，如 2026-10-19 17:23:14
// sent=2001 recv=0 彻底断流）。
func TestSessionConn_AutoPick_DisabledKeepsOldSwitch(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 200 * time.Millisecond // 窗口缩短以触发结算与劣化切换
	var mu sync.Mutex
	var toFallbackCalls int
	sc := NewSessionConn(pcP, "kold", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls++
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证会话活跃门卫
	// 不调用 SetAutoPick：保持非 autoPick 模式
	sc.SetFallbacks([]string{"A", "B"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		if name == "A" {
			return newCandidateFakeConn(150*time.Millisecond, 0), nil
		}
		if name == "B" {
			return newCandidateFakeConn(20*time.Millisecond, 0), nil
		}
		return nil, net.ErrClosed
	})

	// 阶段一：坏窗口但仍有 80% 回包 → 连接存活，必须零切换
	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 80)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	tf := toFallbackCalls
	mu.Unlock()
	if tf != 0 {
		t.Fatalf("session alive (recv within 10s) must block degraded switch, got %d", tf)
	}

	// 阶段二：模拟真死链（连续 10s recvDelta==0）后才放行切换。
	// 独立新会话避免阶段一 predictor 已置 fallback 模式的干扰。
	var toFallbackCalls2 int
	sc2 := NewSessionConn(newFakePacketConn(t, "primary2"), "kold2", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls2++
		}
		mu.Unlock()
		return nil
	})
	defer sc2.Close()
	sc2.protectedSince.Store(0) // 绕过初始保护期
	sc2.lastRecvAt.Store(0)     // 无任何回包 = 真死链
	sc2.SetFallbacks([]string{"A", "B"})
	sc2.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		if name == "A" {
			return newCandidateFakeConn(150*time.Millisecond, 0), nil
		}
		if name == "B" {
			return newCandidateFakeConn(20*time.Millisecond, 0), nil
		}
		return nil, net.ErrClosed
	})
	for i := 0; i < 15 && sc2.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc2, peer, 100, 0) // 全上行无回包
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sc2.candMu.Lock()
		done := sc2.candProbe == nil
		sc2.candMu.Unlock()
		if done {
			break
		}
		fillSessionWindow(t, sc2, peer, 40, 0)
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	tf2 := toFallbackCalls2
	mu.Unlock()
	if tf2 != 1 {
		t.Fatalf("dead link (recvDelta==0) want 1 switch, got %d", tf2)
	}
}

// === v6.1 候选池重构验收 ===

// 亚洲服务器：香港全部 + 台湾全部全量进池（核心不裁剪），
// 代表按"每地各 1 优先、富余补第 2 个"填充（日新韩各 1 + 欧/北美代表）
func TestBuildServerPool_Asia_HKTwFull(t *testing.T) {
	live := []string{
		"香港-01", "香港-02", "香港-03", "香港-04", "香港-05",
		"香港-06", "香港-07", "香港-08",
		"台湾-01", "台湾-02",
		"新加坡-01", "新加坡-02", "日本-01", "日本-02", "韩国-01", "韩国-02",
		"英国-01", "德国-01", "美国-01", "美国-02",
	}
	rtt := map[string]int{
		"香港-01": 40, "香港-02": 41, "香港-03": 42, "香港-04": 43,
		"香港-05": 44, "香港-06": 45, "香港-07": 46, "香港-08": 47,
		"台湾-01": 50, "台湾-02": 51,
		"新加坡-01": 60, "新加坡-02": 61, "日本-01": 62, "日本-02": 63,
		"韩国-01": 64, "韩国-02": 65,
		"英国-01": 200, "德国-01": 201, "美国-01": 202, "美国-02": 203,
	}
	pool := buildServerPool(serverRegionAsia, live, rtt)
	// 香港全部 8 个在最前（全量进池，不裁剪）
	for i, n := range []string{"香港-01", "香港-02", "香港-03", "香港-04", "香港-05", "香港-06", "香港-07", "香港-08"} {
		if pool[i] != n {
			t.Fatalf("asia pool[%d] want %s, got %s (pool=%v)", i, n, pool[i], pool)
		}
	}
	// 台湾全量紧随其后
	if pool[8] != "台湾-01" || pool[9] != "台湾-02" {
		t.Fatalf("asia pool TW want 台湾-01,台湾-02, got %v", pool[8:10])
	}
	// 池上限 12
	if len(pool) > maxCandidatePool {
		t.Fatalf("asia pool len want <= %d, got %d (%v)", maxCandidatePool, len(pool), pool)
	}
	// 代表：日新韩各 1 优先（room=2：新加坡、日本第 2 个按序补上）
	rest := pool[10:]
	contains := func(names []string, target string) bool {
		for _, n := range names {
			if n == target {
				return true
			}
		}
		return false
	}
	for _, n := range []string{"新加坡-01", "日本-01"} {
		if !contains(rest, n) {
			t.Fatalf("asia pool want %s in reps, got %v", n, rest)
		}
	}
	if len(pool) != 12 {
		t.Fatalf("asia pool len want 12, got %d (%v)", len(pool), pool)
	}
}

// 端到端：APEX 亚洲服（89.222.117.194 → geoip HK）候选池港台全量
// （香港 01-08 全部保留）+ 日新韩代表，池内无 DIRECT、无枯竭（≥5）
func TestAutoPickPrimaryPool_Asia_HKTwFull_Capped(t *testing.T) {
	m := newDefaultManager()
	all := []string{
		"香港-01", "香港-02", "香港-03", "香港-04", "香港-05",
		"香港-06", "香港-07", "香港-08",
		"台湾-01",
		"新加坡-01", "新加坡-02", "日本-01", "日本-02", "韩国-01", "韩国-02",
		"英国-01", "德国-01", "美国-01", "美国-02", "DIRECT",
	}
	rtt := map[string]int{
		"香港-01": 40, "香港-02": 41, "香港-03": 42, "香港-04": 43,
		"香港-05": 44, "香港-06": 45, "香港-07": 46, "香港-08": 47,
		"台湾-01":  50,
		"新加坡-01": 60, "新加坡-02": 61, "日本-01": 62, "日本-02": 63,
		"韩国-01": 64, "韩国-02": 65,
		"英国-01": 200, "德国-01": 201, "美国-01": 202, "美国-02": 203,
		// DIRECT 无 RTT → 不进候选
	}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "HK" // 训练场 APEX 亚洲服 → 亚洲分支
	}
	pool := m.autoPickPrimaryPool(netip.MustParseAddr("89.222.117.194"), all, rtt)
	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len want <= %d, got %d (%v)", maxCandidatePool, len(pool), pool)
	}
	if len(pool) < minCandidatePool {
		t.Fatalf("pool len want >= %d, got %d (%v)", minCandidatePool, len(pool), pool)
	}
	// 香港 01-08 全部保留（全量核心不裁剪）
	for i, n := range []string{"香港-01", "香港-02", "香港-03", "香港-04", "香港-05", "香港-06", "香港-07", "香港-08"} {
		if pool[i] != n {
			t.Fatalf("pool[%d] want %s, got %s (pool=%v)", i, n, pool[i], pool)
		}
	}
	// 台湾兜底在核心内（pool[8]）；新加坡/日本代表进池（韩国 RTT 最慢，cap 12 截断后不保证）
	seen := map[string]bool{}
	for _, n := range pool[8:] {
		seen[n] = true
	}
	for _, tag := range []string{"台湾", "新加坡", "日本"} {
		found := false
		for n := range seen {
			if containsPrefix(n, tag) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("pool want %s representative, got %v", tag, pool)
		}
	}
	// 池内无 DIRECT
	for _, n := range pool {
		if n == "DIRECT" {
			t.Fatalf("pool must not contain DIRECT, got %v", pool)
		}
	}
}

// 北美服务器：本地区（美加）全量优先 + 邻近（欧洲/大洋洲）+ 亚洲代表
func TestBuildServerPool_NA_RegionFirst(t *testing.T) {
	live := []string{
		"美国-01", "美国-02", "加拿大-01",
		"英国-01", "德国-01", "澳大利亚-01",
		"香港-01", "新加坡-01", "日本-01", "韩国-01",
	}
	rtt := map[string]int{
		"美国-01": 50, "美国-02": 55, "加拿大-01": 60,
		"英国-01": 150, "德国-01": 155, "澳大利亚-01": 160,
		"香港-01": 200, "新加坡-01": 210, "日本-01": 220, "韩国-01": 230,
	}
	pool := buildServerPool(serverRegionNA, live, rtt)
	if len(pool) < 3 {
		t.Fatalf("NA pool want >= 3 (region full), got %v", pool)
	}
	for i, n := range []string{"美国-01", "美国-02", "加拿大-01"} {
		if pool[i] != n {
			t.Fatalf("NA pool[%d] want %s, got %s (pool=%v)", i, n, pool[i], pool)
		}
	}
	if len(pool) > maxCandidatePool {
		t.Fatalf("NA pool len want <= %d, got %d (%v)", maxCandidatePool, len(pool), pool)
	}
}

// 地区无法判定：港台全量 + 全球主要地区代表，探测裁决
func TestBuildServerPool_Unknown_GlobalReps(t *testing.T) {
	live := []string{
		"香港-01", "香港-02", "台湾-01",
		"新加坡-01", "日本-01", "韩国-01", "英国-01", "德国-01",
		"法国-01", "美国-01", "加拿大-01", "澳大利亚-01", "阿联酋-01",
		"沙特-01",
	}
	rtt := map[string]int{
		"香港-01": 40, "香港-02": 45, "台湾-01": 50,
		"新加坡-01": 60, "日本-01": 62, "韩国-01": 64, "英国-01": 180,
		"德国-01": 185, "法国-01": 190, "美国-01": 200, "加拿大-01": 210,
		"澳大利亚-01": 220, "阿联酋-01": 230, "沙特-01": 240,
	}
	pool := buildServerPool("", live, rtt)
	if len(pool) > maxCandidatePool {
		t.Fatalf("unknown pool len want <= %d, got %d (%v)", maxCandidatePool, len(pool), pool)
	}
	if len(pool) < minCandidatePool {
		t.Fatalf("unknown pool len want >= %d, got %d (%v)", minCandidatePool, len(pool), pool)
	}
	if pool[0] != "香港-01" || pool[1] != "香港-02" || pool[2] != "台湾-01" {
		t.Fatalf("unknown pool HK/TW full want first, got %v", pool[:3])
	}
}

// 池枯竭保护：无地区标签/无代表时从全局活节点补足到 minCandidatePool
func TestAutoPickPrimaryPool_EnsureMin_FillsTo5(t *testing.T) {
	m := newDefaultManager()
	all := []string{"节点-A", "节点-B", "节点-C", "节点-D", "节点-E", "节点-F"}
	rtt := map[string]int{"节点-A": 10, "节点-B": 20, "节点-C": 30, "节点-D": 40, "节点-E": 50, "节点-F": 60}
	// geoip 注入为空 → 无法判定分支：无港台、无代表标签 → 全局活节点补足
	pool := m.autoPickPrimaryPool(netip.Addr{}, all, rtt)
	if len(pool) < minCandidatePool {
		t.Fatalf("pool len want >= %d, got %d (%v)", minCandidatePool, len(pool), pool)
	}
	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len want <= %d, got %d", maxCandidatePool, len(pool))
	}
}

// v6.11 服务器侧优先：服务器 GeoIP 判 DE 时优先德国节点，
// 不再因玩家在 CN（亚洲）先选港台——玩家侧仅在服务器区未知/不可信时兜底。
func TestPickPrimaryTemp_ServerDE_PrefersServer_OverPlayerHKTw(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "香港-02", "台湾-01", "德国-01", "美国-01"}
	rtt := map[string]int{"香港-01": 60, "香港-02": 55, "台湾-01": 58, "德国-01": 30, "美国-01": 200}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "DE" // 服务器 GeoIP 判德国
	}
	setPlayerCountryForTest("CN")
	defer setPlayerCountryForTest("")
	if got := m.pickPrimaryTemp(netip.MustParseAddr("216.244.19.233"), all, rtt); got != "德国-01" {
		t.Fatalf("player CN + server DE want 德国-01 (server-side geoip rtt-lowest), got %q", got)
	}
}

// v6.5 玩家侧就近不误伤非亚洲玩家：玩家在 US → 服务器 GeoIP 地区补充
func TestPickPrimaryTemp_PlayerSideNotAsia_FallsToServerGeoIP(t *testing.T) {
	m := newDefaultManager()
	all := []string{"香港-01", "德国-01", "美国-01"}
	rtt := map[string]int{"香港-01": 60, "德国-01": 30, "美国-01": 200}
	old := geoipCountryFor
	defer func() { geoipCountryFor = old }()
	geoipCountryFor = func(ip netip.Addr) string {
		return "DE"
	}
	setPlayerCountryForTest("US")
	defer setPlayerCountryForTest("")
	if got := m.pickPrimaryTemp(netip.MustParseAddr("216.244.19.233"), all, rtt); got != "德国-01" {
		t.Fatalf("player US + server DE want 德国-01 (geoip fallback), got %q", got)
	}
}

func containsPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}
