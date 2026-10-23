package gamelane

import (
	"net/netip"
	"testing"
)

// 《国内游戏直连指令 2026-10-21》单测（v2.12 清单4 更新，2026-10-22）：
// 判据由 GeoIP(MMDB) 换为内置大陆 IPv4 路由表（chnroutes）后，
// 目标 IP 属大陆路由表且未命中已知游戏段表 → 拒绝接管（直连）；
// 段表命中永不直连；表外（含海外）目标零变化；路由数据不可用时保守接管。
//
// 用例不依赖真实路由数据的具体网段（数据每次更新都会变），统一用
// chinaMainlandFn 注入判定结果（仿 geoipCountryFor 的注入方式）。

// withChinaMainland20261021 注入大陆路由表判定结果，返回时自动恢复。
func withChinaMainland20261021(t *testing.T, china bool) {
	t.Helper()
	old := chinaMainlandFn
	t.Cleanup(func() { chinaMainlandFn = old })
	chinaMainlandFn = func(netip.Addr) bool { return china }
}

// 用例 ①：属大陆路由表且未命中段表 → RegisterTargetIPTrusted 返回 false，
// 目标表不含该 IP（交系统直连）。
func TestDomesticDirect20261021_RegisterRejectsChina(t *testing.T) {
	withChinaMainland20261021(t, true)
	m := newAutoManager(true, nil)

	const ip = "203.0.113.77"
	if m.RegisterTargetIPTrusted(ip, true) {
		t.Fatal("大陆路由表内且未命中段表的目标不应被注册（应直连放行）")
	}
	for _, tg := range m.targets {
		for _, c := range tg.CIDR {
			if c.Addr().String() == ip {
				t.Fatalf("目标表不应包含 %s: %+v", ip, tg.CIDR)
			}
		}
	}
	if len(m.targets) != 0 {
		t.Fatalf("目标表应为空，实际 %d 条", len(m.targets))
	}
}

// 用例 ②：表外（海外）→ 正常注册 true（海外行为零变化）。
func TestDomesticDirect20261021_RegisterAllowsOverseas(t *testing.T) {
	withChinaMainland20261021(t, false)
	m := newAutoManager(true, nil)
	if !m.RegisterTargetIPTrusted("203.0.113.78", true) {
		t.Fatal("海外目标应正常注册")
	}
	if len(m.targets) != 1 {
		t.Fatalf("目标表应为 1 条，实际 %d 条", len(m.targets))
	}
}

// 用例 ③：路由表不可用（构建失败/空表，判定恒 false）→ 保守按原路径接管。
func TestDomesticDirect20261021_RegisterTableUnavailable(t *testing.T) {
	withChinaMainland20261021(t, false)
	m := newAutoManager(true, nil)
	if !m.RegisterTargetIPTrusted("203.0.113.79", true) {
		t.Fatal("路由数据不可用时应保守按原路径注册")
	}
	if len(m.targets) != 1 {
		t.Fatalf("目标表应为 1 条，实际 %d 条", len(m.targets))
	}
}

// 用例 ④：进程目标 + 大陆路由表 → MatchTarget 返回 nil,false（直连）；
// 表外目标仍返回 *Target,true。
func TestDomesticDirect20261021_MatchTargetSkipsChina(t *testing.T) {
	m := newAutoManager(true, []Target{
		{ProcessName: "game.exe", Proxy: "香港-01"},
	})
	m.SetAllProxies([]string{"香港-01"})
	m.SetRTTTable(map[string]int{"香港-01": 10})

	withChinaMainland20261021(t, true)
	if tgt, ok := m.MatchTarget(testMetadata("game.exe", "203.0.113.80"), false); ok || tgt != nil {
		t.Fatalf("大陆路由表目标应视为未命中返回 nil,false，实际 %v %v", tgt, ok)
	}

	withChinaMainland20261021(t, false)
	tgt, ok := m.MatchTarget(testMetadata("game.exe", "203.0.113.81"), false)
	if !ok || tgt == nil {
		t.Fatal("表外目标应正常命中 GameLane")
	}
	if px := tgt.EffectiveProxy(); px != "香港-01" {
		t.Fatalf("表外命中出口应为 香港-01，实际 %q", px)
	}
}

// 用例 ⑤：属大陆路由表但命中已知游戏段（内置 Valve SDR 155.133.224.0/19）
// → 仍正常注册 true（段表命中永不直连，防误伤必测）。
func TestDomesticDirect20261021_SegmentHitStillRegistered(t *testing.T) {
	const ip = "155.133.238.178"
	addr := netip.MustParseAddr(ip)
	if !SegmentTable().MatchIP(addr) {
		t.Fatalf("前置条件失败：%s 应命中已知游戏段表", ip)
	}
	withChinaMainland20261021(t, true)
	m := newAutoManager(true, nil)
	if !m.RegisterTargetIPTrusted(ip, true) {
		t.Fatal("段表命中的游戏服务器永不直连，应正常注册")
	}
	if len(m.targets) != 1 {
		t.Fatalf("目标表应为 1 条，实际 %d 条", len(m.targets))
	}
}

// 用例 ⑥：清单5 反悔记忆 —— 同一大陆 IP 已有 fakecn_override 记录时，
// 直连判定被豁免，按海外服接管（避免重启后又回落直连）。
func TestDomesticDirect20261021_FakeCNOverrideBypasses(t *testing.T) {
	const ip = "203.0.113.82"
	withChinaMainland20261021(t, true)
	restore := withTempFakeCNStore(t)
	defer restore()

	fakeCNOverrideStore.Lock()
	fakeCNOverrideStore.entries[ip] = fakeCNOverrideEntry{IP: ip, Reason: "no_reply", At: fakeCNNow()}
	fakeCNOverrideStore.Unlock()

	m := newAutoManager(true, nil)
	if !m.RegisterTargetIPTrusted(ip, true) {
		t.Fatal("已有 fakecn_override 记忆的目标应被接管（跳过直连判定）")
	}
	if len(m.targets) != 1 {
		t.Fatalf("目标表应为 1 条，实际 %d 条", len(m.targets))
	}
}
