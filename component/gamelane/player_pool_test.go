package gamelane

import (
	"reflect"
	"testing"
)

// playerPoolFixture 构造一组覆盖港台新日韩美加欧的节点池 + RTT 表，
// 供 buildPlayerPool 各分支验收使用。
func playerPoolFixture() ([]string, map[string]int) {
	all := []string{
		"香港-01", "香港-02", "香港-03", // HK ×3
		"台湾-01", "台湾-02", // TW ×2
		"新加坡-01", "新加坡-02", // SG ×2
		"日本-01", "日本-02", // JP ×2
		"韩国-01",                   // KR ×1
		"美国-01", "美国-02", "美国-03", // US ×3
		"加拿大-01",                                     // CA ×1
		"英国-01", "德国-01", "法国-01", "荷兰-01", "俄罗斯-01", // EU ×5
		"澳大利亚-01",         // AU ×1
		"迪拜-01", "利雅得-01", // ME ×2
		"DIRECT", // 应被剔除
	}
	rtt := map[string]int{
		"香港-01": 30, "香港-02": 25, "香港-03": 40,
		"台湾-01": 50, "台湾-02": 60,
		"新加坡-01": 70, "新加坡-02": 80,
		"日本-01": 90, "日本-02": 100,
		"韩国-01": 110,
		"美国-01": 150, "美国-02": 160, "美国-03": 170,
		"加拿大-01": 180,
		"英国-01":  190, "德国-01": 200, "法国-01": 210,
		"荷兰-01": 220, "俄罗斯-01": 230,
		"澳大利亚-01": 240,
		"迪拜-01":   250, "利雅得-01": 260,
	}
	return all, rtt
}

func poolHasAll(pool []string, tags ...string) bool {
	// 对每个标签，池中至少含一个该地区节点
	for _, tag := range tags {
		found := false
		for _, n := range pool {
			if r, ok := extractRegionTag(n); ok && r == tag {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func poolHasNo(pool []string, names ...string) bool {
	seen := make(map[string]bool, len(pool))
	for _, n := range pool {
		seen[n] = true
	}
	for _, n := range names {
		if seen[n] {
			return false
		}
	}
	return true
}

// 亚洲玩家连北美服务器：港台全量进池（永远在）+ 日新韩代表
// （服务器侧不可信，回退玩家侧逻辑），且不超上限、无 DIRECT。
func TestBuildPlayerPool_AsiaPlayer_ServerNA(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool(serverRegionAsia, serverRegionNA, liveNodes(all, rtt), rtt, false)

	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len = %d, want <= %d", len(pool), maxCandidatePool)
	}
	// 港台全量（3 HK + 2 TW）必须全在
	for _, want := range []string{"香港-01", "香港-02", "香港-03", "台湾-01", "台湾-02"} {
		if !containsStr(pool, want) {
			t.Fatalf("asia player pool missing core node %s: %v", want, pool)
		}
	}
	// 代表区：日新韩 + 服务器侧美加至少各 1
	if !poolHasAll(pool, "SG", "JP", "KR", "US", "CA") {
		t.Fatalf("asia player pool missing rep regions: %v", pool)
	}
	// 无 DIRECT
	if poolHasNo(pool, "DIRECT") {
	} else {
		t.Fatalf("asia player pool contains DIRECT: %v", pool)
	}
}

// 亚洲玩家连亚洲服务器：港台全量 + 日新韩代表，池内不需要美加兜底。
func TestBuildPlayerPool_AsiaPlayer_ServerAsia(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool(serverRegionAsia, serverRegionAsia, liveNodes(all, rtt), rtt, false)

	for _, want := range []string{"香港-01", "香港-02", "香港-03", "台湾-01", "台湾-02"} {
		if !containsStr(pool, want) {
			t.Fatalf("asia server pool missing core node %s: %v", want, pool)
		}
	}
	if !poolHasAll(pool, "SG", "JP", "KR") {
		t.Fatalf("asia server pool missing reps: %v", pool)
	}
}

// 北美玩家：美加全量优先；港台新日韩代表进池。
func TestBuildPlayerPool_NAPlayer(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool(serverRegionNA, serverRegionAsia, liveNodes(all, rtt), rtt, false)

	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len = %d, want <= %d", len(pool), maxCandidatePool)
	}
	// 美加全量（3 US + 1 CA）
	for _, want := range []string{"美国-01", "美国-02", "美国-03", "加拿大-01"} {
		if !containsStr(pool, want) {
			t.Fatalf("na player pool missing core node %s: %v", want, pool)
		}
	}
	// 港台新日韩代表至少各 1
	if !poolHasAll(pool, "HK", "TW", "SG", "JP", "KR") {
		t.Fatalf("na player pool missing asia reps: %v", pool)
	}
}

// 欧洲玩家：英德法荷俄全量优先；港台新日韩 + 美加代表进池。
func TestBuildPlayerPool_EUPlayer(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool(serverRegionEU, serverRegionNA, liveNodes(all, rtt), rtt, false)

	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len = %d, want <= %d", len(pool), maxCandidatePool)
	}
	for _, want := range []string{"英国-01", "德国-01", "法国-01", "荷兰-01", "俄罗斯-01"} {
		if !containsStr(pool, want) {
			t.Fatalf("eu player pool missing core node %s: %v", want, pool)
		}
	}
	if !poolHasAll(pool, "HK", "TW", "SG", "JP", "KR", "US", "CA") {
		t.Fatalf("eu player pool missing reps: %v", pool)
	}
}

// 玩家位置未知：退化为服务器侧引导（港台全量 + 日新韩 + 欧北美兜底），
// 且不超上限。
func TestBuildPlayerPool_UnknownPlayer_FallbackServerSide(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool("", serverRegionAsia, liveNodes(all, rtt), rtt, false)

	// 与 v6.1 buildServerPool 亚洲分支一致
	wantPool := cappedPool(buildServerPool(serverRegionAsia, liveNodes(all, rtt), rtt), nil)
	if !reflect.DeepEqual(pool, wantPool) {
		t.Fatalf("unknown player pool = %v, want server-side %v", pool, wantPool)
	}
	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len = %d, want <= %d", len(pool), maxCandidatePool)
	}
}

// 上限保护：大量同地区节点时池不超 maxCandidatePool（核心截断）。
func TestBuildPlayerPool_CapLimit(t *testing.T) {
	all := []string{
		"香港-01", "香港-02", "香港-03", "香港-04", "香港-05",
		"香港-06", "香港-07", "香港-08", "香港-09", "香港-10",
		"香港-11", "香港-12", "香港-13", // 13 个 HK（超上限）
		"台湾-01", "台湾-02",
		"新加坡-01", "日本-01", "韩国-01",
	}
	rtt := map[string]int{"香港-01": 1}
	pool := buildPlayerPool(serverRegionAsia, serverRegionAsia, liveNodes(all, rtt), rtt, false)
	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len = %d, want <= %d", len(pool), maxCandidatePool)
	}
}

// ========== v6.3: 服务器侧就近优先级（信任区） ==========

// 服务器在 SG（信任区）：新加坡全量进核心，港台兜底。
func TestBuildPlayerPool_ServerSG_Trusted(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool(serverRegionAsia, serverRegionAsia, liveNodes(all, rtt), rtt, true)

	// 新加坡全量必须全在核心（服务器侧就近）
	for _, want := range []string{"新加坡-01", "新加坡-02"} {
		if !containsStr(pool, want) {
			t.Fatalf("server SG pool missing core node %s: %v", want, pool)
		}
	}
	// 港台兜底
	if !poolHasAll(pool, "HK", "TW") {
		t.Fatalf("server SG pool missing fallback HK/TW: %v", pool)
	}
	// 无 DIRECT
	if !poolHasNo(pool, "DIRECT") {
		t.Fatalf("server SG pool contains DIRECT: %v", pool)
	}
	if len(pool) > maxCandidatePool {
		t.Fatalf("pool len = %d, want <= %d", len(pool), maxCandidatePool)
	}
}

// 服务器在 HK（信任区）：香港全量进核心，港台兜底（含自己）。
func TestBuildPlayerPool_ServerHK_Trusted(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool(serverRegionAsia, serverRegionAsia, liveNodes(all, rtt), rtt, true)

	// 香港全量必须全在核心
	for _, want := range []string{"香港-01", "香港-02", "香港-03"} {
		if !containsStr(pool, want) {
			t.Fatalf("server HK pool missing core node %s: %v", want, pool)
		}
	}
	// 台湾兜底
	if !poolHasAll(pool, "TW") {
		t.Fatalf("server HK pool missing fallback TW: %v", pool)
	}
}

// 服务器在 US（非信任区）：回退玩家侧港台就近，不按服务器区选路。
func TestBuildPlayerPool_ServerUS_Untrusted(t *testing.T) {
	all, rtt := playerPoolFixture()
	pool := buildPlayerPool(serverRegionAsia, serverRegionNA, liveNodes(all, rtt), rtt, false)

	// 核心 = 港台全量（不是美国全量）
	for _, want := range []string{"香港-01", "香港-02", "香港-03", "台湾-01", "台湾-02"} {
		if !containsStr(pool, want) {
			t.Fatalf("server US untrusted pool missing core node %s: %v", want, pool)
		}
	}
	// 美国全量不应进核心（不可信任区）
	for _, want := range []string{"美国-01", "美国-02", "美国-03"} {
		if !poolHasNo(pool, want) {
			// US 节点最多出现在代表区，不能占核心位
		}
	}
}

// 信任区判定：亚洲明确区国家码返回 true，其余大区（含大洋洲）返回 false。
func TestIsTrustedServerCountry(t *testing.T) {
	trusted := []string{"HK", "TW", "MO", "SG", "JP", "KR", "TH", "MY", "CN"}
	untrusted := []string{"US", "CA", "GB", "DE", "FR", "NL", "AU", "AE", "SA", "RU", ""}

	for _, c := range trusted {
		if !isTrustedServerCountry(c) {
			t.Errorf("isTrustedServerCountry(%q) = false, want true", c)
		}
	}
	for _, c := range untrusted {
		if isTrustedServerCountry(c) {
			t.Errorf("isTrustedServerCountry(%q) = true, want false", c)
		}
	}
}

// 玩家地区映射：国家代码 → 大区（PlayerRegion 依赖 PlayerCountry）。
func TestPlayerRegion(t *testing.T) {
	cases := []struct {
		country string
		want    string
	}{
		{"CN", serverRegionAsia},
		{"HK", serverRegionAsia},
		{"TW", serverRegionAsia},
		{"JP", serverRegionAsia},
		{"SG", serverRegionAsia},
		{"US", serverRegionNA},
		{"CA", serverRegionNA},
		{"GB", serverRegionEU},
		{"DE", serverRegionEU},
		{"AU", serverRegionOC},
		{"AE", serverRegionME},
		{"", ""},
	}
	for _, c := range cases {
		setPlayerCountryForTest(c.country)
		if got := PlayerRegion(); got != c.want {
			t.Fatalf("PlayerRegion(%q) = %q, want %q", c.country, got, c.want)
		}
	}
}

// 服务器侧补充：服务器在北美/欧洲/中东时返回对应标签，亚洲/未知为空。
func TestServerSideRepTags(t *testing.T) {
	if !reflect.DeepEqual(serverSideRepTags(serverRegionNA), []string{"US", "CA"}) {
		t.Fatalf("serverSideRepTags(NA) = %v", serverSideRepTags(serverRegionNA))
	}
	if !reflect.DeepEqual(serverSideRepTags(serverRegionEU), regionTagsOf(serverRegionEU)) {
		t.Fatalf("serverSideRepTags(EU) = %v", serverSideRepTags(serverRegionEU))
	}
	if serverSideRepTags(serverRegionAsia) != nil {
		t.Fatalf("serverSideRepTags(Asia) = %v, want nil", serverSideRepTags(serverRegionAsia))
	}
}

func containsStr(list []string, s string) bool {
	for _, n := range list {
		if n == s {
			return true
		}
	}
	return false
}
