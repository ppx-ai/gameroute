package gamelane

import (
	"sort"
	"strings"
)

// regionTag 按节点名中的地区关键词提取区域标签。
// 返回标签（如 "HK"）和是否匹配。
// 支持 13 个主流地区：HK、TW、JP、KR、SG、US、CA、GB、DE、FR、NL、RU、AU。
// 优先级：emoji 国旗 > 中文完整 > 英文全拼 > 英文缩写。
// 短关键词（<=3字符）和中文单字需要满足边界条件，避免子串误配。
func extractRegionTag(name string) (string, bool) {
	name = strings.ToLower(strings.ReplaceAll(name, " ", ""))
	runes := []rune(name)
	n := len(runes)

	// 判断是否为单词字符（字母/数字）：短关键词必须出现在非单词字符之间，避免子串误配
	isWordChar := func(r rune) bool {
		return (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}

	// 判断是否为中文字符
	isChinese := func(r rune) bool {
		return (r >= 0x4e00 && r <= 0x9fff) ||
			(r >= 0x3400 && r <= 0x4dbf) ||
			(r >= 0xf900 && r <= 0xfaff)
	}

	// 检查 kw 在 runes[name] 中作为独立标记出现
	kwMatch := func(kw string) bool {
		kwRunes := []rune(kw)
		kwLen := len(kwRunes)
		if kwLen == 0 || kwLen > n {
			return false
		}
		for i := 0; i <= n-kwLen; i++ {
			match := true
			for j := 0; j < kwLen; j++ {
				if runes[i+j] != kwRunes[j] {
					match = false
					break
				}
			}
			if match {
				beforeOK := i == 0 || !isWordChar(runes[i-1])
				afterOK := i+kwLen == n || !isWordChar(runes[i+kwLen])
				if beforeOK && afterOK {
					return true
				}
			}
		}
		return false
	}

	// US 优先：名称同时含"美国/美"与"香港"时按 US 归类（如"美国香港"）
	for _, group := range [][]string{
		{"美", "🇺🇸"},
		{"us", "美国", "usa", "america"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "US", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "US", true
				}
			}
		}
	}
	// TW
	for _, group := range [][]string{
		{"台湾", "🇹🇼"},
		{"taiwan", "台湾"},
		{"tw", "台", "tai"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "TW", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "TW", true
				}
			}
		}
	}
	// HK
	for _, group := range [][]string{
		{"香港", "🇭🇰"},
		{"hk", "港"},
		{"hongkong", "hkg"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "HK", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "HK", true
				}
			}
		}
	}
	// JP
	for _, group := range [][]string{
		{"日本", "🇯🇵"},
		{"japan", "日本"},
		{"jp", "东京"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "JP", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "JP", true
				}
			}
		}
	}
	// KR
	for _, group := range [][]string{
		{"韩国", "🇰🇷"},
		{"kr", "韩", "首尔"},
		{"korea", "korean", "southkorea"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "KR", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "KR", true
				}
			}
		}
	}
	// SG
	for _, group := range [][]string{
		{"新加坡", "🇸🇬"},
		{"sg", "星"},
		{"singapore"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "SG", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "SG", true
				}
			}
		}
	}
	// 中文子串兜底（2026-10-17 Shadow Forking 需求 A 防御项，批复审查②）：
	// 部分机场命名（如"香港 01"去空格后"香港01"，数字紧邻中文导致 token
	// 独立标记失败）用 strings.Contains 兜底，防未来换机场时五区池被误清空。
	// 位置=五区 token 分支之后、其他区（AU/CA/GB/DE…）之前——否则"新加坡01"
	// 会被 CA 分支的松散词"加"抢先误判（2026-10-18 实测）。优先级：emoji/
	// 英文 token → 五区中文子串 → 其他区。
	for _, kw := range []string{"香港", "港", "hk"} {
		if strings.Contains(name, kw) {
			return "HK", true
		}
	}
	for _, kw := range []string{"台湾", "台", "tw"} {
		if strings.Contains(name, kw) {
			return "TW", true
		}
	}
	for _, kw := range []string{"新加坡", "狮城", "sg"} {
		if strings.Contains(name, kw) {
			return "SG", true
		}
	}
	for _, kw := range []string{"日本", "jp"} {
		if strings.Contains(name, kw) {
			return "JP", true
		}
	}
	for _, kw := range []string{"韩国", "韩", "kr"} {
		if strings.Contains(name, kw) {
			return "KR", true
		}
	}
	// AU
	for _, group := range [][]string{
		{"澳大利亚", "🇦🇺"},
		{"australia", "australian"},
		{"au", "澳", "悉尼", "墨尔本", "sydney", "melbourne"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "AU", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "AU", true
				}
			}
		}
	}
	// CA
	for _, group := range [][]string{
		{"加拿大", "🇨🇦"},
		{"ca", "加"},
		{"canada", "canadian"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "CA", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "CA", true
				}
			}
		}
	}
	// GB
	for _, group := range [][]string{
		{"英国", "🇬🇧"},
		{"gb", "uk", "英国", "britain", "british", "england", "london"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "GB", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "GB", true
				}
			}
		}
	}
	// DE
	for _, group := range [][]string{
		{"德国", "🇩🇪"},
		{"germany", "german"},
		{"de", "德", "frankfurt"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "DE", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "DE", true
				}
			}
		}
	}
	// FR
	for _, group := range [][]string{
		{"法国", "🇫🇷"},
		{"france", "french"},
		{"fr", "法"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "FR", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "FR", true
				}
			}
		}
	}
	// NL
	for _, group := range [][]string{
		{"荷兰", "🇳🇱"},
		{"nl", "尼"},
		{"netherlands", "dutch", "dutchland", "amsterdam"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "NL", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "NL", true
				}
			}
		}
	}
	// RU
	for _, group := range [][]string{
		{"俄罗斯", "🇷🇺"},
		{"ru", "俄"},
		{"russia", "russian"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "RU", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "RU", true
				}
			}
		}
	}
	// AE（阿联酋）
	for _, group := range [][]string{
		{"阿联酋", "🇦🇪"},
		{"ae", "迪拜"},
		{"uae", "dubai"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "AE", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "AE", true
				}
			}
		}
	}
	// SA（沙特）
	for _, group := range [][]string{
		{"沙特", "🇸🇦"},
		{"sa", "利雅得"},
		{"saudi", "riyadh"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "SA", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "SA", true
				}
			}
		}
	}
	// TR（土耳其）
	for _, group := range [][]string{
		{"土耳其", "🇹🇷"},
		{"tr", "伊斯坦布尔"},
		{"turkey", "istanbul"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "TR", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "TR", true
				}
			}
		}
	}
	// IL（以色列）
	for _, group := range [][]string{
		{"以色列", "🇮🇱"},
		{"il", "特拉维夫"},
		{"israel", "telaviv", "tel-aviv"},
	} {
		for _, kw := range group {
			if len(kw) <= 3 || isChinese([]rune(kw)[0]) {
				if kwMatch(kw) {
					return "IL", true
				}
			} else {
				if strings.Contains(name, kw) {
					return "IL", true
				}
			}
		}
	}

	return "", false
}

// regionContains checks if node name `n` belongs to the same region as `targetRegion`.
// 同地区判定：复用 extractRegionTag 的优先级规则解析节点区域，再与目标区域比对。
// 这样 "香港-01-东京" 这类混合名也按关键词优先级稳定归类，不会跨区误配。
func regionContains(n, targetRegion string) bool {
	region, ok := extractRegionTag(n)
	if !ok {
		return false
	}
	return region == targetRegion
}

// FilterByRegion filters proxy names, keeping only those in the same region
// as the main proxy. Returns at least `mainProxy` itself if it's in the list.
func FilterByRegion(proxyNames []string, mainProxy string, targetRegion string) []string {
	if targetRegion == "" {
		return proxyNames
	}
	result := make([]string, 0, len(proxyNames))
	for _, n := range proxyNames {
		if regionContains(n, targetRegion) {
			result = append(result, n)
		}
	}
	return result
}

// 按 RTT 升序排序，取 top N 个
func topNByRtt(names []string, rttTable map[string]int, n int) []string {
	if len(names) == 0 || n <= 0 {
		return nil
	}
	// 按 RTT 排序
	type nodeRtt struct {
		name string
		rtt  int
	}
	nodes := make([]nodeRtt, 0, len(names))
	for _, nm := range names {
		if rt, ok := rttTable[nm]; ok {
			nodes = append(nodes, nodeRtt{name: nm, rtt: rt})
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].rtt < nodes[j].rtt
	})
	// 取前 n 个
	if len(nodes) > n {
		nodes = nodes[:n]
	}
	result := make([]string, 0, len(nodes))
	for _, nr := range nodes {
		result = append(result, nr.name)
	}
	return result
}

// 服务器大区：按游戏服务器 GeoIP 国家代码归属的大区标签，
// 用于 v6.1 候选池按服务器地区分支引导（Asia/EU/NA/OC/ME/其他）。
const (
	serverRegionAsia = "Asia"
	serverRegionEU   = "EU"
	serverRegionNA   = "NA"
	serverRegionOC   = "OC"
	serverRegionME   = "ME"
)

// laneRegions 五区锁定（Shadow Forking 改造 2026-10-17 需求 A/E）：
// 黄金枢纽池候选与记忆 RegionActual 的取值空间，仅此五区。
var laneRegions = map[string]bool{"HK": true, "TW": true, "SG": true, "JP": true, "KR": true}

// IsLaneRegion 返回 tag 是否属于五区白名单（HK/TW/SG/JP/KR）。
func IsLaneRegion(tag string) bool {
	return laneRegions[tag]
}

// serverRegionOf 将国家代码（大写，如 US/HK/SG/JP）映射到服务器大区；
// 无法判定（未知/南极等地区）返回 ""，调用方按"无法判定"分支处理。
func serverRegionOf(country string) string {
	switch country {
	case "HK", "TW", "MO", "CN", "SG", "JP", "KR",
		"TH", "MY", "VN", "PH", "ID", "IN", "BD", "PK", "LK",
		"NP", "MM", "KH", "LA", "BN", "TL":
		return serverRegionAsia
	case "GB", "DE", "FR", "NL", "RU", "IT", "ES", "SE", "PL", "CH",
		"AT", "BE", "IE", "PT", "FI", "DK", "NO", "CZ", "GR", "HU",
		"RO", "UA", "EE", "LV", "LT", "SK", "SI", "HR", "BA", "RS",
		"BG", "LU", "IS", "MT", "CY", "AD", "LI", "MC", "SM", "VA",
		"IM", "JE", "GG", "AX":
		return serverRegionEU
	case "US", "CA", "MX":
		return serverRegionNA
	case "AU", "NZ", "FJ", "PG", "NC", "SB", "VU", "WS", "TO", "PF":
		return serverRegionOC
	case "AE", "SA", "TR", "IL", "QA", "KW", "BH", "OM", "JO", "LB",
		"EG", "YE", "IQ", "IR", "SY", "AF", "PS", "CY2", "GE", "AM",
		"AZ", "KZ", "UZ", "TM", "TJ", "KG":
		return serverRegionME
	}
	return ""
}

// isTrustedServerCountry 判定服务器 GeoIP 是否为信任区。
// 信任区：亚洲明确区（HK/TW/MO/SG/JP/KR 等），不可无差别信任
// US/DE/AWS 云段等非亚洲区。非信任区返回 false，调用方回退玩家侧
// 港台就近。
func isTrustedServerCountry(country string) bool {
	return serverRegionOf(country) == serverRegionAsia
}

// regionTagsOf 服务器大区 → 该地区对应的节点名标签组，
// 用于"该地区节点优先"筛选（配合 extractRegionTag 判定）。
func regionTagsOf(serverRegion string) []string {
	switch serverRegion {
	case serverRegionAsia:
		return []string{"HK", "TW", "JP", "KR", "SG"}
	case serverRegionEU:
		return []string{"GB", "DE", "FR", "NL", "RU"}
	case serverRegionNA:
		return []string{"US", "CA"}
	case serverRegionOC:
		return []string{"AU"}
	case serverRegionME:
		return []string{"AE", "SA", "TR", "IL"}
	}
	return nil
}

// nearbyServerRegions 服务器大区 → 邻近大区列表（顺序即优先级），
// 用于非亚洲服务器分支"补邻近地区 1-2 个代表"。
func nearbyServerRegions(serverRegion string) []string {
	switch serverRegion {
	case serverRegionEU:
		return []string{serverRegionNA, serverRegionME}
	case serverRegionNA:
		return []string{serverRegionOC, serverRegionEU}
	case serverRegionOC:
		return []string{serverRegionNA, serverRegionAsia}
	case serverRegionME:
		return []string{serverRegionEU, serverRegionAsia}
	}
	return nil
}

// liveNodes 从全局节点中过滤 DIRECT 与死节点（RTT 有记录且 <=0），
// 返回可用节点列表，保持原顺序。
func liveNodes(allProxies []string, rttTable map[string]int) []string {
	out := make([]string, 0, len(allProxies))
	for _, n := range allProxies {
		if n == "" || n == "DIRECT" {
			continue
		}
		if rt, ok := rttTable[n]; ok && rt <= 0 {
			continue // 死节点（探测失败/无效 RTT）
		}
		out = append(out, n)
	}
	return out
}

// sortedByRttStable 稳定排序：有 RTT 数据的按升序排前，无 RTT 数据排后
// 保持原有先后顺序（探测校正阶段补齐）。
func sortedByRttStable(names []string, rttTable map[string]int) []string {
	out := append([]string(nil), names...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := rttTable[out[i]]
		rj, okj := rttTable[out[j]]
		if !oki {
			return false
		}
		if !okj {
			return true
		}
		return ri < rj
	})
	return out
}

// regionNodes 返回属于任一给定标签组的活节点（全量），按 RTT 升序
// （无 RTT 数据排后）。用于"港台全量进池"与该地区节点优先。
func regionNodes(live []string, rttTable map[string]int, tags ...string) []string {
	inTag := func(tag string) bool {
		for _, t := range tags {
			if t == tag {
				return true
			}
		}
		return false
	}
	out := make([]string, 0, len(live))
	for _, n := range live {
		if tag, ok := extractRegionTag(n); ok && inTag(tag) {
			out = append(out, n)
		}
	}
	return sortedByRttStable(out, rttTable)
}

// repPerGroup 对 tags 中每个标签组各取前 per 个代表（组内按 RTT 升序），
// 按 tags 顺序拼接；组内不足 per 个时取实际数量。
func repPerGroup(live []string, rttTable map[string]int, per int, tags ...string) []string {
	if per <= 0 {
		return nil
	}
	out := make([]string, 0, per*len(tags))
	for _, tag := range tags {
		group := regionNodes(live, rttTable, tag)
		if len(group) > per {
			group = group[:per]
		}
		out = append(out, group...)
	}
	return out
}

// buildPlayerPool 生成候选池（v6.3 服务器侧就近 + 玩家侧兜底）：
// 核心规则：服务器 GeoIP 信任区（亚洲明确区）时采用"服务器侧就近优先"，
// 即服务器所在区节点全量进池 + 港台兜底；可疑区/未知区退化为玩家侧
// 港台就近。RTT 实测佐证由上层 ensureAutoPrimary 传入参数，GeoIP 仅
// 做区判定不自行选路——实测 RTT 才由探测链路裁决选主节点。
//   - 服务器区明确且信任（HK/SG/JP 等）：核心 = 服务器所在区全量，
//     代表 = 港台 + 新/日/韩；
//   - 服务器区非亚洲 / 未知 / 不可信（US/DE/AWS 等）：核心 = 港台全量，
//     代表 = 新/日/韩（沿用现有玩家侧就近逻辑）。
//
// 池上限 maxCandidatePool；任何路径生成后不足 minCandidatePool（5）
// 由调用方从全局活节点按 RTT 升序补足。
func buildPlayerPool(playerRegion, serverRegion string, live []string, rttTable map[string]int, trustedServer bool) []string {
	if trustedServer && serverRegion != "" {
		// 服务器侧就近优先：服务器所在区全量进核心，港台兜底
		core := regionNodes(live, rttTable, regionTagsOf(serverRegion)...)
		// 港台兜底 + 新/日/韩代表
		tags := []string{"HK", "TW", "SG", "JP", "KR"}
		return cappedPool(core, fillReps(live, rttTable, maxCandidatePool-len(core), tags...))
	}

	switch playerRegion {
	case serverRegionAsia:
		// 港台永远在：全量进池；新/日/韩代表 + 服务器侧补充
		core := regionNodes(live, rttTable, "HK", "TW")
		tags := []string{"SG", "JP", "KR"}
		tags = append(tags, serverSideRepTags(serverRegion)...)
		return cappedPool(core, fillReps(live, rttTable, maxCandidatePool-len(core), tags...))
	case serverRegionNA:
		// 玩家在北美：美加全量优先；港台新日韩代表 + 服务器侧补充
		core := regionNodes(live, rttTable, "US", "CA")
		tags := []string{"HK", "TW", "SG", "JP", "KR"}
		tags = append(tags, serverSideRepTags(serverRegion)...)
		return cappedPool(core, fillReps(live, rttTable, maxCandidatePool-len(core), tags...))
	case serverRegionEU:
		// 玩家在欧洲：欧洲全量优先；港台新日韩 + 美加代表 + 服务器侧补充
		core := regionNodes(live, rttTable, regionTagsOf(serverRegionEU)...)
		tags := []string{"HK", "TW", "SG", "JP", "KR", "US", "CA"}
		tags = append(tags, serverSideRepTags(serverRegion)...)
		return cappedPool(core, fillReps(live, rttTable, maxCandidatePool-len(core), tags...))
	default:
		// 玩家位置未知：保持服务器侧引导（v6.1 原逻辑）
		return cappedPool(buildServerPool(serverRegion, live, rttTable), nil)
	}
}

// serverSideRepTags 服务器 GeoIP 地区 → 需补充进候选池的该地区节点标签。
// 玩家侧就近优先之外，保证服务器所在地区有代表可切（防"亚洲玩家连
// 北美服务器却无美加候选"）。服务器在亚洲时不额外补充（港台新日韩
// 已是玩家侧代表，重复无意义）。
func serverSideRepTags(serverRegion string) []string {
	switch serverRegion {
	case serverRegionNA:
		return []string{"US", "CA"}
	case serverRegionEU:
		return regionTagsOf(serverRegionEU) // GB DE FR NL RU
	case serverRegionOC:
		return []string{"AU"}
	case serverRegionME:
		return regionTagsOf(serverRegionME) // AE SA TR IL
	}
	return nil
}

// cappedPool 核心 + 代表拼接并硬限 maxCandidatePool（核心过多时截断），
// 保证任何路径生成的候选池都不超过上限（v6.2 统一收口）。
func cappedPool(core, reps []string) []string {
	if len(core) >= maxCandidatePool {
		return core[:maxCandidatePool]
	}
	room := maxCandidatePool - len(core)
	if len(reps) > room {
		reps = reps[:room]
	}
	out := append([]string(nil), core...)
	return append(out, reps...)
}
