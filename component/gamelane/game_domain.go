package gamelane

// 游戏域名判定（2026-10-18 Fake-IP 双保险 第一招，批复 Q-B/Q-C）：
// DNS 层（dns/middleware.go withFakeIP :155）对命中域名的查询跳过 fake-ip、
// 直接返回真实解析结果——治本解决"赛马拨号不可路由/主路查锁脱节/fake-ip
// 同 /24 互相污染"。判定顺序：域名后缀树（SegmentTable().MatchDomain，
// ns 级纯内存）→ 内置云测速/游戏后缀清单（静态编译，不依赖任何文件——
// 域名树由 StartSegmentLoader 异步加载，启动窗口期也能命中，批复 Q-C）。

import (
	"strings"
)

// builtinCloudSpeedtestSuffixes 内置云测速/游戏后缀清单（批复 Q-C 修正版 13 条）。
// 命中规则：domain == suffix 或 strings.HasSuffix(domain, "."+suffix)（含子域通配）。
// 关键修正：GameLift UDP Ping Beacon 域名为 gamelift-ping.<region>.api.aws
// （7770 测速流），后缀是 api.aws 而非 amazonaws.com——原 gamelift/compute
// 两条作废，api.aws 一条覆盖全球所有区域测速端点。
var builtinCloudSpeedtestSuffixes = []string{
	// GameLift UDP Ping Beacon（7770 测速流，域名 gamelift-ping.<region>.api.aws）
	"api.aws",
	// 云底座（AWS 控制面/计算、GCP、Azure）
	"amazonaws.com",
	"googleusercontent.com",
	"trafficmanager.net",
	"cloudapp.net",
	// 游戏大厂（EA / Valve / Riot / Epic）
	"ea.com",
	"origin.com",
	"respawn.com",
	"steamserver.net",
	"steampowered.com",
	"pvp.net",
	"riotgames.com",
	"epicgames.com",
	// ---- v2.9 P1（2026-10-19 批复）：非亚太厂商域名，免 Fake-IP 直接真实解析 ----
	"battle.net",
	"blizzard.com",
	"activision.com",
	"demonware.net",
	"ubi.com",
	"ubisoft.com",
	"valvesoftware.com",
	"steamcontent.com",
	// ---- v2.5 强制修正一：STUN 服务器域名免 Fake-IP（STUN 保底探针的
	// 域名解析路径依赖；解析失败/返回 Fake-IP 仍有静态 Anycast IP 兜底）----
	"stun.cloudflare.com",
	"stun.l.google.com",
}

// matchGameSuffix domain 是否等于 suffix 或为其子域（大小写不敏感）。
func matchGameSuffix(domain, suffix string) bool {
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}

// IsGameDomain 判定域名是否属于游戏/云测速域（DNS 层跳过 fake-ip 的唯一
// 判据，dns/middleware.go:155 消费）。纯内存、无锁、无 IO——DNS 路径
// 禁止引入锁/阻塞/IO（批复 Q 性能要求）。语义边界：仅命中游戏/云测速
// 域名的查询跳过 fake-ip，其余域名照常返回 198.18.x.x（网页行为不变）。
func (m *Manager) IsGameDomain(domain string) bool {
	if domain == "" {
		return false
	}
	d := strings.ToLower(domain)
	if SegmentTable().MatchDomain(d) {
		// v2.10 埋点：域名树命中（DNS 路径只 atomic，零分配）
		metricsDomainTableHit.Add(1)
		return true
	}
	for _, s := range builtinCloudSpeedtestSuffixes {
		if matchGameSuffix(d, s) {
			// v2.10 埋点：内置后缀命中（v2.9 新增 8 条厂商后缀的观测点）
			metricsSuffixHit.Add(1)
			return true
		}
	}
	return false
}
