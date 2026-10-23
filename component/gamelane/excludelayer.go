package gamelane

import "net/netip"

// gameExcludedPrefixes 自动识别前的排除层（2026-10-19 v2.5 第一刀彻底洗白，
// 谷歌批复 100% 通过）：只保留基础设施段——私网/环回/CGNAT/链路本地/组播/
// TUN 虚拟网段/本网。
// 铁令 B 日志实锤（00:40 一场）：此前被拉黑的三个"公网游戏段"全是误杀——
//   - 155.133.224.0/19：实为 Valve（Steam 官方，AS32590）全球核心服务器段
//     （Steam SDR 游戏对局中继），绝非 Discord——Steam 版 APEX/CS2/PUBG 等
//     走 Steam Networking Sockets 的 27015~27200 UDP 100% 落在该段；
//   - 162.254.192.0/18：同为 Valve 核心网段（162.254.193.99:27120 实测）；
//   - 89.222.0.0/16：G-Core Labs 游戏云段（89.222.117.200:27052 对局实锤）。
//     全部迁入 gameBuiltInCIDRs 白名单（首包 T=0ms 段表命中）。
//
// 公网 CDN 段（54.230/20.43/18.65/18.230/3.66/100.60/20.196）一并删除：
//
//	443/8125 已被铁令 C 端口总闸一票否决（v2.4），Steam 下载与网页 CDN 走
//	TCP/QUIC 不经 GameLane，无需按 IP 段拉黑——按公网 IP 段拉黑只会误杀
//	动态分配的对局服务器（code:net 根因）。
//
// 保留：RFC1918 10/8、172.16/12、192.168/16、环回、CGNAT 100.64/10、
// 链路本地 169.254/16、组播 224.0.0.0/4、本网 0.0.0.0/8、TUN 虚拟网段
// 198.18.0.0/15（TUN 模式源地址归属该段，目标绝不应出现在该段）。
// 规则（批复原文）：UDP 目的端口 1024~65535 且不在排除端口（53/123/443/
// 1900/3478/5353/8081/8125，见 autoreg.IsExcludedAutoRegPort）内、属游戏
// 进程/活跃期的，一律不准按公网 IP 段拉黑。
//
// 非法格式/255+ 由 ParseAddr 与 Is4 校验在调用方先行拦截。
var gameExcludedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"),  // TUN 虚拟网段（fake-ip）
	netip.MustParsePrefix("224.0.0.0/4"),    // 组播
	netip.MustParsePrefix("0.0.0.0/8"),      // 本网/未指定
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("127.0.0.0/8"),    // 环回
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("169.254.0.0/16"), // 链路本地
}

// gameBuiltInCIDRs 内置游戏服务器段表（F11 接线，2026-10-16 确认）：
// 原 v4 定义后从未被引用（死代码），现由 server_segment.MatchIP 并入
// “已知游戏段”判定：命中即允许注册；但**区判定不因段命中而信任 GeoIP**——
// 仅当命中非云段且 GeoIP 为亚洲信任区才视为 trustedServer（见
// RegionTrustedFor）。除原有 EA/Valve 段外，补充 2026-10-16 core.log
// 实锤的 APEX 服务器/数据中心段：
var gameBuiltInCIDRs = []netip.Prefix{
	netip.MustParsePrefix("103.10.124.0/23"), // EA/Valve 亚太（103.10.124-125.x 实测）
	netip.MustParsePrefix("146.66.0.0/16"),   // EA/Valve 自有段
	netip.MustParsePrefix("18.136.0.0/13"),   // AWS 新加坡（ap-southeast-1）
	netip.MustParsePrefix("152.233.0.0/16"),  // APEX 数据中心（152.233.52.x 实测）
	netip.MustParsePrefix("103.28.54.0/24"),  // APEX/TLS 数据中心（103.28.54.x 实测）
	netip.MustParsePrefix("45.121.184.0/24"), // APEX 数据中心（45.121.184.x 实测）
	netip.MustParsePrefix("185.25.180.0/22"), // APEX 数据中心（185.25.180-183.x 实测）
	netip.MustParsePrefix("54.189.0.0/16"),   // AWS us-west-2（APEX 服务/遥测实测）
	// ---- v2.3 修改①（2026-10-18 谷歌批复）：AWS 亚太对局/测速段补全 ----
	// 治本第一层：真实 IP 首包 0ms 命中段表（autoreg 段表路径同步注册）。
	netip.MustParsePrefix("18.162.0.0/15"), // AWS 香港 ap-east-1（APEX 港服核心段）
	netip.MustParsePrefix("18.166.0.0/16"), // AWS 香港 ap-east-1
	netip.MustParsePrefix("52.220.0.0/15"), // AWS 新加坡 ap-southeast-1
	netip.MustParsePrefix("13.228.0.0/15"), // AWS 新加坡 ap-southeast-1
	// ---- v2.7（《根治训练场 1~2 分钟后切换卡死超时指令》）：补训练场实锤段 ----
	netip.MustParsePrefix("15.129.0.0/16"),  // 训练场对局目标 15.129.62.61 所在段（AWS 亚太实测）
	netip.MustParsePrefix("13.250.0.0/15"),  // AWS 新加坡 ap-southeast-1
	netip.MustParsePrefix("13.112.0.0/14"),  // AWS 东京 ap-northeast-1
	netip.MustParsePrefix("52.192.0.0/15"),  // AWS 东京 ap-northeast-1
	netip.MustParsePrefix("18.232.0.0/14"),  // EA 大厅/跨区测速段
	netip.MustParsePrefix("15.184.0.0/16"),  // EA 跨区测速段（巴林 15.184.192.233 在内）
	netip.MustParsePrefix("216.244.0.0/16"), // v2.4 1.1：AWS 通用云段双保险（与 cloudGameSegments 一致；RegionTrustedFor 仍 false，区判定口径不变）
	// ---- v2.5 第一刀（2026-10-19 谷歌批复 100% 通过）：误杀段洗白入白名单 ----
	netip.MustParsePrefix("155.133.224.0/19"), // Valve SDR 游戏核心网段（155.133.238.178:27051 实测）
	netip.MustParsePrefix("162.254.192.0/18"), // Valve SDR 游戏核心网段（162.254.193.99:27120 实测）
	netip.MustParsePrefix("89.222.0.0/16"),    // G-Core Labs 游戏云段（89.222.117.200:27052 实测）
	netip.MustParsePrefix("15.185.0.0/16"),    // EA 测速/部署段（与 15.184.0.0/16 相邻；仅注册，不作测速模板——见 preheat 巴林禁靶）
}

// cloudGameSegments 云厂商全球段（红线 2 / F11 第三态）：确有游戏服务器部署，
// 但 GeoIP 国家码不可信（曾因全信 GeoIP 选到欧美节点、延迟 200ms+）。命中
// 本表的 IP：允许注册（MatchIP=true），但 RegionTrustedFor=false——绝不因段
// 命中就信任其 GeoIP 区判定，区以记忆/可信 GeoIP 为准。
var cloudGameSegments = []netip.Prefix{
	netip.MustParsePrefix("216.244.0.0/16"), // AWS 通用段（APEX 亚洲服务器 216.244.12.x 在内）
	// ---- v2.9 P4（2026-10-19 批复裁决 1：方案 A）----
	// 7 个 GCP/AWS 亚洲段全部进本表而非 gameBuiltInCIDRs：只要 MatchIP=true
	// （首包 0ms 注册），但 RegionTrustedFor 维持 false——这些是共享公有云段，
	// GeoIP 常被判欧美，一旦区可信就会点亮 trustedServer → buildServerPool
	// 走 EU/NA 空池分支，港台核心池从 12 缩到 5~6（gamelane.go:1402 实锤）。
	netip.MustParsePrefix("35.201.0.0/16"),    // GCP 台湾 asia-east1
	netip.MustParsePrefix("35.229.128.0/17"),  // GCP 台湾 asia-east1
	netip.MustParsePrefix("104.199.128.0/18"), // GCP 台湾 asia-east1
	netip.MustParsePrefix("35.187.192.0/19"),  // GCP 东京 asia-northeast1
	netip.MustParsePrefix("34.92.0.0/16"),     // GCP 香港 asia-east2
	netip.MustParsePrefix("13.124.0.0/15"),    // AWS 首尔 ap-northeast-2
	netip.MustParsePrefix("52.78.0.0/15"),     // AWS 首尔 ap-northeast-2
}

// isCloudSegmentIP 命中云厂商段表返回 true（区判定不可信）。
func isCloudSegmentIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	for _, p := range cloudGameSegments {
		if p.Contains(addr) {
			// v2.10 埋点：v2.9 P4 新增 7 段是否真的吃进注册（atomic，热路径安全）
			metricsCloudSegHit.Add(1)
			return true
		}
	}
	return false
}

// isExcludedIP 命中任一排除段返回 true。供候选预过滤（isAutoRegCandidate）
// 与注册前终检（RegisterTargetIP）两处调用，保证"排除层 → 特征判定 →
// 注册前再查排除层"全链路闭合。
func isExcludedIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	for _, p := range gameExcludedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
