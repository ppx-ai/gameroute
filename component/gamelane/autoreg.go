package gamelane

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// gameProcessKeywords 判定"游戏进程"的子串关键字（与面板自动圈选一致）。
// 命中后其 UDP 目标视为候选对局服务器，走"识别即注册"。
//
// v2.9 P0（2026-10-19 批复修正一）：扩容到非亚太 Source 引擎系游戏本体。
// 平台启动器词（battle.net / ubisoft / leagueclient）一律剔除——启动器常驻
// 后台产生的 UDP 流量会被 trusted=true 永久免淘汰保活，不得作为识别依据；
// 本体识别改用 rainbowsix / "league of legends" 等真实进程名。
// R6S 本体进程为 RainbowSix.exe（不含 rainbow6/r6s 子串），故用 rainbowsix。
var gameProcessKeywords = []string{
	// 既有词条（只加不减）
	"tslgame", "pubg", "execpubg", "gameusersettings", "battl", "r5apex",
	"valorant", "vgk", "vanguard", "cs2", "csgo", "cod", "warzone", "fortnite",
	// v2.9 P0：暴雪 / Valve / 育碧 / EA / 亚洲系本体
	"overwatch", "ow2", "dota2", "rainbowsix", "escapefromtarkov",
	"deadbydaylight", "helldivers2", "thefinals", "marvelrivals",
	"deltaforce", "naraka", "league of legends", "genshin", "starrail",
	// v2.9 P0：Unity/虚幻 shipping 变体通杀（专用判定见 isGameProcessName）
	"-shipping",
	// v2.10 识别升级（2026-10-20）：平台安装目录特征——Windows 下进程反查
	// 拿到的是完整可执行路径，库内任意游戏即使进程名不在词条表，路径命中
	// 即判定为游戏（旧词条一条未删，只加不减）。
	// battle.net 属启动器词，不进本表（会误圈启动器自身），改由
	// auxProcessKeywords 排除；epicwebhelper 同理（路径含 "epic games"）。
	"steamapps\\common", "epic games", "riot games", "ea games",
	"origin games", "ubisoft game launcher", "xboxgames", "wegameapps",
	// v2.11 无词表通用识别（2026-10-21）：中文游戏平台/网咖出盘目录特征。
	// 顺网云电脑等无盘环境把游戏释放到 <盘>\我的游戏\ / 网络游戏\ 等中文
	// 目录，进程名与平台目录都不含任何已知词条，只能用目录形态兜底。
	// 匹配语义为 strings.Contains(小写整路径, k)，中文不涉大小写；
	// 入参在 isGameProcess 内已 ToLower，故此处写原文即可。
	"我的游戏\\", "网络游戏\\", "对战游戏\\", "单机游戏\\", "\\games\\",
	// 注（v2.12 修正，2026-10-22）：第二批国际软件 aux 词（代理/VPN/BT/流媒体/
	// IM）此前被误置于本表，已移回 auxProcessKeywords——本表只收"游戏本体
	// 特征"，混入非游戏进程词会让 isGameProcessName 把它们当游戏。
}

// skipAutoRegPorts 自动注册统一排除端口（F10 单一来源，flow.go 的
// flowSkipPorts 即本表别名，消除双表漂移）：
//   - 443(QUIC/网页视频)/8081：CDN/网页流量不参与零名单注册；
//   - 53/123/5353/1900：DNS/NTP/mDNS/SSDP 系统流量（3478 STUN 已于
//     v2.12 移出——对局服务器自身常驻 3478，排除即漏接对局）；
//   - 8125：APEX 遥测 StatsD（r5-pc-stats.stryder.respawn.com），实测被
//     误注册为对局目标并参与切换/记忆污染（2026-10-16 诊断 RC12），按确认排除；
//   - 红线：27022 属 APEX 对局端口段 27015-27060，必须注册，不得加入本表
//     （曾因跳过注册导致对局流量不被接管；flow.go 曾误加，已同步移除）。
//
// IsExcludedAutoRegPort 排除端口总闸（2026-10-18 v2.4 铁令 C）：8125
// StatsD 遥测/443 QUIC/53 DNS 等一票否决——严禁注册/onLane/SessionConn
// 包装观测（单向流/无状态特征会污染评分/记忆并触发误切换，RC12 回归）。
func IsExcludedAutoRegPort(port uint16) bool {
	skipPortsMu.RLock()
	v := skipAutoRegPorts[port]
	skipPortsMu.RUnlock()
	return v
}

// skipPortsMu 保护 skipAutoRegPorts 的"启动期合并"写入：清单3 的
// game_udp_sysports.json 在启动时（流量起来之前）合并进本表，此后只读。
// 读侧统一走 IsExcludedAutoRegPort（RLock），避免 map 并发读写。
var skipPortsMu sync.RWMutex

// skipAutoRegPorts 内置兜底 7 端口（v2.12 清单3，2026-10-22）：
// 3478(STUN) 已移除——Epic/多数对局服务器自身用 3478 做对局端口，
// 排除它会把整场对局流量挡在 GameLane 之外（零冲突清单红线）。
// 其余系统服务端口由 runtime/game_udp_sysports.json 动态合并（用户可自改）。
var skipAutoRegPorts = map[uint16]bool{
	53:   true, // DNS
	123:  true, // NTP
	443:  true, // QUIC/HTTP3
	1900: true, // UPnP/SSDP
	5353: true, // mDNS
	8081: true, // CDN 探测（与 game_channel.json 一致）
	8125: true, // APEX 遥测 StatsD（2026-10-16 确认排除）
}

// RegisterTargetIP 将单个公网 IPv4 以 /32 CIDR 注册进内存态
// 目标注册表（幂等：目标已存在或已被现有 CIDR 覆盖时返回 false）。
// 供"识别即注册"链路使用：对局服务器目标一经识别立即注册，使该会话
// 后续（含首包）即命中 GameLane 快速通道，并由 M3 接管自动主节点分配。
// 注册前用排除层再查一遍（判定后验证）：命中 Discord/Steam/TUN/私网/
// 组播/保留段等任一排除段一律拒绝注册。
// 注册成功后同步写入自学习记忆（普通 IP key），供重启后秒识别。
func (m *Manager) RegisterTargetIP(ip string) bool {
	return m.RegisterTargetIPTrusted(ip, false)
}

// RegisterTargetIPTrusted 注册单 IP /32 目标（2026-10-18 v2.4 铁令 A）：
// trusted=true 表示来源为段表命中/游戏域名命中/游戏进程确认——无视
// isBlacklisted 并从黑名单移除（防 watch 历史误杀 24h 永久拉黑对局
// 服务器）；isExcludedIP 终检保留（排除层红线不豁免）。
func (m *Manager) RegisterTargetIPTrusted(ip string, trusted bool) bool {
	return m.registerTargetIPTrusted(ip, trusted, false)
}

// registerTargetIPTrusted 内部分档实现。forceOverseas=true 表示调用方已
// 确认该目标必须接管（清单5 fakeCN 观察窗判定为"假大陆 IP"），跳过大陆
// 路由表直连判定；其余语义与导出函数完全一致。
func (m *Manager) registerTargetIPTrusted(ip string, trusted bool, forceOverseas bool) bool {
	if trusted {
		m.removeBlacklist(ip)
	} else if bl, until := m.isBlacklisted(ip); bl {
		log.Warnln("[GameLane] blacklist hit %s (until %s)", ip, until)
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}
	if isExcludedIP(addr) {
		log.Debugln("[GameLane] register rejected: %s hits excluded CIDR", ip)
		return false
	}
	// 国内游戏 UDP 直连（domestic-direct，指令 2026-10-21；判据于 v2.12
	// 清单4 由 GeoIP(MMDB) 换为内置大陆 IPv4 路由表 chnroutes，理由：
	// MMDB 需外部数据文件、云电脑打包常缺失，缺数据时只能保守接管海外
	// 目标 → 国内对局被绕出国再回国。路由表开箱内置、零依赖）：
	// 目标 IP 属大陆路由表且未命中已知游戏段表时，GameLane 拒绝接管，
	// 交系统直连放行。段表命中永不直连；表外目标（含海外）行为零变化。
	// 清单5 反悔机制：同 IP 若已有 fakecn_override 持久标记（曾实测直连
	// 死链/高延迟），直接按海外服处理，绕过本判定。
	if !forceOverseas {
		if isChinaMainlandIP(addr) && !SegmentTable().MatchIP(addr) {
			if !m.hasFakeCNOverride(ip) {
				recordDiag("domestic_direct", "register skipped, china-mainland route not in game segments: %s", ip)
				return false
			}
			recordDiag("fakecn_override", "memory override hits, take over despite china route: %s", ip)
			forceOverseas = true
		}
	}
	prefix := netip.PrefixFrom(addr, 32)

	m.mu.Lock()
	if !m.enabled {
		m.mu.Unlock()
		return false
	}
	for i := range m.targets {
		if cidrContains(m.targets[i].CIDR, addr) {
			m.mu.Unlock()
			return false
		}
	}
	m.targets = append(m.targets, Target{
		CIDR: []netip.Prefix{prefix},
		// Proxy 为空 → auto 目标：Match 命中后走 ensureAutoPicked 进场临时
		// 主节点（最低 RTT / 随机 / 默认出口兜底），M3 预测式切换接管后续
		// 劣化自动切优。GameLane 绝不直连：默认出口作最终兜底。
		Proxy: "",
	})
	// v2.4 漏洞四（第三刀，谷歌强制）：注册即初始化主路——currentPrimary
	// 从诞生第 1ms 起绝不空（bestRaceWinner / 段锁 / 冠军直接填入），
	// /api/game/lane/status 不再出现 proxy 空目标（216.244.26.60 形态）。
	nt := &m.targets[len(m.targets)-1]
	if nt.Proxy == "" || nt.Proxy == "auto" {
		nt.autoPrimary = true
		m.ensureAutoPicked(nt, addr, "", m.allProxies, m.rttTable)
	}
	m.mu.Unlock()
	// F4：新注册目标入队，tunnel 层去抖后按 IP 精确重建会话（不再全表重建）。
	m.pushNewRegistration(ip)
	// 登记动态监视条目：注册不是永久，后续由 watch 持续验证并自我纠错
	// （大包下载/单向流/端口跳变/24h 无对局特征 → 自动淘汰）。
	m.watchesMu.Lock()
	if m.watches == nil {
		m.watches = make(map[string]*watchStat)
	}
	m.watches[ip] = newWatchStat(ip)
	m.watchesMu.Unlock()

	// 自学习记忆：目标确认注册后记住（普通 IP key "ip/32"；
	// 端口段记忆由 ObserveUDPFlow 注册路径在拿到 DstPort 后补充）。
	// v4：RegisterTargetIP 无进程反查信息，记为 flow 来源（B类）。
	m.remember(ip, 0)

	log.Infoln("[GameLane] auto-register target %s/32 (auto primary, M3 managed)", ip)
	// P0-2 入口分母：注册成功唯一出口（RegisterTargetIP 内部直接委托本函数，
	// 段表/域名/进程/flow 四档均汇流到此），统一口径避免多点重复埋。
	metricsRegisteredTotal.Add(1)
	return true
}

// UnregisterTargetIP 从注册表移除指定 IP 的 /32 目标（运行中动态删除）。
// 移除成功后将该 IP 相关记忆全部降权（active → decay），不再秒识别。
// 注意：watch 的 idle/dead/process-exited 淘汰不降权（v3 合并修复），
// 必须走 unregisterTarget(ip, false)；只有手动删除/硬性异常特征淘汰才 forget。
func (m *Manager) UnregisterTargetIP(ip string) bool {
	return m.unregisterTarget(ip, true)
}

// unregisterTarget 移除指定 IP 的 /32 目标。withForget=true 时同时将
// 该 IP 记忆降权（手动删除语义）；withForget=false 时仅移除注册表与
// watch（idle/dead-cleanup 与进程退出清理语义——游戏下次启动同进程
// 还会学回来，不应降权记忆）。
func (m *Manager) unregisterTarget(ip string, withForget bool) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}
	want := netip.PrefixFrom(addr, 32)
	m.mu.Lock()
	removed := false
	for i := range m.targets {
		if len(m.targets[i].CIDR) == 1 && m.targets[i].CIDR[0] == want {
			m.targets = append(m.targets[:i], m.targets[i+1:]...)
			removed = true
			break
		}
	}
	m.mu.Unlock()
	if !removed {
		return false
	}
	// 同步清理动态监视条目
	m.watchesMu.Lock()
	delete(m.watches, ip)
	m.watchesMu.Unlock()
	if withForget {
		// 记忆降权：该 IP 被移除说明不可靠，不再参与秒识别
		m.forget(ip)
	}
	log.Infoln("[GameLane] unregister target %s/32 (forget=%v)", ip, withForget)
	return true
}

// pushNewRegistration 新注册目标入队（F4 注册重建收窄）：RegisterTargetIP
// 成功即调用；tunnel 层 DrainNewRegistrations 取走后按目标 IP 精确重建
// （只重建 dst==该 IP 的会话），不再全表匹配重建。
func (m *Manager) pushNewRegistration(ip string) {
	m.newRegMu.Lock()
	m.newRegQueue = append(m.newRegQueue, ip)
	m.newRegMu.Unlock()
}

// DrainNewRegistrations 取走自上次取走以来的全部新注册目标 IP（去重保序）。
func (m *Manager) DrainNewRegistrations() []string {
	m.newRegMu.Lock()
	defer m.newRegMu.Unlock()
	if len(m.newRegQueue) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(m.newRegQueue))
	out := make([]string, 0, len(m.newRegQueue))
	for _, ip := range m.newRegQueue {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	m.newRegQueue = m.newRegQueue[:0]
	return out
}

// isGameProcessName 按关键字子串匹配进程名（大小写不敏感）。
//
// v2.9 修正一：cod 词条会把 VS Code（Code.exe）误判为 COD 本体，显式排除。
// 裁决 4：-shipping 通杀词不用 Contains 裸匹配，改三分支判定以兼容虚幻引擎
// 完整命名（X-Win64-Shipping.exe / X-WinGDK-Shipping.exe / X-Shipping.xxx）。
func isGameProcessName(name string) bool {
	n := strings.ToLower(name)
	// v2.10 识别升级：aux 排除前置于一切命中（启动器/反作弊常驻进程
	// 即便路径含 steamapps 或同目录带引擎 DLL 也不得判定为游戏本体）。
	if isAuxProcessName(n) {
		return false
	}
	if n == "code.exe" || n == "code" {
		// v2.10 埋点：VSCode 显式排除次数（只 atomic，不进事件环）
		metricsProcCodeExcluded.Add(1)
		return false
	}
	if matchGameProcessKeyword(n) {
		recordProcKwHitSample(name)
		return true
	}
	return false
}

// isGameProcessNameQuiet 与 isGameProcessName 判定结果一致，但不写任何计数器
// （连 code.exe 排除也不计数）。专供历史数据校验、离线判定等"非运行期识别"
// 场景调用，保证 proc_keyword_hit / proc_code_excluded 只反映真实流量判定。
func isGameProcessNameQuiet(name string) bool {
	n := strings.ToLower(name)
	if isAuxProcessName(n) {
		return false
	}
	if n == "code.exe" || n == "code" {
		return false
	}
	return matchGameProcessKeyword(n)
}

// matchGameProcessKeyword 是纯判定内核（入参须已 ToLower），只回答"是否命中
// 游戏进程关键词"，不写任何计数、不打日志。
//
// 拆分原因（v2.10.2）：LoadMemory 的历史记忆污染校验也要做同一判定，但那是
// "校验历史条目"而非"运行期检测到游戏进程"，绝不能计入 proc_keyword_hit
// （否则计数器变成"加载了几条记忆"，实测 93 条 × 两次加载 = 186 的假信号）。
func matchGameProcessKeyword(n string) bool {
	for _, k := range gameProcessKeywords {
		if k == "-shipping" {
			if strings.HasSuffix(n, "-shipping.exe") ||
				strings.HasSuffix(n, "-shipping") ||
				strings.Contains(n, "-shipping.") {
				return true
			}
			continue
		}
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// auxProcessKeywords 辅助/启动器进程词（2026-10-20 识别升级）：
// 这些进程自身不是游戏本体，但可能带 Unity/虚幻 运行库或落在游戏平台
// 目录里，必须优先于 keywords/目录/DLL 判定直接排除，防止启动器常驻
// 后台的 UDP 流量被 trusted=true 免淘汰保活。
var auxProcessKeywords = []string{
	"steam", "steamwebhelper", "epicwebhelper", "epicgameslauncher",
	"battle.net", "blizzard", "riotclient", "riotclientservices",
	"origin", "eadesktop", "eabackgroundservice", "ubisoftconnect",
	"uplay", "galaxyclient", "wegame", "xboxpcapp", "gamingservices",
	"crashreport", "crashpad", "easyanticheat", "beclient", "beservice",
	"vgc", "vgtray", "unrealcefsubprocess", "cefsubprocess",
	// v2.11 无词表通用识别（2026-10-21）：processGate 放开未知进程后，
	// 浏览器/IM/下载器/播放器/系统进程必须有显式对齐，否则它们与引擎
	// DLL 同目录（或路径带 \games\ 之类）时会漏过流量特征闸门。
	// 取舍：qq 为包含匹配，会连带压制含 "qq" 的腾讯系老游戏进程名，
	// 但游戏本体可由目录/DLL 特征兜底，且避免 QQMusic/QQ 误注册优先。
	"discord", "qq", "wechat", "chrome", "msedge", "firefox", "opera",
	"qbittorrent", "thunder", "bilibili", "potplayer", "cloudmusic",
	"kugou", "feishu", "dingtalk", "zoom", "svchost", "explorer",
	// v2.12 清单4/红线4（2026-10-22）：原 airlinks（顺网云串流客户端）与
	// \shunwangcloud\ 路径词已移除——两者均为国内软件，其串流目标 IP 已被
	// 大陆路由表直连拦下（不进 GameLane），留在 aux 表属"无收益的死条目"，
	// 违背"不做无用功"。若实测出现串流流量被误判为对局，再按单条恢复。
	//
	// v2.12 清单1.5 第二批（2026-10-22，来源 MetaCubeX/rules-mrs
	// applications.yaml + teslaproduuction/ClashDomainsList，Apache-2.0，
	// 见 data/AUX-RULES-NOTICE.txt）：只收"连国外目标的非游戏进程"——
	// 国内软件（wemeet/qiyi/youku/douyu/huya/wps/baidu/quark/aliyun/todesk/
	// sunlogin/sogou/leigod/xunyou/uu/ime）一律不加，其流量已被
	// isChinaMainlandIP 直连门禁拦在注册之前。
	// 取舍：surge/fdm/xdm/leaf 为包含匹配，可能连带压制个别含同串的游戏名，
	// 游戏本体仍可由目录特征/引擎 DLL 兜底（宁可不识别也不误伤）。
	"nvidia",
	"hysteria", "tuic", "udp2raw", "v2ray", "xray", "sing-box", "tailscale",
	"zerotier", "trojan", "shadowsocks", "ss-local", "naive", "proxifier",
	"speeder", "speederv2", "leaf", "frpc", "frps", "surge",
	"bitcomet", "utorrent", "transmission", "webtorrent", "aria2", "fdm",
	"nettransport", "neatdm", "folx", "xdm",
	"teams", "telegram", "spotify", "whatsapp",
}

// auxPathKeywords 辅助/启动器安装目录特征（小写，反斜杠分隔）：
// 路径命中同样先排除，例如 Epic 的 EpicWebHelper.exe 位于
// ...\Epic Games\Launcher\Portal\Extras\EOS\... 下。
var auxPathKeywords = []string{
	"\\steam\\bin\\", "\\steam\\steamapps\\common\\steamworks",
	"\\epic games\\launcher\\", "\\battle.net\\", "\\blizzard entertainment\\",
	"\\riot client\\", "\\programdata\\riot games\\",
	"\\origin\\", "\\ea desktop\\", "\\ubisoft game launcher\\",
	"\\wegameapps\\wegame\\", "\\xboxgames\\xbox app\\",
	// v2.11 无词表通用识别（2026-10-21）：系统/系统级安装目录一律排除，
	// 防止 system32 / Windows 自带进程在放开进程门禁后误注册。
	"\\windows\\", "\\programdata\\microsoft\\", "\\system32\\",
	// v2.12 清单1.5 路径补充（2026-10-22）：NVIDIA 系列进程名随组件变化
	// （nvcontainer.exe / nvsphelper64.exe / nvngx_dlss 相关宿主），裸名不含
	// "nvidia"，只能靠安装目录特征排除（方向为收紧）。
	// 仅用带 Corporation 的完整目录名，避免 "\\nvidia\\" 这类过宽词误伤。
	"\\nvidia corporation\\",
	// Telegram 便携版可能落在任意目录，桌面版固定 Desktop 子目录；
	// 裸名已覆盖 telegram.exe，此处兜 path 变体（收紧方向）。
	"\\telegram desktop\\",
}

// gameEngineDLLs 引擎/游戏运行库特征 DLL（小写）：进程同目录（或其父目录、
// 其 Tools 子目录）存在任一即判定为游戏本体（覆盖进程名不含任何词条的自研/
// 冷门游戏）。精确匹配走 os.Stat；Oodle 压缩库因文件名带版本号，另由
// dirHasEngineDLL 做 oo2core_ 前缀兜底扫描（精确表仍枚举常见版本）。
//
// 2026-10-21 修正：删除虚构条目 unrealengine.dll（UE 从不产出该文件名，
// 该条目只会带来无意义 stat）；补齐 Unity/UE/EOS/EAC/中间件 DLL。
var gameEngineDLLs = []string{
	"unityplayer.dll", "ue4game.exe", "ue5game.exe",
	"physxcore.dll", "physx3common_x64.dll", "nvngx_dlss.dll",
	"steam_api64.dll", "steam_api.dll",
	"eossdk-win64-shipping.dll", "eossdk-win64.dll",
	"easyanticheat.dll", "easyanticheat_eos.dll",
	"bink2w64.dll", "binkw64.dll",
	"fmod.dll", "fmod64.dll", "fmodstudio.dll",
	"aksoundengine.dll", "amd_ags_x64.dll", "openvr_api.dll",
	"oo2core_3_win64.dll", "oo2core_4_win64.dll", "oo2core_5_win64.dll",
	"oo2core_6_win64.dll", "oo2core_7_win64.dll", "oo2core_8_win64.dll",
	"oo2core_9_win64.dll",
}

// oodleDLLPrefix Oodle 压缩库文件名前缀（版本号随 UE 版本变化，不能穷举）。
const oodleDLLPrefix = "oo2core_"

// dllSniffTTL DLL 嗅探目录缓存有效期；对局中途游戏可能热更新，
// 5 分钟足够覆盖单局生命周期，同时避免磁盘反复 stat。
const dllSniffTTL = 5 * time.Minute

// dllSniffCacheMax 缓存条目上限（防进程名爆炸/路径爆炸导致内存无界增长）。
const dllSniffCacheMax = 512

type dllSniffCacheEntry struct {
	hit bool
	ts  time.Time
}

var (
	dllSniffMu    sync.RWMutex
	dllSniffCache = make(map[string]dllSniffCacheEntry, dllSniffCacheMax)
)

// processBaseName 取进程可执行文件名（小写），兼容传入完整路径或裸名。
func processBaseName(name string) string {
	b := filepath.Base(strings.ToLower(name))
	return b
}

// isAuxProcessName 判定是否辅助/启动器进程（裸名或路径命中 aux 表）。
func isAuxProcessName(name string) bool {
	n := strings.ToLower(name)
	if n == "" {
		return false
	}
	base := processBaseName(n)
	for _, k := range auxProcessKeywords {
		if base == k || base == k+".exe" || strings.Contains(base, k) {
			return true
		}
	}
	for _, k := range auxPathKeywords {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// engineDLLScanDirs 返回需要嗅探的目录集合（去重、保序）：
// 进程所在目录 → 其父目录（UE 常见 <Game>\Binaries\Win64\X-Shipping.exe
// 布局，DLL 在 <Game>\ 或 <Game>\Binaries\Win64\）→ 同目录 Tools 子目录
// （部分工具链把运行库放在 Tools 下）。
func engineDLLScanDirs(dir string) []string {
	dirs := make([]string, 0, 3)
	seen := make(map[string]struct{}, 3)
	for _, d := range []string{dir, filepath.Dir(dir), filepath.Join(dir, "Tools")} {
		if d == "" || d == "." {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		dirs = append(dirs, d)
	}
	return dirs
}

// dirHasOodleDLL 在目录内做一次 oo2core_ 前缀扫描（Oodle 版本号不可穷举）。
// 仅在精确表全未命中、且该目录尚无 5 分钟缓存时调用，不在热路径上。
func dirHasOodleDLL(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(strings.ToLower(e.Name()), oodleDLLPrefix) {
			return true
		}
	}
	return false
}

// dirHasEngineDLL 判定进程所在目录（含父目录/Tools 子目录）是否存在引擎
// 特征 DLL（带 TTL 缓存，缓存键仍为进程所在目录）。
func dirHasEngineDLL(name string) bool {
	n := strings.ToLower(name)
	dir := filepath.Dir(n)
	if dir == "." || dir == "" || dir == n {
		return false
	}
	now := time.Now()
	dllSniffMu.RLock()
	if e, ok := dllSniffCache[dir]; ok && now.Sub(e.ts) < dllSniffTTL {
		dllSniffMu.RUnlock()
		return e.hit
	}
	dllSniffMu.RUnlock()

	dirs := engineDLLScanDirs(dir)
	hit := false
	for _, d := range dirs {
		for _, dll := range gameEngineDLLs {
			if _, err := os.Stat(filepath.Join(d, dll)); err == nil {
				hit = true
				break
			}
		}
		if hit {
			break
		}
	}
	// Oodle 兜底：精确表全未命中时，逐个目录做一次前缀扫描（带 TTL 缓存）。
	if !hit {
		for _, d := range dirs {
			if dirHasOodleDLL(d) {
				hit = true
				break
			}
		}
	}

	dllSniffMu.Lock()
	if len(dllSniffCache) >= dllSniffCacheMax {
		// 满则整表重置：条目都是可重建的廉价事实，重置优于随机淘汰。
		dllSniffCache = make(map[string]dllSniffCacheEntry, dllSniffCacheMax)
	}
	dllSniffCache[dir] = dllSniffCacheEntry{hit: hit, ts: now}
	dllSniffMu.Unlock()
	return hit
}

// isGameProcess 统一游戏进程判定（2026-10-20 识别升级）：
// 判定顺序 aux 排除 → 进程名/目录关键词 → 同目录引擎 DLL 嗅探。
// 返回 (是否游戏, 命中原因)，原因用于注册日志定位（keyword/dll/aux）。
// 与 isGameProcessName 的差别：本函数接受完整路径，且会做一次受缓存
// 约束的磁盘嗅探；isGameProcessName 保持纯内存判定语义不变。
func isGameProcess(name string) (bool, string) {
	if name == "" {
		return false, ""
	}
	if isAuxProcessName(name) {
		return false, "aux"
	}
	n := strings.ToLower(name)
	base := processBaseName(n)
	if base == "code.exe" || base == "code" {
		return false, "vscode"
	}
	if matchGameProcessKeyword(n) {
		return true, "keyword"
	}
	if dirHasEngineDLL(name) {
		return true, "dll"
	}
	return false, ""
}

// isAutoRegCandidate 判定目标 IP/端口是否适合自动注册：
// 仅公网 IPv4（排除私网/环回/链路本地/组播/未指定等）且
// 命中排除层（Discord/Steam/TUN/私网/组播/保留段）的一律跳过，
// 且非大厅/CDN/Steam 探测端口。
func isAutoRegCandidate(metadata *C.Metadata) bool {
	addr := metadata.DstIP
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	if skipAutoRegPorts[metadata.DstPort] {
		return false
	}
	if isExcludedIP(addr) {
		return false
	}
	return addr.IsGlobalUnicast() && !addr.IsPrivate()
}

// RegisterRetryHint 判定该会话首包识别失败是否值得后续持续重试注册。
// 仅当进程反查失败（UDP 表未更新，name==""）且目标本身符合自动注册
// 候选（公网 IPv4、非探测端口、非排除段）时返回 true；明确非游戏进程
// 或注册硬性拒绝（排除段/探测端口/非公网）一律返回 false，避免对
// 明确非游戏流量做无谓重复反查。
// 由 tunnel 层在 selectUDPQueue 首包识别失败后调用，结果写入 laneEntry
// pendingRetry：true 的会话后续每包（500ms 节流）重试 findProcessByPort，
// 查到游戏进程立即注册接管，不等 flow 打分 8 秒。
func (m *Manager) RegisterRetryHint(metadata *C.Metadata, isTUN bool) bool {
	if !m.Enabled() {
		return false
	}
	var name string
	if isTUN {
		_, name = findProcessByPort(metadata)
	} else {
		_, name = findProcess(metadata)
	}
	if name != "" {
		return false
	}
	return isAutoRegCandidate(metadata)
}

// RegisterGameTargetIfNeeded 识别即注册：
// 对局服务器目标在会话首包决策前被识别（进程反查命中游戏进程关键字，
// 目标为公网 UDP 且非探测端口）后，立即注册进内存态目标注册表
// （初始出口=默认出口，非 DIRECT），使该会话首包即命中 GameLane
// 快速通道。GameLane 绝不直连：默认出口缺失时保持上一可用出口或
// 排队等待选路（见 MatchTarget 兜底逻辑）。
// 识别失败/非游戏流量/目标已注册一律返回 false，对默认流程零影响。
// TUN 模式下源 IP 为虚拟网段，按 SrcPort-only 反查 UDP 套接字归属进程
// （修复 APEX 等游戏进程在 TUN 下无法被识别的问题：GetExtendedUdpTable
// 按本地端口匹配真实绑定地址，忽略虚拟源 IP 才拿得到 PID）。
func (m *Manager) RegisterGameTargetIfNeeded(metadata *C.Metadata, isTUN bool) bool {
	if !m.Enabled() {
		return false
	}
	// 铁令 C（2026-10-18 v2.4 批复）：排除端口总闸最顶层——8125 遥测等
	// 一票否决，段表/域名命中也不得注册（Q-I1 调和：总闸先于一切）。
	if IsExcludedAutoRegPort(metadata.DstPort) {
		metricsRegBlockPort.Add(1)
		missRecord("", metadata.DstIP, metadata.DstPort, MissReasonPort) // miss 埋点：端口总闸（反查之前，无身份→<<no_proc>>）
		return false
	}

	// v2.6 联动 B（2026-10-19 终批复）：Fake-IP 防污染——第二刀后主路不回填
	// realIP，fake 会话的 DstIP 是 198.18.x.x（IsValid 为真，段表/域名路径
	// 却会照常走到注册），绝不注册进 targets（v2.3 铁令"绝不把 198.18.x.x
	// 注册成垃圾地址"复活并前移；真实 IP 注册移至赛马旁路 race.go 联动 C）。
	if resolver.IsFakeIP(metadata.DstIP) {
		metricsRegBlockFakeIP.Add(1)
		missRecord("", metadata.DstIP, metadata.DstPort, MissReasonFakeIP) // miss 埋点：Fake-IP 拦截（反查之前，无身份→<<no_proc>>）
		return false
	}

	// 铁律三（2026-10-18 v2.2 批复）：段表命中检查前置到进程反查之前——
	// 段表（含编译内置云段 216.244.0.0/16）命中即同步注册，不需要进程名，
	// 也不承担 findProcessByPort 全表扫描的秒级延迟（游戏数百 UDP socket
	// 实测拖慢首包决策，制造"先建连后补刀 retarget"窗口，code:house 根因
	// 之一）。代价：段表注册路径不做进程名自学习（记忆/flow 打分路径仍可
	// 后续补学）。段表命中后首包即同步注册、当包进 lane，无二次 retarget。
	if metadata.DstIP.IsValid() && SegmentTable().MatchIP(metadata.DstIP) {
		m.MarkGameActive() // v2.4 漏洞三③：段表命中即入临战活跃态（对局首包 0ms 秒接管）
		// 1.3 强制（v2.4 批复）：段表命中第一顺位无条件放行——不看对局端口
		// 段、不看进程反查结果（排除端口已被顶层总闸拦截；10200 等动态
		// 对局端口不被任何白名单口径拦）。trusted=true 顺带豁免黑名单。
		if m.RegisterTargetIPTrusted(metadata.DstIP.String(), true) {
			log.Infoln("[GameLane] segment-register target %s/32 (game segment hit)", metadata.DstIP.String())
			// v2.10 埋点：段表首包注册（低频决策点，进事件环）
			metricsRegSegmentHit.Add(1)
			recordDiagFields("reg_segment", metadata.DstIP.String(), int(metadata.DstPort), "", "segment_table",
				"segment register %s:%d (trusted)", metadata.DstIP.String(), metadata.DstPort)
			return true
		}
		return false
	}
	// 衔接 2（2026-10-18 v2.3 批复）：域名匹配升级为 IsGameDomain——把内置
	// 13 条云后缀（amazonaws.com/api.aws/ea.com/origin.com/respawn.com 等）
	// 一并纳入首包域名自动注册体系；EA QoS ELB 域名不在规则集树，原
	// MatchDomain 口径漏网（首包漏网的另一半原因）。纯内存无锁。
	if metadata.Host != "" && m.IsGameDomain(metadata.Host) && metadata.DstIP.IsValid() {
		m.MarkGameActive() // v2.4 漏洞三②：IsGameDomain 命中即入临战活跃态
		// 1.3 强制（v2.4 批复）：域名命中同段表——第一顺位无条件放行。
		if m.RegisterTargetIPTrusted(metadata.DstIP.String(), true) {
			log.Infoln("[GameLane] segment-register target %s/32 (game domain %s)", metadata.DstIP.String(), metadata.Host)
			// v2.10 埋点：域名命中原生注册（v2.9 新增 8 条云后缀的可观测点）
			metricsRegDomainHit.Add(1)
			recordDiagFields("reg_domain", metadata.DstIP.String(), int(metadata.DstPort), "", metadata.Host,
				"domain register %s:%d host=%s", metadata.DstIP.String(), metadata.DstPort, metadata.Host)
			return true
		}
		return false
	}

	var name string
	if isTUN {
		_, name = findProcessByPort(metadata)
	} else {
		_, name = findProcess(metadata)
	}

	if name == "" {
		metricsRegBlockUnknownPID.Add(1)
		missRecord("", metadata.DstIP, metadata.DstPort, MissReasonUnknownPID) // miss 埋点：反查无 PID→<<unknown_pid>>
		return false
	}
	isGame, reason := isGameProcess(name)
	if !isGame {
		metricsRegBlockNotGame.Add(1)
		missRecord(name, metadata.DstIP, metadata.DstPort, missReasonForIdent(reason)) // miss 埋点：非游戏（reason 空→unrecognized，aux/vscode→aux）
		return false
	}
	if !isAutoRegCandidate(metadata) {
		metricsRegBlockExcluded.Add(1)
		missRecord(name, metadata.DstIP, metadata.DstPort, missReasonForCandidate(metadata)) // miss 埋点：游戏进程被排除层/端口拦（excluded/port）
		return false
	}
	// 进程确认路径同属铁令 A trusted 来源（游戏进程名确认）。
	if m.RegisterTargetIPTrusted(metadata.DstIP.String(), true) {
		// 进程名自学习：识别即注册的目标，把反查到的进程名写进记忆
		// （零名单：进程名是运行时学来的事实，不是内置名单；重启后
		// 同进程流量秒识别 + 进程级保活）。
		m.rememberProcessName(metadata.DstIP.String(), name)
		// v2.10 埋点：进程名确认注册（29 条关键词是否真正吃到流量）
		metricsRegProcHit.Add(1)
		// v2.10 识别升级：注册日志带命中原因（keyword/dll），便于线上定位
		// 是词条命中还是 DLL 嗅探命中。
		log.Infoln("[GameLane] process-register target %s/32 (proc=%s reason=%s)", metadata.DstIP.String(), name, reason)
		recordDiagFields("reg_proc", metadata.DstIP.String(), int(metadata.DstPort), "", name,
			"process register %s:%d proc=%s reason=%s", metadata.DstIP.String(), metadata.DstPort, name, reason)
		return true
	}
	return false
}
