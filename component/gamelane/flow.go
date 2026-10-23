package gamelane

import (
	"math"
	"net/netip"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// UDP 流特征自动识别（零名单）：
// 不依赖进程名/游戏名单，仅凭出站 UDP 流的统计特征判定目标是否游戏对局服务器。
// 判定通过后立即注册进内存态目标注册表（auto 主节点），与进程名识别殊途同归。
// 特征依据：主流网游（APEX/PUBG/CS2/Valorant 等）对局同步流量均为
// 持续、高频、双向的小 UDP 包（几十~几百字节），与 DNS/视频/文件传输的
// 统计特征显著不同。

const (
	// flowObserveMinPackets 观察窗口内最少出站包数（高频交互）。
	flowObserveMinPackets = 20
	// flowObserveMinDurationMs 流持续最短时长（观察窗口≥5s，避免单次查询误判；
	// 5s 窗口可覆盖游戏对局同步的持续高频特征，同时拉开与一次性查询/探测的差距）。
	flowObserveMinDurationMs = 5000
	// flowObserveMaxIdleMs 流空闲上限：超过视为流结束，条目清理。
	flowObserveMaxIdleMs = 15000
	// flowMinPayload / flowMaxPayload 游戏同步包典型载荷区间（字节）。
	flowMinPayload = 20
	flowMaxPayload = 500
	// flowSmallPayloadRatio 小包占比下限：窗口内典型同步包占比不足则不判游戏。
	flowSmallPayloadRatio = 0.6
	// flowMaxEntries 观察表条目上限，超出时按空闲时间清理防内存膨胀。
	flowMaxEntries = 10000
	// flowScoreHigh 置信度高分阈值：达到即直接注册（无需升级观察）。
	flowScoreHigh = 80
	// flowScoreSuspect 置信度疑似阈值：[suspect, high) 只标记疑似不注册，
	// 需连续 flowPromoteWindows 个观察窗口分数上升才升级注册。
	flowScoreSuspect = 60
	// flowPromoteWindows 疑似升级所需的连续上升窗口数。
	flowPromoteWindows = 3
	// flowScoreMinEvalGapMs 两次打分评估的最小间隔，避免每包重复评估。
	flowScoreMinEvalGapMs = 500
	// flowApexPortBonus 目的端口辅助加分：命中已知 APEX 对局 UDP 端口段
	// （1024-1124/9960-9969/37000-37015）时加权加分。端口维度即强证据，
	// 弱化对包型统计的依赖，让端口特征明显但对局包型略偏的流也能过线注册。
	flowApexPortBonus = 15
)

// flowSkipPorts 已知非游戏 UDP 服务端口（F10 端口归一：与 autoreg.skipAutoRegPorts
// 同一张表，本变量即其别名，消除双表漂移）。这些端口的流量即使呈"高频小包"
// 也是 DNS/时钟/STUN/QUIC 网页视频等系统或应用流量，一律排除。
// 注意：27022 属 APEX 对局端口段 27015-27060，红线要求必须注册，曾误加进本表
// （2026-10-16 诊断 RC10，已移除）；8125（APEX 遥测 StatsD）按确认加入排除。
var flowSkipPorts = skipAutoRegPorts

// flowStat 单个目标 (IP:Port) 的轻量流统计。
type flowStat struct {
	firstTS       int64   // 首包时间（UnixMilli）
	lastTS        int64   // 最近出站包时间
	prevTS        int64   // 上一出站包时间（包间隔统计用）
	packets       int     // 出站包总数（客户端→服务器，c2s）
	s2c           int     // 服务器→客户端回复包总数（由 ObserveUDPReply 补充）
	small         int     // 典型游戏同步包（载荷在 [min,max] 区间）数量
	intervalSum   int64   // 出站包间隔总和
	intervalSqSum float64 // 出站包间隔平方和（方差计算用）
	intervalCount int     // 出站包间隔样本数
	lastScoreTS   int64   // 上次打分评估时间（节流用）
	scores        []int   // 各观察窗口置信度分数历史（保留最近若干条）
}

// isKnownGamePort 命中已知游戏对局 UDP 端口段。命中时视为强信号，
// 可免双向对称性要求"快速注册"；未命中则必须满足全部特征（含对称性）。
// 排除端口（flowSkipPorts）优先级更高，调用方先查排除端口再查本函数。
func isKnownGamePort(port uint16) bool {
	var hit bool
	switch {
	case port >= 1024 && port <= 1124: // APEX 主同步
		hit = true
	case port >= 9960 && port <= 9969: // APEX 备用
		hit = true
	case port >= 37000 && port <= 37015: // APEX 对局
		hit = true
	case port >= 27000 && port <= 27200: // PUBG/Steam 游戏端口段
		hit = true
	// ---- v2.9 P2（2026-10-19 批复）：非亚太引擎系对局端口 ----
	// 注意：5000-5500（Valorant）刻意不在本表——防 UPnP/NAS/Synology 5000
	// 端口误加分（裁决 3）；Valorant 由 valorant/vgk/vanguard 进程门禁覆盖。
	case port == 3724: // 暴雪 Battle.net 对局
		hit = true
	case port == 6113: // 育碧/Uplay 对局
		hit = true
	case port == 3074: // COD / Xbox Live 对局
		hit = true
	case port >= 26503 && port <= 36503: // OW2/COD 宽动态对局段
		hit = true
	}
	if hit {
		// v2.10 埋点：flow 打分强信号命中数（atomic，零分配，热路径安全）
		metricsKnownPortHit.Add(1)
	}
	return hit
}

// flowSymmetricRatioMin / Max 双向对称性要求：客户端→服务器 与
// 服务器→客户端 包数比例必须落在 [0.3, 3] 内才判定为游戏对局流量。
// 下载/流媒体等严重不对称（单向大流量）流量直接排除。
const (
	flowSymmetricRatioMin = 0.3
	flowSymmetricRatioMax = 3.0
)

// processGate 进程门禁：注册前查进程。进程反查存在且命中 aux 表
// （启动器/浏览器/IM/下载器/播放器/系统进程）→ 一票否决拒绝注册（score 置 0），
// 防 msedge / QQMusic / Discord / Steam 等常驻流量污染游戏目标与 A 类记忆。
//
// 2026-10-21 无词表通用识别：原判定为 !isGameProcessName(name)，要求进程名
// 命中词表，导致无词条的冷门/平台外游戏被误拒。改为只做 aux 黑名单否决，
// 未知进程一律放行，交由 ObserveUDPFlow 的流量特征（对称性/小包占比/
// 连续窗口打分）兜底；aux 表同时补齐浏览器/播放器/IM，防止误放。
// 反查不到（未知进程）→ 返回 true 按原打分逻辑继续。
// 仅注册动作前调用（频率低：新目标确认注册时），避免每包反查开销。
func processGate(metadata *C.Metadata) bool {
	name := procNameForMetadata(metadata)
	if name != "" && isAuxProcessName(name) {
		log.Infoln("[GameLane] process-gate reject %s (proc=%s)", metadata.DstIP.String(), name)
		return false
	}
	return true
}

// ObserveUDPFlow 每个出站 UDP 包调用一次：喂入目标流统计，当统计满足
// 游戏对局特征时自动注册目标。返回 true 表示本次调用新注册了一个目标
// （调用方应触发 UDP 会话重评估）；false 表示未注册（含已注册/非候选）。
func (m *Manager) ObserveUDPFlow(metadata *C.Metadata, payloadLen int) bool {
	if !m.Enabled() {
		return false
	}
	// P0-2 入口分母：GameLane 激活态流经的 UDP 包总数（含后续被闸门拒绝的），
	// 用于回答"流量到底进没进内核"——只做 atomic 自增，零锁零分配。
	metricsObservedFlowTotal.Add(1)

	// fakeCN 反悔接管观察窗记账（v2.12 清单5）：观察窗内目标每包一次 map
	// 查找（无观察窗时走 atomic 计数短路），达判据即反悔接管并返回 true
	// 触发调用方重评估 UDP 会话。判定逻辑见 fakecn.go。
	if m.fakeCNAccountOutbound(metadata.DstIP.String(), metadata.DstPort) {
		return true
	}

	if !isAutoRegCandidate(metadata) {
		return false
	}
	if flowSkipPorts[metadata.DstPort] {
		return false
	}

	// 自学习记忆秒识别：重启后首个数据包即查记忆（active 且距最后命中
	// <24h 才可用），命中则直接注册并返回，跳过完整观察期/打分期——
	// 实现"第二次秒识别"（记忆在注册时写入，跨重启持久化）。
	if memKey, ok := m.lookupMemory(metadata.DstIP.String(), metadata.DstPort); ok {
		// 进程门禁：记忆命中同样先查进程——历史污染记忆（msedge/QQMusic）
		// 在进程门禁下不再秒识别。
		if !processGate(metadata) {
			return false
		}
		ip := metadata.DstIP.String()
		if m.RegisterTargetIP(ip) {
			log.Infoln("[GameLane] memory-hit instant-register %s (mem=%s)", ip, memKey)
			return true
		}
		// 国内直连判定拒绝注册时为游戏进程登记反悔观察窗（v2.12 清单5）。
		m.noteDomesticDirect(ip, metadata.DstPort, procNameForMetadata(metadata))
		return false
	}

	now := time.Now().UnixMilli()
	key := metadata.DstIP.String() + ":" + strconv.Itoa(int(metadata.DstPort))

	// 已注册目标：不进观察表，仅更新动态监视（watch），并即时检查
	// 大包下载/单向流/本地端口跳变等非对局特征，命中即自动淘汰。
	if m.observeWatch(metadata, payloadLen) {
		return false
	}

	m.flowsMu.Lock()
	defer m.flowsMu.Unlock()

	// 懒清理：观察表接近上限时先剔除空闲超时的流；仍不达标则按最近包
	// 时间淘汰最老条目，保证后续插入后条目数不超过上限、内存有界。
	if len(m.flows) >= flowMaxEntries {
		for k, s := range m.flows {
			if now-s.lastTS > flowObserveMaxIdleMs {
				delete(m.flows, k)
			}
		}
		for len(m.flows) >= flowMaxEntries {
			var oldKey string
			var oldTS int64 = 1<<63 - 1
			for k, s := range m.flows {
				if s.lastTS < oldTS {
					oldTS = s.lastTS
					oldKey = k
				}
			}
			delete(m.flows, oldKey)
		}
	}

	st, ok := m.flows[key]
	if !ok {
		st = &flowStat{firstTS: now, lastTS: now, prevTS: now}
		m.flows[key] = st
	}
	st.lastTS = now
	st.packets++
	if payloadLen >= flowMinPayload && payloadLen <= flowMaxPayload {
		st.small++
	}
	if st.prevTS != 0 {
		if gap := now - st.prevTS; gap > 0 {
			st.intervalCount++
			st.intervalSum += gap
			st.intervalSqSum += float64(gap) * float64(gap)
		}
	}
	st.prevTS = now

	dur := st.lastTS - st.firstTS
	if dur < flowObserveMinDurationMs || st.packets < flowObserveMinPackets {
		return false
	}

	// 命中已知游戏端口段：强信号快速注册（时长/包数/小包占比达标即注册，
	// 免打分、免对称性）。未命中则走置信度打分制。
	if isKnownGamePort(metadata.DstPort) {
		if float64(st.small)/float64(st.packets) < flowSmallPayloadRatio {
			return false
		}
		// 进程门禁：注册前查进程，非游戏进程（浏览器/播放器）一票否决。
		if !processGate(metadata) {
			delete(m.flows, key)
			return false
		}
		delete(m.flows, key)
		ip := metadata.DstIP.String()
		if !m.RegisterTargetIP(ip) {
			// 国内直连判定拒绝注册时为游戏进程登记反悔观察窗（v2.12 清单5）。
			m.noteDomesticDirect(ip, metadata.DstPort, procNameForMetadata(metadata))
			return false
		}
		m.remember(ip, metadata.DstPort)
		// 进程名自学习：反查源端口归属进程写入记忆（失败留空，不影响注册）。
		m.rememberProcessName(ip, procNameForMetadata(metadata))
		log.Infoln("[GameLane] flow-observe auto-register %s (known-port pkts=%d dur=%dms small=%d/%d)",
			ip, st.packets, dur, st.small, st.packets)
		return true
	}

	// 置信度打分制：四维打分（双向对称性/包间隔稳定性/包长集中度/会话时长）。
	// 高 → 直接注册；中 → 疑似，连续 3 窗口分数上升才升级；低 → 忽略并逐步清理。
	// lastScoreTS==0 表示自上次评估后有新回复包到达（节流已解除），立即重评。
	if st.lastScoreTS != 0 && now-st.lastScoreTS < flowScoreMinEvalGapMs {
		return false
	}
	st.lastScoreTS = now
	score := scoreFlow(st, metadata.DstPort)
	st.scores = append(st.scores, score)
	if len(st.scores) > flowPromoteWindows+1 {
		st.scores = st.scores[len(st.scores)-(flowPromoteWindows+1):]
	}

	ip := metadata.DstIP.String()
	switch {
	case score >= flowScoreHigh:
		// 进程门禁：注册前查进程，非游戏进程（浏览器/播放器）一票否决。
		if !processGate(metadata) {
			delete(m.flows, key)
			return false
		}
		delete(m.flows, key)
		// 铁令 C（v2.4）：排除端口遥测流不注册（8125 单向流假丢包污染评分）
		if IsExcludedAutoRegPort(metadata.DstPort) {
			return false
		}
		if !m.RegisterTargetIPTrusted(ip, SegmentTable().MatchIP(metadata.DstIP)) {
			// 国内直连判定拒绝注册时为游戏进程登记反悔观察窗（v2.12 清单5）。
			m.noteDomesticDirect(ip, metadata.DstPort, procNameForMetadata(metadata))
			return false
		}
		m.remember(ip, metadata.DstPort)
		// 进程名自学习：反查源端口归属进程写入记忆（失败留空，不影响注册）。
		m.rememberProcessName(ip, procNameForMetadata(metadata))
		log.Infoln("[GameLane] flow-score auto-register %s (score=%d pkts=%d s2c=%d dur=%dms)",
			ip, score, st.packets, st.s2c, dur)
		return true
	case score >= flowScoreSuspect:
		// 疑似：不注册，继续观察。连续 3 个观察窗口分数严格上升才升级注册。
		n := len(st.scores)
		if n >= flowPromoteWindows &&
			st.scores[n-1] > st.scores[n-2] && st.scores[n-2] > st.scores[n-3] {
			// 进程门禁：升级注册前查进程，非游戏进程一票否决。
			if !processGate(metadata) {
				delete(m.flows, key)
				return false
			}
			delete(m.flows, key)
			// 铁令 C（v2.4）：排除端口遥测流不注册（promote 路径同门槛）
			if IsExcludedAutoRegPort(metadata.DstPort) {
				return false
			}
			if !m.RegisterTargetIPTrusted(ip, SegmentTable().MatchIP(metadata.DstIP)) {
				// 国内直连判定拒绝注册时为游戏进程登记反悔观察窗（v2.12 清单5）。
				m.noteDomesticDirect(ip, metadata.DstPort, procNameForMetadata(metadata))
				return false
			}
			m.remember(ip, metadata.DstPort)
			// 进程名自学习：反查源端口归属进程写入记忆（失败留空，不影响注册）。
			m.rememberProcessName(ip, procNameForMetadata(metadata))
			log.Infoln("[GameLane] flow-suspect promote %s (scores=%v pkts=%d s2c=%d)",
				ip, st.scores, st.packets, st.s2c)
			return true
		}
		// P0-1：疑似分但连续 3 个窗口未严格上升 → 记录"打分不够"。
		// 上方 flowScoreMinEvalGapMs 已保证每评估周期最多一次，无需额外节流。
		missRecordFlow(procNameForMetadata(metadata), metadata.DstIP, metadata.DstPort, score, flowScoreSuspect)
		return false
	default:
		// 低分忽略：连续 flowPromoteWindows 个窗口均低于疑似线则清理观察条目。
		n := len(st.scores)
		if n >= flowPromoteWindows {
			stale := true
			for i := n - flowPromoteWindows; i < n; i++ {
				if st.scores[i] >= flowScoreSuspect {
					stale = false
					break
				}
			}
			if stale {
				delete(m.flows, key)
			}
		}
		// P0-1：低分直接忽略 → 记录 score 与疑似线，让"差多少分"可见。
		missRecordFlow(procNameForMetadata(metadata), metadata.DstIP, metadata.DstPort, score, flowScoreSuspect)
		return false
	}
}

// ObserveUDPReply 每个服务器→客户端回复包调用一次：补充目标流双向对称
// 计数（s2c），供 ObserveUDPFlow 的对称性判定使用。只更新已有观察条目，
// 不新建条目、不触发注册判定（判定统一由出站方向触发，避免重入竞态）。
// 刻意不刷新 lastTS：若出站包已停止、仅回复方向仍在涌流（下载/流媒体
// 单向大流量），条目会按空闲超时被懒清理，恰好符合排除预期。
func (m *Manager) ObserveUDPReply(src netip.AddrPort, payloadLen int) {
	if !m.Enabled() {
		return
	}
	addr := src.Addr().Unmap()
	if !addr.IsValid() || !addr.Is4() || isExcludedIP(addr) {
		return
	}
	// 已注册目标：先更新动态监视（watch），具备对局特征则刷新保留证据；
	// 命中非对局特征（大包下载/单向流/端口跳变）时内部直接自动淘汰。
	m.observeWatchReply(addr, src.Port(), payloadLen)

	// fakeCN 反悔接管观察窗回包记账（v2.12 清单5）：记录回包存在性与
	// 实测直连最小 RTT，供"高延迟/零回包"反悔判据使用。
	m.fakeCNAccountReply(addr.String())

	key := addr.String() + ":" + strconv.Itoa(int(src.Port()))

	m.flowsMu.Lock()
	defer m.flowsMu.Unlock()
	st, ok := m.flows[key]
	if !ok {
		return // 无出站观察条目（流非候选/已判定），忽略
	}
	st.s2c++
	// 新回复包到达：解除打分节流（lastScoreTS=0），下次出站包立即重新评估，
	// 使"补足对称性后应注册"类时序即时生效，而非等到 500ms 节流窗口过后。
	if st.lastScoreTS != 0 {
		st.lastScoreTS = 0
	}
}

// scoreFlow 四维置信度打分（0-100）：双向对称性 / 包间隔稳定性 /
// 包长分布集中度 / 会话时长，各 25 分。替换"一刀切是/否"判定，
// 高(≥80)→直接注册；中(≥60)→疑似继续观察；低(<60)→忽略。
// port 为出站目的端口：命中已知游戏对局端口段（APEX 等）时加权加分。
// 端口辅助只做正向加权，不覆盖排除逻辑——命中排除段（Discord/Steam/
// TUN/89.222/组播/RFC1918/DNS/NTP/STUN/mDNS/SSDP/443 等）的流在
// isAutoRegCandidate 与 RegisterTargetIP 处已被先行拒绝，到不了打分环节。
func scoreFlow(st *flowStat, port uint16) int {
	// 1) 双向对称性（0-25）：c2s 与 s2c 包数比越接近 1 越好。
	// 严重不对称（下载/流媒体单向流）得分趋近 0，直接拉低总分。
	symScore := 0
	if st.s2c > 0 && st.packets > 0 {
		ratio := float64(st.packets) / float64(st.s2c)
		r := ratio
		if r > 1 {
			r = 1 / r
		}
		switch {
		case r >= 0.5:
			symScore = 25
		case r >= 0.3:
			symScore = 15 + int((r-0.3)/0.2*10) // 0.3→15, 0.5→25
		default:
			symScore = int(r / 0.3 * 15) // 0→0, 0.3→15
		}
	}

	// 2) 包间隔稳定性（0-25）：固定频率同步（游戏心跳）CV 极小得高分；
	// 突发/杂乱流量（视频缓冲、随机探测）CV 大得低分。样本不足给中性分。
	intScore := 12
	if st.intervalCount >= 3 {
		mean := float64(st.intervalSum) / float64(st.intervalCount)
		if mean > 0 {
			v := st.intervalSqSum/float64(st.intervalCount) - mean*mean
			if v < 0 {
				v = 0
			}
			cv := math.Sqrt(v) / mean
			switch {
			case cv <= 0.4:
				intScore = 25
			case cv <= 1.0:
				intScore = 25 - int((cv-0.4)/0.6*15)
			case cv <= 2.0:
				intScore = 10 - int((cv-1.0)/1.0*10)
			default:
				intScore = 0
			}
		}
	}

	// 3) 包长分布集中度（0-25）：典型游戏同步小包占比越高得分越高；
	// 混合大包（下载/视频/文件传输）占比升高得分骤降。
	lenScore := 0
	if st.packets > 0 {
		r := float64(st.small) / float64(st.packets)
		switch {
		case r >= 0.9:
			lenScore = 25
		case r >= 0.6:
			lenScore = 15 + int((r-0.6)/0.3*10) // 0.6→15, 0.9→25
		case r >= 0.3:
			lenScore = int(r / 0.6 * 15) // 0.3→7, 0.6→15
		default:
			lenScore = int(r / 0.3 * 5) // 0→0, 0.3→5
		}
	}

	// 4) 会话时长（0-25）：持续越久越像游戏对局（长会话），短查询/探测低分。
	// 注意用浮点除法：整数除法会让 5s~15s 区间全部截断为 10 分。
	dur := st.lastTS - st.firstTS
	durScore := 0
	switch {
	case dur >= 15000:
		durScore = 25
	case dur >= flowObserveMinDurationMs:
		durScore = 10 + int(float64(dur-flowObserveMinDurationMs)/10000*15) // 5s→10, 15s→25
	case dur > 0:
		durScore = int(float64(dur) / float64(flowObserveMinDurationMs) * 10)
	}

	score := symScore + intScore + lenScore + durScore
	// 端口辅助加权：命中已知游戏对局 UDP 端口段（APEX 1024-1124/9960-9969/
	// 37000-37015 及 PUBG/Steam 27000-27200）视为强端口证据，加分过线。
	if isKnownGamePort(port) {
		score += flowApexPortBonus
		if score > 100 {
			score = 100
		}
	}
	// 端口维度压制：TCP 443/80（下载 / CDN 特征）score 压低 <60 不注册。
	// 该端口组合是网页下载/视频/CDN 流量的典型特征，即使包型统计
	// 偶发接近游戏（高频小包），也强制压到疑似线以下，杜绝误圈。
	if port == 443 || port == 80 {
		if score > 30 {
			score = 30
		}
	}
	return score
}
