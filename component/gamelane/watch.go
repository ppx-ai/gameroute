package gamelane

import (
	"net/netip"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// 已注册目标动态验证 + 自动淘汰（注册不是永久，可自我纠错）：
// 自动注册（流特征/进程识别）进入目标注册表后，由 watch 持续监视其流量。
// 具备"高频、双向、小包、本地端口固定、长会话"对局特征 → 确认保留；
// 出现大包下载、单向流、本地端口跳变、流量停止 → 自动移除注册。
// 清理判据（v3 进程级保活）：优先看游戏进程是否还活着（RFC 4787 要求
// UDP 会话超时 ≥2 分钟；UU/迅游均以进程生命周期管理加速目标）——
//
//	有进程名且进程存活 → 不淘汰（无论流量静默多久）；
//	有进程名但进程已退出 → 立即清理（真正的游戏结束信号）；
//	无进程名（纯 flow-score 识别的无进程来源目标）→ 3 分钟 idle 兜底。
const (
	// watchCleanAfterMs 无进程名来源目标 3 分钟无对局特征流量 → 自动清理。
	// 3 分钟 ≥ RFC 4787 的 2 分钟行业底线，覆盖训练场 60s 心跳脉冲 +
	// 对局中菜单 / 死亡等待间隙。有进程名且进程存活的目标不适用此阈值。
	watchCleanAfterMs = 3 * 60 * 1000
	// watchDeadAfterMs 双向流量均停止超过 3 分钟 → 视为会话死亡，移除注册
	// （仅作用于无进程名来源目标；有进程名目标由进程存活判定保活）。
	watchDeadAfterMs = 3 * 60 * 1000
	// watchBigRatio 大包（>500B）占比超过该比例且数量达标 → 下载/流媒体特征。
	watchBigRatio = 0.5
	// watchBigMin 大包计数下限，避免个别偶发大包误杀。
	watchBigMin = 5
	// watchNoReplyMs 出站持续活跃但该时长内无回复 → 单向流特征。
	watchNoReplyMs = 30 * 1000
	// watchSrcPortLimit 本地端口集合超过 1 → 端口跳变（非固定对局会话）。
	watchSrcPortLimit = 2
)

// watchStat 单个已注册目标的动态监视状态。key 为目标 IP。
type watchStat struct {
	ip           string
	registeredAt int64
	lastMatchTS  int64 // 最后"对局特征"活动时间：高频小包且双向有来有回
	lastC2STS    int64 // 最后出站包时间（任何载荷）
	lastReplyTS  int64 // 最后回复包时间（任何载荷）
	c2s          int   // 出站包数
	s2c          int   // 回复包数
	small        int   // 典型小包（[min,max]）数
	big          int   // 大包（>max）数
	srcPorts     map[uint16]struct{}
}

func newWatchStat(ip string) *watchStat {
	return &watchStat{
		ip:           ip,
		registeredAt: time.Now().UnixMilli(),
		srcPorts:     make(map[uint16]struct{}),
	}
}

// observeWatch 出站方向监视已注册目标：更新对局特征统计并做即时淘汰检查。
// 返回 true 表示目标仍处于已注册状态（调用方不应再走流特征观察）；
// 返回 false 表示目标刚被自动淘汰（可重新进入观察流程）或本就不是已注册目标。
func (m *Manager) observeWatch(metadata *C.Metadata, payloadLen int) bool {
	addr := metadata.DstIP
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	ip := addr.String()

	m.watchesMu.Lock()
	st, ok := m.watches[ip]
	if !ok {
		m.watchesMu.Unlock()
		return false
	}
	now := time.Now().UnixMilli()
	st.lastC2STS = now
	st.c2s++
	if payloadLen >= flowMinPayload && payloadLen <= flowMaxPayload {
		st.small++
		if st.s2c > 0 {
			st.lastMatchTS = now
		}
	} else if payloadLen > flowMaxPayload {
		st.big++
	}
	st.srcPorts[metadata.SrcPort] = struct{}{}
	drop := m.watchShouldDropLocked(st)
	m.watchesMu.Unlock()

	if drop != "" {
		m.evictWatch(ip, drop)
		return false
	}
	return true
}

// observeWatchReply 回复方向监视已注册目标：对称性计数与对局特征刷新。
func (m *Manager) observeWatchReply(addr netip.Addr, port uint16, payloadLen int) bool {
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	ip := addr.String()

	m.watchesMu.Lock()
	st, ok := m.watches[ip]
	if !ok {
		m.watchesMu.Unlock()
		return false
	}
	now := time.Now().UnixMilli()
	st.lastReplyTS = now
	st.s2c++
	if payloadLen >= flowMinPayload && payloadLen <= flowMaxPayload {
		st.small++
		if st.c2s > 0 {
			st.lastMatchTS = now
		}
	}
	drop := m.watchShouldDropLocked(st)
	m.watchesMu.Unlock()

	if drop != "" {
		m.evictWatch(ip, drop)
		return false
	}
	return true
}

// watchShouldDropLocked 即时淘汰检查（需持 watchesMu）。返回非空原因即应淘汰。
func (m *Manager) watchShouldDropLocked(st *watchStat) string {
	// 铁令 A（2026-10-18 v2.4 批复）：段表命中/游戏进程名目标受保护——
	// 大包下载/单向流/端口跳变三类启发式严禁触发（对局加载地图的大包
	// 会被误判为下载流量并写 24h 黑名单，误杀对局服务器）。
	if m.isProtectedTarget(st.ip) {
		return ""
	}
	now := time.Now().UnixMilli()
	if len(st.srcPorts) >= watchSrcPortLimit {
		// 游戏进程豁免：命中游戏关键字（CS2/Valorant 等使用动态本地端口、
		// 但对局会话固定）的本地端口跳变不淘汰；非游戏进程（下载器/CDN
		// 客户端多端口并发）仍按端口跳变淘汰。
		if !isGameProcessName(m.lookUpProcessName(st.ip)) {
			return "local-port-flap"
		}
	}
	if st.big >= watchBigMin && float64(st.big) >= watchBigRatio*float64(st.c2s) {
		return "large-packet-download"
	}
	if st.c2s >= flowObserveMinPackets && st.lastReplyTS > 0 && now-st.lastReplyTS > watchNoReplyMs {
		return "one-way-flow"
	}
	return ""
}

// evictWatch 移除注册 + 清理监视条目（自动淘汰出口）。
// v4 A/B 类规则：
//   - 硬性异常（大包下载/单向流/端口跳变）：一律 forget + 写入临时黑名单（24h 内拒绝再注册），黑名单命中打日志。
//   - idle/dead-cleanup / process-exited：A 类不调 forget（长期保留）；B 类降权 decay。
func (m *Manager) evictWatch(ip, reason string) {
	// 临时黑名单：硬性异常淘汰一律写入，24h 内 RegisterTargetIP/记忆命中拒绝。
	if reason == "large-packet-download" || reason == "one-way-flow" || reason == "local-port-flap" {
		m.writeBlacklistLocked(ip)
		m.forget(ip)
	}

	m.unregisterTarget(ip, false)
	m.forgetWatch(ip)

	// idle/dead-cleanup / process-exited：A 类不降权（不调 forget）；
	// B 类降权——当前 evictWatch 中 idle/dead-cleanup 不会走到这里（
	// sweepWatches 中 processKeepAlive 已过滤掉），process-exited 同理。
	log.Infoln("[GameLane] watch evict %s: %s", ip, reason)
}

// forgetWatch 删除监视条目（不操作注册表）。
func (m *Manager) forgetWatch(ip string) {
	m.watchesMu.Lock()
	delete(m.watches, ip)
	m.watchesMu.Unlock()
}

// processKeepAlive 进程级保活判定（sweepWatches 淘汰前调用）：
// 记忆条目携带进程名 → 查系统进程表：
//   - 进程存活 → keepAlive=true（游戏进程还在，无论流量静默多久都不淘汰）
//   - 进程已退出 → keepAlive=false 且 hasProc=true（真正的游戏结束信号，
//     交由 evictWatch 立即清理，且不降权记忆——下次启动同进程还会学回来）
//
// 无进程名（纯 flow-score 识别的无进程来源目标）→ hasProc=false，
// 走 idle 兜底阈值（watchCleanAfterMs / watchDeadAfterMs）。
func (m *Manager) processKeepAlive(ip string) (keepAlive bool, hasProc bool) {
	procName := m.lookUpProcessName(ip)
	if procName == "" {
		return false, false
	}
	hasProc = true
	if !processAliveByName(procName) {
		log.Infoln("[GameLane] process-exited detect %s (proc=%s gone)", ip, procName)
		return false, true
	}
	log.Debugln("[GameLane] process keep-alive %s (proc=%s alive)", ip, procName)
	return true, true
}

// sweepWatches 周期清扫：无进程名来源目标超过 watchCleanAfterMs 无对局
// 特征流量自动清理；双向流量均停止超过 watchDeadAfterMs 视为会话死亡移除。
// 有进程名且进程存活的目标保活（不受任何静默时长限制）；有进程名但进程
// 已退出的目标立即清理。
func (m *Manager) sweepWatches() {
	now := time.Now().UnixMilli()
	m.watchesMu.Lock()
	var evict []string
	for ip, st := range m.watches {
		if now-st.lastMatchTS > watchCleanAfterMs {
			evict = append(evict, ip)
			continue
		}
		if st.lastC2STS > 0 && now-st.lastC2STS > watchDeadAfterMs &&
			(st.lastReplyTS == 0 || now-st.lastReplyTS > watchDeadAfterMs) {
			evict = append(evict, ip)
		}
	}
	m.watchesMu.Unlock()
	for _, ip := range evict {
		// 铁令 A（v2.4）：protected 目标仅保留 process-exited 清理；
		// 段表命中且无进程名可查 → 长期保留（对局服务器段秒识别收益
		// 大于清理，且不写黑名单）。
		if m.isProtectedTarget(ip) && !m.processNamedTarget(ip) {
			continue
		}
		keep, hasProc := m.processKeepAlive(ip)
		if keep {
			continue // 游戏进程存活：不淘汰（无论流量静默多久）
		}
		reason := "idle/dead-cleanup"
		if hasProc {
			reason = "process-exited" // 有进程名但已退出：真正的游戏结束信号
		}
		m.evictWatch(ip, reason)
	}
}

var watchSweepOnce = new(sync.Once)

// blacklistEntry 临时黑名单条目（硬性异常淘汰后写入，24h 自动过期）。
type blacklistEntry struct {
	until int64 // UnixMilli 到期时间
}

// writeBlacklistLocked 写入临时黑名单（须持有 m.mu）。24h 后自动过期。
func (m *Manager) writeBlacklistLocked(ip string) {
	if m.blacklist == nil {
		m.blacklist = make(map[string]blacklistEntry)
	}
	m.blacklist[ip] = blacklistEntry{
		until: time.Now().UnixMilli() + 24*3600*1000,
	}
	log.Infoln("[GameLane] blacklist write %s (until %s)", ip, time.UnixMilli(m.blacklist[ip].until).Format("2006-01-02 15:04:05"))
}

// isBlacklisted 检查 IP 是否在临时黑名单中。返回 true 且在 until 之后过期。
func (m *Manager) isBlacklisted(ip string) (blacklisted bool, until string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.blacklist[ip]; ok {
		if time.Now().UnixMilli() >= entry.until {
			// 已过期，清理
			delete(m.blacklist, ip)
			return false, ""
		}
		return true, time.UnixMilli(entry.until).Format("2006-01-02 15:04:05")
	}
	return false, ""
}

// removeBlacklist 铁令 A（v2.4）：trusted 注册时从黑名单移除（须持 m.mu），
// 防 watch 历史误杀把对局服务器 24h 永久拉黑。
func (m *Manager) removeBlacklist(ip string) {
	m.mu.Lock()
	delete(m.blacklist, ip)
	m.mu.Unlock()
}

// isProtectedTarget 铁令 A 判定：游戏进程名记忆或段表命中 → true。
func (m *Manager) isProtectedTarget(ip string) bool {
	if name := m.lookUpProcessName(ip); name != "" && isGameProcessName(name) {
		return true
	}
	if addr, err := netip.ParseAddr(ip); err == nil && SegmentTable().MatchIP(addr) {
		return true
	}
	return false
}

// processNamedTarget 目标是否携带游戏进程名（process-exited 清理判定用）。
func (m *Manager) processNamedTarget(ip string) bool {
	name := m.lookUpProcessName(ip)
	return name != "" && isGameProcessName(name)
}

// sweepBlacklist 清理过期黑名单条目。
func (m *Manager) sweepBlacklist() {
	now := time.Now().UnixMilli()
	m.mu.Lock()
	if m.blacklist == nil {
		m.mu.Unlock()
		return
	}
	for ip, entry := range m.blacklist {
		if now >= entry.until {
			delete(m.blacklist, ip)
			log.Infoln("[GameLane] blacklist expired %s", ip)
		}
	}
	m.mu.Unlock()
}

// startWatchSweeper 启动全局周期清扫 goroutine（60s 一次），只针对
// defaultManager；测试中的独立 Manager 实例自行调用 sweepWatches。
func startWatchSweeper() {
	watchSweepOnce.Do(func() {
		go func() {
			t := time.NewTicker(60 * time.Second)
			defer t.Stop()
			for range t.C {
				if defaultManager != nil {
					defaultManager.sweepWatches()
					defaultManager.memSweep()
					defaultManager.sweepBlacklist()
				}
			}
		}()
	})
}
