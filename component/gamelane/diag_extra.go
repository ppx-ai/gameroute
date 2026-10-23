package gamelane

// 本项目文件：诊断快照补全（2026-10-19）。
//
// 背景：GET /game-lane/diag/dump 原只输出 events/capacity/used/head/metrics/
// primary/region_actual/last_switch/switch_history/stats，缺少判读"为什么没切/
// 为什么选了它"的核心状态量：
//   - rttTable（含数据源、最近成功时间、失败连击、熔断惩罚后的生效值）
//   - dropped（环形缓冲因覆盖丢弃的累计事件数）
//   - 坏点熔断表 / 切换冷却表 / 活跃门卫与出生保护期状态
//   - /24 段锁死明细
//
// 本文件全部为**只读快照**函数：只做锁内拷贝与派生计算，不写任何状态字段、
// 不改变任何决策路径、不新增全局锁。锁序与既有读取侧保持一致：
//   - m.mu(R) → badNodeMu（与 SnapshotRTT 一致）
//   - m.mu(R) → failStreakMu（与 MergeProbeResults 的写序一致）
// 严禁在此文件内做任何 m.mu 写操作或在锁内调用外部回调。

import (
	"sort"
	"time"
)

// procStartAt 内核进程启动近似时刻（UnixMilli），由包初始化时记录。
// 仅用于诊断快照标注 uptime_ms，不参与任何业务判定。
var procStartAt = time.Now().UnixMilli()

// DiagRTTRow RTT 表单行（读取侧最终生效值 + 原始数据）。
type DiagRTTRow struct {
	Proxy        string `json:"proxy"`
	RTT          int    `json:"rtt"`            // 生效值（熔断期内已叠加 +200ms 惩罚，与 SnapshotRTT 同口径）
	BaseRTT      int    `json:"base_rtt"`       // rttTable 原始值（未叠加惩罚）
	BadNode      bool   `json:"bad_node"`       // 是否在熔断期内
	BadNodeUntil int64  `json:"bad_node_until"` // 熔断截止（UnixMilli，0=未熔断）
	Region       string `json:"region,omitempty"`
	Source       string `json:"source,omitempty"`        // race / urltest / session ...
	LastURLTest  int    `json:"last_url_test,omitempty"` // 最近一次原始 URLTest 值
	LastOKAt     int64  `json:"last_ok_at,omitempty"`    // 最近一次成功实测时间
	FailStreak   int    `json:"fail_streak"`             // 连续失败轮数（≥3 判死写 0）
}

// DiagBadNode 坏点熔断表单行。
type DiagBadNode struct {
	Proxy    string `json:"proxy"`
	Until    int64  `json:"until"`     // 熔断截止（UnixMilli）
	RemainMs int64  `json:"remain_ms"` // 剩余毫秒（≤0 表示已过期，仅本次快照可见）
	RTT      int    `json:"rtt"`       // 熔断期内生效值（含惩罚）
}

// DiagCooldown 切换冷却表单行（dst → 冷却截止）。
type DiagCooldown struct {
	Dst      string `json:"dst"`
	Until    int64  `json:"until"`
	RemainMs int64  `json:"remain_ms"`
}

// DiagSessionGate 单目标会话门卫/保护期状态。
// Active 表示"过去 10s 内收到过回包"（sessionAliveBlocksSwitch 的拦截条件）；
// BirthGrace 表示会话出生 30s 内（birthGraceMs），期间禁止换节点。
type DiagSessionGate struct {
	Dst            string `json:"dst"`
	LastRecvAt     int64  `json:"last_recv_at,omitempty"`
	LastRecvAgoMs  int64  `json:"last_recv_ago_ms,omitempty"`
	Active         bool   `json:"active"`
	ActiveRemainMs int64  `json:"active_remain_ms,omitempty"`
	BirthAt        int64  `json:"birth_at,omitempty"`
	BirthGrace     bool   `json:"birth_grace"`
	BirthRemainMs  int64  `json:"birth_remain_ms,omitempty"`
}

// DiagSegmentLock /24 段锁死明细（Shadow Forking 赛马胜者锁）。
type DiagSegmentLock struct {
	Segment  string `json:"segment"`
	Proxy    string `json:"proxy"`
	Region   string `json:"region,omitempty"`
	RTTMs    int    `json:"rtt_ms"`
	LockedAt int64  `json:"locked_at"`
	Host     string `json:"host,omitempty"`
	Stale    bool   `json:"stale,omitempty"` // true=已解锁待重赛（segmentStale）
}

// DiagState 诊断快照的状态段。
type DiagState struct {
	RTTTable          []DiagRTTRow      `json:"rtt_table"`
	RTTCount          int               `json:"rtt_count"`
	BadNodes          []DiagBadNode     `json:"bad_nodes"`
	Cooldowns         []DiagCooldown    `json:"cooldowns"`
	SessionGates      []DiagSessionGate `json:"session_gates"`
	SegmentLocks      []DiagSegmentLock `json:"segment_locks"`
	ProbeLastOKAt     int64             `json:"probe_last_ok_at"`
	ProcStartAt       int64             `json:"proc_start_at"`
	UptimeMs          int64             `json:"uptime_ms"`
	SwitchCooldownMs  int64             `json:"switch_cooldown_ms"`
	BirthGraceMs      int64             `json:"birth_grace_ms"`
	ActiveGraceMs     int64             `json:"active_grace_ms"`
	BadNodePenaltyMs  int64             `json:"bad_node_penalty_ms"`
	BadNodeRttPenalty int               `json:"bad_node_rtt_penalty"`
}

// DiagDroppedTotal 返回环形缓冲因覆盖丢失的累计事件数。
// seq 为累计写入条数，n 为当前保留条数，差值即被覆盖丢弃的数量。
func DiagDroppedTotal() int {
	globalDiag.mu.Lock()
	defer globalDiag.mu.Unlock()
	if globalDiag.seq > uint64(globalDiag.n) {
		return int(globalDiag.seq - uint64(globalDiag.n))
	}
	return 0
}

// DiagSeqTotal 返回累计写入的事件总数（含已被覆盖的）。
func DiagSeqTotal() uint64 {
	globalDiag.mu.Lock()
	defer globalDiag.mu.Unlock()
	return globalDiag.seq
}

// DiagStateSnapshot 汇总状态段（只读）。
// 锁序：m.mu(RLock) → badNodeMu / failStreakMu（与写侧同序）。
func (m *Manager) DiagStateSnapshot() DiagState {
	now := time.Now().UnixMilli()
	out := DiagState{
		RTTTable:          []DiagRTTRow{},
		BadNodes:          []DiagBadNode{},
		Cooldowns:         []DiagCooldown{},
		SessionGates:      []DiagSessionGate{},
		SegmentLocks:      []DiagSegmentLock{},
		ProbeLastOKAt:     m.lastProbeOKAt.Load(),
		ProcStartAt:       procStartAt,
		UptimeMs:          now - procStartAt,
		SwitchCooldownMs:  switchCooldownMs,
		BirthGraceMs:      birthGraceMs,
		ActiveGraceMs:     activeSessionGraceMs,
		BadNodePenaltyMs:  badNodePenaltyMs,
		BadNodeRttPenalty: badNodeRttPenalty,
	}

	// ---- RTT 表 + 熔断表（同一把 m.mu.RLock 内取 rttTable 拷贝，再取 badNodeMu）----
	m.mu.RLock()
	base := make(map[string]int, len(m.rttTable))
	for k, v := range m.rttTable {
		base[k] = v
	}
	source := make(map[string]string, len(m.rttSource))
	for k, v := range m.rttSource {
		source[k] = v
	}
	lastOK := make(map[string]int64, len(m.rttLastOK))
	for k, v := range m.rttLastOK {
		lastOK[k] = v
	}
	lastUT := make(map[string]int, len(m.lastURLTest))
	for k, v := range m.lastURLTest {
		lastUT[k] = v
	}
	m.mu.RUnlock()

	m.failStreakMu.RLock()
	streak := make(map[string]int, len(m.rttFailStreak))
	for k, v := range m.rttFailStreak {
		streak[k] = v
	}
	m.failStreakMu.RUnlock()

	m.badNodeMu.Lock()
	badUntil := make(map[string]int64, len(m.badNodeUntil))
	for k, v := range m.badNodeUntil {
		if now < v {
			badUntil[k] = v
		}
	}
	m.badNodeMu.Unlock()

	names := make([]string, 0, len(base))
	seen := make(map[string]struct{}, len(base))
	for k := range base {
		names = append(names, k)
		seen[k] = struct{}{}
	}
	for k := range badUntil {
		if _, ok := seen[k]; !ok {
			names = append(names, k)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		row := DiagRTTRow{
			Proxy:       name,
			BaseRTT:     base[name],
			RTT:         base[name],
			Source:      source[name],
			LastURLTest: lastUT[name],
			LastOKAt:    lastOK[name],
			FailStreak:  streak[name],
		}
		if region, ok := extractRegionTag(name); ok {
			row.Region = region
		}
		if until, ok := badUntil[name]; ok && until > 0 {
			row.BadNode = true
			row.BadNodeUntil = until
			row.RTT = base[name] + badNodeRttPenalty
			out.BadNodes = append(out.BadNodes, DiagBadNode{
				Proxy:    name,
				Until:    until,
				RemainMs: until - now,
				RTT:      row.RTT,
			})
		}
		out.RTTTable = append(out.RTTTable, row)
	}
	out.RTTCount = len(out.RTTTable)

	sort.Slice(out.BadNodes, func(i, j int) bool { return out.BadNodes[i].Proxy < out.BadNodes[j].Proxy })

	// ---- 切换冷却表 ----
	m.switchCooldownMu.Lock()
	for dst, until := range m.switchCooldown {
		if until > now {
			out.Cooldowns = append(out.Cooldowns, DiagCooldown{Dst: dst, Until: until, RemainMs: until - now})
		}
	}
	m.switchCooldownMu.Unlock()
	sort.Slice(out.Cooldowns, func(i, j int) bool { return out.Cooldowns[i].Dst < out.Cooldowns[j].Dst })

	// ---- 会话门卫 / 出生保护期（dst → 时间戳）----
	m.sessionActiveMu.Lock()
	recvAt := make(map[string]int64, len(m.sessionActiveRecvAt))
	for k, v := range m.sessionActiveRecvAt {
		recvAt[k] = v
	}
	birthAt := make(map[string]int64, len(m.sessionBirthAt))
	for k, v := range m.sessionBirthAt {
		birthAt[k] = v
	}
	m.sessionActiveMu.Unlock()

	dsts := make([]string, 0, len(recvAt)+len(birthAt))
	seenDst := make(map[string]struct{}, len(recvAt)+len(birthAt))
	for k := range recvAt {
		dsts = append(dsts, k)
		seenDst[k] = struct{}{}
	}
	for k := range birthAt {
		if _, ok := seenDst[k]; !ok {
			dsts = append(dsts, k)
		}
	}
	sort.Strings(dsts)

	for _, dst := range dsts {
		g := DiagSessionGate{Dst: dst, LastRecvAt: recvAt[dst], BirthAt: birthAt[dst]}
		if g.LastRecvAt > 0 {
			g.LastRecvAgoMs = now - g.LastRecvAt
			if g.LastRecvAgoMs < activeSessionGraceMs {
				g.Active = true
				g.ActiveRemainMs = activeSessionGraceMs - g.LastRecvAgoMs
			}
		}
		if g.BirthAt > 0 {
			age := now - g.BirthAt
			if age < birthGraceMs {
				g.BirthGrace = true
				g.BirthRemainMs = birthGraceMs - age
			}
		}
		out.SessionGates = append(out.SessionGates, g)
	}

	// ---- /24 段锁死明细（含待重赛的 stale 段）----
	m.segmentLockMu.RLock()
	for seg, e := range m.segmentLock {
		if e == nil {
			continue
		}
		out.SegmentLocks = append(out.SegmentLocks, DiagSegmentLock{
			Segment: seg, Proxy: e.Proxy, Region: e.Region, RTTMs: e.RTTMs, LockedAt: e.LockedAt, Host: e.Host,
		})
	}
	for seg, e := range m.segmentStale {
		if e == nil {
			continue
		}
		out.SegmentLocks = append(out.SegmentLocks, DiagSegmentLock{
			Segment: seg, Proxy: e.Proxy, Region: e.Region, RTTMs: e.RTTMs, LockedAt: e.LockedAt, Host: e.Host, Stale: true,
		})
	}
	m.segmentLockMu.RUnlock()
	sort.Slice(out.SegmentLocks, func(i, j int) bool {
		if out.SegmentLocks[i].Segment == out.SegmentLocks[j].Segment {
			return !out.SegmentLocks[i].Stale && out.SegmentLocks[j].Stale
		}
		return out.SegmentLocks[i].Segment < out.SegmentLocks[j].Segment
	})

	return out
}
