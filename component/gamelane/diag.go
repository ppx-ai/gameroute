package gamelane

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ---- 诊断事件环形缓冲（2026-10-19 训练场卡顿/超时定位）----
// 需求背景：外部轮询（/game-lane/status、/traffic）与日志流都存在采样窗口，
// 不能保证抓到毫秒级因果链。本缓冲在关键决策点的代码路径上同步写入
// （零采样窗口）：事件发生时必然被记录。卡顿复现后通过
//   GET /game-lane/diag/events  增量拉取全部事件
//   GET /game-lane/diag/dump    一键冻结导出（事件 + 切换历史 + 主出口快照）
// 得到秒级对齐的会话级事件时间线，可直接定位"训练场卡住 → 连接服务器超时"
// 的完整因果链（接管是否命中 → 临时主节点是谁 → 是否发生劣化/切换/被冷却拒绝
// → 会话是否断流 recv_stall）。
//
// v2.10 P1（2026-10-19）：事件补 Seq（单调序号，前端 since 游标）与结构化字段
// （dst/port/node/note），并把"增量拉取 + kind 过滤 + 条数上限"下沉到内核，
// 面板不再全量拉 2048 条后自行筛选。

// DiagEvent 单条诊断事件。
type DiagEvent struct {
	At   int64  `json:"at"`             // 事件时刻（UnixMilli）
	Seq  uint64 `json:"seq"`            // 单调递增序号（1 起），增量游标
	Kind string `json:"kind"`           // 事件类型
	Msg  string `json:"msg"`            // 事件文本（人读摘要）
	Dst  string `json:"dst,omitempty"`  // 结构化目标（IP 或 host）
	Port int    `json:"port,omitempty"` // 结构化目标端口
	Node string `json:"node,omitempty"` // 结构化节点/出口名
	Note string `json:"note,omitempty"` // 结构化补充（进程名/协议/原因码）
}

// diagRingCapacity 环形缓冲容量：2048 条常驻，正常速率覆盖分钟级窗口，
// 最坏速率（毫秒级风暴）也能保留最近约 2 秒的完整现场。
const diagRingCapacity = 2048

type diagRing struct {
	mu     sync.Mutex
	events [diagRingCapacity]DiagEvent
	idx    int
	n      int
	seq    uint64
}

var globalDiag = &diagRing{}

// recordDiag 记录一条诊断事件（环形覆盖，满时自动丢弃最旧，调用方不感知）。
// 仅供 gamelane 包内部埋点调用；格式化语义与 log.Infoln 一致。
func recordDiag(kind, format string, args ...interface{}) {
	appendDiagEvent(DiagEvent{Kind: kind, Msg: formatDiagMsg(format, args...)})
}

// recordDiagFields 记录带结构化字段的事件（v2.10 P1）。
// 只在低频决策点调用（每会话一次 / 每次切换一次），热路径请用 metrics.go
// 的 atomic 计数器。
func recordDiagFields(kind, dst string, port int, node, note, format string, args ...interface{}) {
	appendDiagEvent(DiagEvent{
		Kind: kind,
		Msg:  formatDiagMsg(format, args...),
		Dst:  dst,
		Port: port,
		Node: node,
		Note: note,
	})
}

func formatDiagMsg(format string, args ...interface{}) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

// appendDiagEvent 统一入环：分配序号、补时刻、推进环形指针。
func appendDiagEvent(ev DiagEvent) {
	globalDiag.mu.Lock()
	globalDiag.seq++
	ev.Seq = globalDiag.seq
	if ev.At == 0 {
		ev.At = time.Now().UnixMilli()
	}
	globalDiag.events[globalDiag.idx] = ev
	globalDiag.idx = (globalDiag.idx + 1) % diagRingCapacity
	if globalDiag.n < diagRingCapacity {
		globalDiag.n++
	}
	globalDiag.mu.Unlock()
}

// DiagSnapshot 返回按时间升序排列的全部事件（已按环形顺序规整）与容量。
// 供 /game-lane/diag/events 与 /game-lane/diag/dump 只读输出。
func DiagSnapshot() ([]DiagEvent, int) {
	globalDiag.mu.Lock()
	defer globalDiag.mu.Unlock()
	out := make([]DiagEvent, 0, globalDiag.n)
	start := diagStartLocked()
	for i := 0; i < globalDiag.n; i++ {
		out = append(out, globalDiag.events[(start+i)%diagRingCapacity])
	}
	return out, diagRingCapacity
}

// DiagEventsSince 增量拉取（v2.10 P1）：
//   - since > 0：只返回 Seq > since 的事件（游标以返回的 head 推进）；
//   - kinds 非空：逗号分隔的 kind 白名单，只返回命中的类型；
//   - limit > 0：只保留最新的 limit 条（取尾部）。
//
// 返回值：events、capacity、used、head（最新序号）、dropped（游标已被环形
// 覆盖而永久丢失的条数，0 表示增量完整）。
func DiagEventsSince(since uint64, kinds string, limit int) ([]DiagEvent, int, int, uint64, int) {
	var kindSet map[string]bool
	if kinds != "" {
		parts := strings.Split(kinds, ",")
		kindSet = make(map[string]bool, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				kindSet[p] = true
			}
		}
	}

	globalDiag.mu.Lock()
	defer globalDiag.mu.Unlock()

	out := make([]DiagEvent, 0, globalDiag.n)
	start := diagStartLocked()
	for i := 0; i < globalDiag.n; i++ {
		ev := globalDiag.events[(start+i)%diagRingCapacity]
		if since > 0 && ev.Seq <= since {
			continue
		}
		if kindSet != nil && !kindSet[ev.Kind] {
			continue
		}
		out = append(out, ev)
	}

	dropped := 0
	if since > 0 && globalDiag.n > 0 {
		oldest := globalDiag.events[start].Seq
		if oldest > since+1 {
			dropped = int(oldest - since - 1)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, diagRingCapacity, globalDiag.n, globalDiag.seq, dropped
}

// DiagHeadSeq 返回当前最新事件序号（只读，供轻量游标探测）。
func DiagHeadSeq() uint64 {
	globalDiag.mu.Lock()
	defer globalDiag.mu.Unlock()
	return globalDiag.seq
}

// diagStartLocked 返回环形缓冲最旧元素下标（调用方必须已持锁）。
func diagStartLocked() int {
	if globalDiag.n == diagRingCapacity {
		return globalDiag.idx
	}
	return 0
}

// DiagRingUsed 返回当前已用条数（供外部增量拉取判断是否已覆盖旧游标）。
func DiagRingUsed() int {
	globalDiag.mu.Lock()
	defer globalDiag.mu.Unlock()
	return globalDiag.n
}
