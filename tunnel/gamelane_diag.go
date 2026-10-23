package tunnel

// 本项目文件：GameLane 诊断会话明细导出（2026-10-19）。
//
// 只读：遍历 laneCache 快照，不改任何字段、不触发重建/切换。
// 读取 laneEntry 时对 mu 保护的字段加锁（activeProxy / recvCount /
// lastRecvAt / lastDegradeCheckAt / lastOverdueAt / birthAt），与写侧一致；
// onLane/dst/dport/pendingRetry/retryAt 为建表期写入的元数据，直接读取
// （与既有 GameLaneSessionStats 的读取口径相同）。

import "time"

// GameLaneSessionDetail 单个 UDP 会话在 game-lane 上的状态明细。
type GameLaneSessionDetail struct {
	Key                string `json:"key"`
	OnLane             bool   `json:"on_lane"`
	Dst                string `json:"dst,omitempty"`
	Dport              uint16 `json:"dport,omitempty"`
	ActiveProxy        string `json:"active_proxy,omitempty"`
	RecvCount          int    `json:"recv_count"`
	PendingRetry       bool   `json:"pending_retry"`
	RetryAt            int64  `json:"retry_at,omitempty"`
	LastRecvAt         int64  `json:"last_recv_at,omitempty"`
	LastRecvAgoMs      int64  `json:"last_recv_ago_ms,omitempty"`
	BirthAt            int64  `json:"birth_at,omitempty"`
	AgeMs              int64  `json:"age_ms,omitempty"`
	BirthGrace         bool   `json:"birth_grace"`
	BirthRemainMs      int64  `json:"birth_remain_ms,omitempty"`
	LastDegradeCheckAt int64  `json:"last_degrade_check_at,omitempty"`
	LastOverdueAt      int64  `json:"last_overdue_at,omitempty"`
}

// GameLaneSessionDetails 返回全部 UDP 会话明细（按 key 排序由调用方决定）。
// birthGraceMs 与 SessionConn 保护期同值（30s），在此按常量派生展示字段。
func GameLaneSessionDetails() []GameLaneSessionDetail {
	now := time.Now().UnixMilli()
	out := make([]GameLaneSessionDetail, 0, 16)
	laneCache.Range(func(key string, info *laneEntry) bool {
		if info == nil {
			return true
		}
		d := GameLaneSessionDetail{
			Key:          key,
			OnLane:       info.onLane,
			Dst:          info.dst,
			Dport:        info.dport,
			PendingRetry: info.pendingRetry,
			RetryAt:      info.retryAt,
		}
		info.mu.Lock()
		d.ActiveProxy = info.activeProxy
		d.RecvCount = info.recvCount
		d.LastRecvAt = info.lastRecvAt
		d.BirthAt = info.birthAt
		d.LastDegradeCheckAt = info.lastDegradeCheckAt
		d.LastOverdueAt = info.lastOverdueAt
		info.mu.Unlock()

		if d.LastRecvAt > 0 {
			d.LastRecvAgoMs = now - d.LastRecvAt
		}
		if d.BirthAt > 0 {
			d.AgeMs = now - d.BirthAt
			if d.AgeMs < 30000 {
				d.BirthGrace = true
				d.BirthRemainMs = 30000 - d.AgeMs
			}
		}
		out = append(out, d)
		return true
	})
	return out
}
