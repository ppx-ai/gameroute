package tunnel

import (
	"testing"
	"time"
)

// F3（2026-10-16 诊断 RC3）：laneEntry 监控时序——单次超时不触发，
// 连续两个观测周期超时才触发，收到回包后重置。
func TestLaneEntry_NoRecvOverdue(t *testing.T) {
	e := &laneEntry{onLane: true, dst: "1.2.3.4"}
	base := time.Now().UnixMilli()
	if e.noRecvOverdue(base, 5000, 3500) {
		t.Fatalf("first overdue must not fire")
	}
	if e.noRecvOverdue(base+1000, 5000, 3500) {
		t.Fatalf("second check within interval must not fire")
	}
	if !e.noRecvOverdue(base+4000, 5000, 3500) {
		t.Fatalf("overdue across two periods must fire")
	}
	e.markRecv(base + 4100)
	if e.noRecvOverdue(base+9200, 5000, 3500) {
		t.Fatalf("recv must reset overdue state (first check after recv)")
	}
	if !e.noRecvOverdue(base+12900, 5000, 3500) {
		t.Fatalf("second overdue cycle must fire again")
	}
}

// F3：markRecv 原子合并写——并发调用不丢失更新（行为级：recv 后立即
// 重置 overdue，且 lastRecvAt 单调递增）。
func TestLaneEntry_MarkRecvMonotonic(t *testing.T) {
	e := &laneEntry{onLane: true, dst: "1.2.3.4"}
	base := time.Now().UnixMilli()
	e.markRecv(base)
	e.markRecv(base - 1000) // 旧时间戳不得回退
	e.mu.Lock()
	got := e.lastRecvAt
	e.mu.Unlock()
	if got != base {
		t.Fatalf("lastRecvAt must be monotonic, got %d want %d", got, base)
	}
}
