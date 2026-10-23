package gamelane

import (
	"testing"
	"time"
)

// M3 统计聚合器：启用开关、切换记录、快照读取、重置全链路。
func TestM3Stats_RecordAndSnapshot(t *testing.T) {
	s := &M3Stats{}
	s.currentProxy.Store("")

	if s.M3Enabled() {
		t.Fatal("M3 must start disabled")
	}
	s.SetM3Enabled(true)
	if !s.M3Enabled() {
		t.Fatal("M3 must be enabled after SetM3Enabled(true)")
	}

	before := time.Now()
	s.RecordM3Switch(false, "proxy-b", 0.15)
	s.RecordM3Switch(true, "proxy-a", 0.0)

	snap := s.Snapshot()
	if !snap.Enabled {
		t.Fatal("snapshot enabled must be true")
	}
	if snap.SwitchCount != 2 {
		t.Fatalf("want switch_count 2, got %d", snap.SwitchCount)
	}
	if snap.LastSwitchAt.Before(before) || snap.LastSwitchAt.After(time.Now()) {
		t.Fatal("last_switch_at must be within test window")
	}
	if snap.CurrentProxy != "proxy-a" {
		t.Fatalf("want current_proxy proxy-a, got %q", snap.CurrentProxy)
	}
	if snap.LossRate != 0.0 {
		t.Fatalf("want loss_rate 0 (last switch to primary), got %v", snap.LossRate)
	}

	// 包级便捷函数走同一单例
	ResetM3Stats()
	SetM3Enabled(true)
	if !M3Enabled() {
		t.Fatal("package M3Enabled must reflect singleton")
	}
	RecordM3Switch(false, "proxy-c", 0.33)
	if got := GetM3Snapshot().CurrentProxy; got != "proxy-c" {
		t.Fatalf("package RecordM3Switch must update singleton, got %q", got)
	}
	if got := GetM3Snapshot().LossRate; got != 0.33 {
		t.Fatalf("package snapshot must carry loss rate, got %v", got)
	}

	ResetM3Stats()
	snap = GetM3Snapshot()
	if snap.Enabled || snap.SwitchCount != 0 || snap.CurrentProxy != "" || snap.LossRate != 0 {
		t.Fatalf("reset must zero all fields, got %+v", snap)
	}
	if !snap.LastSwitchAt.IsZero() {
		t.Fatal("reset must zero last_switch_at")
	}
}

// 从未切换时的快照：零值时间、空 proxy、零丢包。
func TestM3Stats_SnapshotNeverSwitched(t *testing.T) {
	s := &M3Stats{}
	s.currentProxy.Store("")
	snap := s.Snapshot()
	if !snap.LastSwitchAt.IsZero() {
		t.Fatal("never-switched snapshot must have zero last_switch_at")
	}
	if snap.CurrentProxy != "" {
		t.Fatalf("never-switched snapshot must have empty proxy, got %q", snap.CurrentProxy)
	}
	if snap.SwitchCount != 0 || snap.LossRate != 0 {
		t.Fatalf("never-switched snapshot must be zeroed, got %+v", snap)
	}
}

// 单例初始化与包级便捷函数基本行为。
func TestM3DefaultSingleton(t *testing.T) {
	if M3Default() == nil {
		t.Fatal("M3Default must not be nil")
	}
	if M3Default() != defaultM3Stats {
		t.Fatal("M3Default must return the package singleton")
	}
}

// 浮点位转换辅助函数往返一致性。
func TestAtomicFloat64RoundTrip(t *testing.T) {
	for _, v := range []float64{0.0, 0.15, 0.333333, 1.0, -1.0, 3.14159} {
		if got := atomicFloat64FromBits(atomicFloat64Bits(v)); got != v {
			t.Fatalf("round-trip mismatch for %v, got %v", v, got)
		}
	}
}

// Auto-Pick Primary 进场/换优后同步当前出口节点：只更新 current_proxy，
// 不把"选路"误记为"切换"（switch_count/last_switch_at 不得变化）。
func TestM3Stats_RecordM3Active(t *testing.T) {
	s := &M3Stats{}
	s.currentProxy.Store("")
	s.SetM3Enabled(true)

	s.RecordM3Active("临时A")
	snap := s.Snapshot()
	if snap.CurrentProxy != "临时A" {
		t.Fatalf("RecordM3Active must expose current proxy, got %q", snap.CurrentProxy)
	}
	if snap.SwitchCount != 0 {
		t.Fatalf("RecordM3Active must not bump switch_count, got %d", snap.SwitchCount)
	}
	if !snap.LastSwitchAt.IsZero() {
		t.Fatalf("RecordM3Active must not touch last_switch_at, got %v", snap.LastSwitchAt)
	}
	if snap.LossRate != 0 {
		t.Fatalf("RecordM3Active must not touch loss_rate, got %v", snap.LossRate)
	}

	// 探测后换优节点（非"切换"，仍不应计切换次数）
	s.RecordM3Active("最优B")
	snap = s.Snapshot()
	if snap.CurrentProxy != "最优B" {
		t.Fatalf("RecordM3Active must update proxy, got %q", snap.CurrentProxy)
	}
	if snap.SwitchCount != 0 {
		t.Fatalf("RecordM3Active must never bump switch_count, got %d", snap.SwitchCount)
	}

	// 包级便捷函数走同一单例
	ResetM3Stats()
	RecordM3Active("包级节点")
	if got := GetM3Snapshot().CurrentProxy; got != "包级节点" {
		t.Fatalf("package RecordM3Active must update singleton, got %q", got)
	}
	if got := GetM3Snapshot().SwitchCount; got != 0 {
		t.Fatalf("package RecordM3Active must not bump switch_count, got %d", got)
	}
}
