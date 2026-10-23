package gamelane

import (
	"testing"
	"time"
)

// 新 Manager 的 Status 输出基础形态：空 primary/region_actual/last_switch，
// candidate_pool 为空数组，stats 可读。
func TestStatus_Empty(t *testing.T) {
	m := newManager(false, nil)
	st := m.Status(3, 100)
	if st.Enabled {
		t.Fatal("want enabled=false")
	}
	if st.Targets != 0 {
		t.Fatalf("want targets=0, got %d", st.Targets)
	}
	if st.Primary != nil {
		t.Fatalf("want primary=nil, got %+v", st.Primary)
	}
	if st.RegionActual != nil {
		t.Fatalf("want region_actual=nil, got %+v", *st.RegionActual)
	}
	if st.CandidatePool == nil || len(st.CandidatePool) != 0 {
		t.Fatalf("want empty candidate_pool, got %+v", st.CandidatePool)
	}
	if st.LastSwitch != nil {
		t.Fatalf("want last_switch=nil, got %+v", st.LastSwitch)
	}
	if st.Stats.ManagedSessions != 3 || st.Stats.UDPPackets != 100 {
		t.Fatalf("want stats(3,100), got %+v", st.Stats)
	}
}

// recordPrimarySnapshot 后 Status.primary 输出 proxy/region/source/rtt。
func TestStatus_PrimarySnapshot(t *testing.T) {
	m := newManager(true, nil)
	rtt := map[string]int{"香港-01": 22, "新加坡-01": 33}
	m.recordPrimarySnapshot("香港-01", "memory-region", rtt)
	st := m.Status(0, 0)
	if st.Primary == nil {
		t.Fatal("want primary set")
	}
	if st.Primary.Proxy != "香港-01" || st.Primary.Region != "HK" ||
		st.Primary.Source != "memory-region" || st.Primary.RTT != 22 {
		t.Fatalf("unexpected primary: %+v", st.Primary)
	}
	// 更新覆盖
	m.recordPrimarySnapshot("新加坡-01", "fallback", rtt)
	st = m.Status(0, 0)
	if st.Primary.Proxy != "新加坡-01" || st.Primary.Source != "fallback" || st.Primary.RTT != 33 {
		t.Fatalf("unexpected primary after update: %+v", st.Primary)
	}
}

// recordCandidateSnapshot 保持生成顺序输出，region/rtt 正确解析。
func TestStatus_CandidatePool(t *testing.T) {
	m := newManager(true, nil)
	rtt := map[string]int{"新加坡-01": 22, "香港-01": 20, "台湾-01": 30}
	m.recordCandidateSnapshot([]string{"新加坡-01", "香港-01", "台湾-01"}, rtt)
	st := m.Status(0, 0)
	if len(st.CandidatePool) != 3 {
		t.Fatalf("want 3 candidates, got %d", len(st.CandidatePool))
	}
	if st.CandidatePool[0].Proxy != "新加坡-01" || st.CandidatePool[0].Region != "SG" || st.CandidatePool[0].RTT != 22 {
		t.Fatalf("unexpected first candidate: %+v", st.CandidatePool[0])
	}
	if st.CandidatePool[1].Proxy != "香港-01" || st.CandidatePool[1].Region != "HK" {
		t.Fatalf("unexpected second candidate: %+v", st.CandidatePool[1])
	}
	if st.CandidatePool[2].Region != "TW" {
		t.Fatalf("unexpected third candidate: %+v", st.CandidatePool[2])
	}
}

// recordSwitchHistory 记录最近一次切换与环形历史，stats.switch_count 累加。
func TestStatus_LastSwitch(t *testing.T) {
	m := newManager(true, nil)
	m.recordSwitchHistory("台湾-01", "新加坡-02", "TW", "SG", "region-changed", 35)
	st := m.Status(0, 0)
	if st.LastSwitch == nil {
		t.Fatal("want last_switch set")
	}
	if st.LastSwitch.FromProxy != "台湾-01" || st.LastSwitch.ToProxy != "新加坡-02" ||
		st.LastSwitch.Reason != "region-changed" {
		t.Fatalf("unexpected last_switch: %+v", st.LastSwitch)
	}
	if st.LastSwitch.Time.IsZero() {
		t.Fatal("want last_switch.time set")
	}
	if st.Stats.SwitchCount != 1 {
		t.Fatalf("want switch_count=1, got %d", st.Stats.SwitchCount)
	}
	// switch_history 输出切换记录
	if len(st.SwitchHistory) != 1 {
		t.Fatalf("want switch_history len=1, got %d", len(st.SwitchHistory))
	}
	if st.SwitchHistory[0].FromProxy != "台湾-01" || st.SwitchHistory[0].ToProxy != "新加坡-02" ||
		st.SwitchHistory[0].FromRegion != "TW" || st.SwitchHistory[0].ToRegion != "SG" ||
		st.SwitchHistory[0].Reason != "region-changed" || st.SwitchHistory[0].RTT != 35 {
		t.Fatalf("unexpected switch_history[0]: %+v", st.SwitchHistory[0])
	}
	// 再切换：仅保留最近一次 last_switch，计数累加，history 追加
	m.recordSwitchHistory("香港-01", "香港-02", "HK", "HK", "degraded", 0)
	st = m.Status(0, 0)
	if st.LastSwitch.ToProxy != "香港-02" || st.LastSwitch.Reason != "degraded" {
		t.Fatalf("unexpected last_switch after update: %+v", st.LastSwitch)
	}
	if st.Stats.SwitchCount != 2 {
		t.Fatalf("want switch_count=2, got %d", st.Stats.SwitchCount)
	}
	if len(st.SwitchHistory) != 2 {
		t.Fatalf("want switch_history len=2, got %d", len(st.SwitchHistory))
	}
}

// LookUpAnyRegionActual 输出记忆中 active 且有 RegionActual 的最近条目。
func TestStatus_RegionActual(t *testing.T) {
	m := newManager(true, nil)
	m.memories = make(map[string]*GameMemory)
	if ra := m.LookUpAnyRegionActual(); ra != "" {
		t.Fatalf("want empty region_actual, got %s", ra)
	}
	now := time.Now().UnixMilli()
	m.memMu.Lock()
	m.memories["1.2.3.4/32"] = &GameMemory{
		Key:         "1.2.3.4/32",
		Status:      "active",
		LastHitAt:   now,
		RegionActual: "SG",
	}
	m.memMu.Unlock()
	if ra := m.LookUpAnyRegionActual(); ra != "SG" {
		t.Fatalf("want region_actual=SG, got %s", ra)
	}
	st := m.Status(0, 0)
	if st.RegionActual == nil || *st.RegionActual != "SG" {
		t.Fatalf("want Status.region_actual=SG, got %+v", st.RegionActual)
	}
	// decay 条目不参与
	m.memMu.Lock()
	m.memories["5.6.7.8/32"] = &GameMemory{
		Key:         "5.6.7.8/32",
		Status:      "decay",
		LastHitAt:   now,
		RegionActual: "JP",
	}
	m.memMu.Unlock()
	if ra := m.LookUpAnyRegionActual(); ra != "SG" {
		t.Fatalf("want region_actual still SG (decay ignored), got %s", ra)
	}
}
