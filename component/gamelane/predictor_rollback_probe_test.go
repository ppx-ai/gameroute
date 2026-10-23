package gamelane

import (
	"testing"
	"time"
)

// 核心缺陷：A 恒劣时 B 连续 5 个好窗口也不得回切 primary——
// 回切前必须确认 primary 已恢复（探测成功），否则会形成
// B好→回切A→A坏→切回B 的乒乓。
func TestRollback_RequiresPrimaryRecovery(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(4000000)
	// 3 个坏窗口触发切换到 fallback
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback first, got %v", act)
	}
	// B 连续 5 个好窗口：由于 primary 未探测/未确认恢复，必须维持 fallback
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 5; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		act := p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
		if i < 4 && act != ActionNone {
			t.Fatalf("window %d want ActionNone, got %v", i, act)
		}
	}
	act := p.OnPacket(false, true, 1000, goodBase.Add(5*time.Second), false)
	if act != ActionNone {
		t.Fatalf("A 恒劣时 B 好窗口不得回切（防乒乓），got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback, got %v", p.Mode())
	}
}

// 探测成功：B 稳定 5 好窗口 + primary 探测恢复 → 允许回切 A
func TestRollback_AfterPrimaryProbeSuccess(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(5000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback first, got %v", act)
	}
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 5; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	// 未探测时不回切
	if act := p.OnPacket(false, true, 1000, goodBase.Add(5*time.Second), false); act != ActionNone {
		t.Fatalf("before probe must not rollback, got %v", act)
	}
	// primary 探测成功：丢包 0、RTT 5ms
	p.OnPrimaryProbe(0, 5, goodBase.Add(5*time.Second))
	// 填充第 6 个好窗口（探测时刻起，不跨边界），下一边界结算时回切 primary
	fillWindow(p, goodBase.Add(5*time.Second), 100, 100, false)
	act := p.OnPacket(false, true, 1000, goodBase.Add(6*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("want rollback after probe success, got %v", act)
	}
	if p.Mode() != modePrimary {
		t.Fatalf("want mode primary, got %v", p.Mode())
	}
}

// 探测失败：primary 未恢复时维持 B，探测进入冷却（不反复尝试），
// 冷却结束后允许再次探测；恢复成功后正常回切。
func TestRollback_ProbeFailure_GatedByCooldown(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(6000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback first, got %v", act)
	}
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 5; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	// primary 探测失败（丢包 30%）：维持 B
	p.OnPrimaryProbe(0.3, 5, goodBase.Add(5*time.Second))
	ts := goodBase.Add(6 * time.Second)
	fillWindow(p, ts, 100, 100, false)
	if act := p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false); act != ActionNone {
		t.Fatalf("probe failed must keep fallback, got %v", act)
	}
	// 探测冷却期内不允许再次探测
	if p.TryBeginProbe(goodBase.Add(5*time.Second + 10*time.Second)) {
		t.Fatalf("probe cooldown must gate re-probe")
	}
	// 冷却结束后允许再次探测
	if !p.TryBeginProbe(goodBase.Add(5*time.Second + 31*time.Second)) {
		t.Fatalf("probe must be allowed after cooldown")
	}
	// 再次探测成功 → 下一次窗口结算即回切（goodStreak 早已达标，
	// 探测确认 primary 恢复后首个结算的好窗口回切）
	p.OnPrimaryProbe(0, 5, goodBase.Add(5*time.Second+31*time.Second))
	act := p.OnPacket(false, true, 1000, goodBase.Add(5*time.Second+33*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("want rollback after successful re-probe, got %v", act)
	}
}

// 探测发起前置条件：仅当 B 好窗口连续计数达到 RollbackWindows 且
// primary 未确认恢复时才允许发起探测（goodStreak 不足不探测）。
func TestTryBeginProbe_RequiresGoodStreak(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(7000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %v", p.Mode())
	}
	// 仅 2 个好窗口：不允许探测
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 2; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	if p.TryBeginProbe(goodBase.Add(2*time.Second)) {
		t.Fatalf("goodStreak below RollbackWindows must not probe")
	}
	// 补满 5 个好窗口：允许探测
	for i := 2; i < 5; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	// 结算第 5 个好窗口（goodStreak=5，primary 未确认，不会回切）
	if act := p.OnPacket(false, true, 1000, goodBase.Add(5*time.Second), false); act != ActionNone {
		t.Fatalf("before probe must not rollback, got %v", act)
	}
	if !p.TryBeginProbe(goodBase.Add(5*time.Second)) {
		t.Fatalf("goodStreak reached RollbackWindows must allow probe")
	}
	// 探测 pending 期间不允许并发重复发起
	if p.TryBeginProbe(goodBase.Add(5*time.Second + time.Second)) {
		t.Fatalf("probe pending must not allow duplicate begin")
	}
}

// 保底回切路径缺陷：fallback(B) 出现坏窗口时旧实现会直接回切 primary(A)，
// 绕过探测确认——A 恒劣时形成 B坏→回切A→A坏→切回B 乒乓。
// 修复后：fallback 坏窗口不得回切 primary（未探测/未恢复），必须维持 B。
func TestFallbackBadWindow_DoesNotBypassProbe(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(9000000)
	// 3 个坏窗口触发切换到 fallback
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback first, got %v", act)
	}
	// fallback 模式：B 出现一个坏窗口（如公网偶发抖动）
	badBase := base.Add(10 * time.Second)
	fillWindow(p, badBase, 100, 90, false)
	act := p.OnPacket(false, true, 1000, badBase.Add(time.Second), false)
	if act != ActionNone {
		t.Fatalf("fallback bad window must not bypass probe to rollback, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("must stay fallback when A not confirmed recovered, got mode %d", p.Mode())
	}
	// B 恢复好窗口后（未探测）依然不回切
	fillWindow(p, badBase.Add(2*time.Second), 100, 100, false)
	if act := p.OnPacket(false, true, 1000, badBase.Add(3*time.Second), false); act != ActionNone {
		t.Fatalf("before probe must not rollback, got %v", act)
	}
}

// 状态重置：一旦再次切换（保底回切/验证失败切回 fallback），
// primary 探测结论作废，必须重新探测才允许回切。
func TestRollback_ResetsProbeStateOnSwitch(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(8000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %v", p.Mode())
	}
	// B 5 好窗口 + 探测成功 → primaryRecovered=true
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 5; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	p.OnPrimaryProbe(0, 5, goodBase.Add(5*time.Second))
	if act := p.OnPacket(false, true, 1000, goodBase.Add(6*time.Second), false); act != ActionSwitchToPrimary {
		t.Fatalf("want rollback after probe success, got %v", act)
	}
	// primary 首个坏窗口（验证期失败）→ 切回 fallback，探测状态重置
	ts := goodBase.Add(6 * time.Second)
	fillWindow(p, ts, 100, 90, false)
	p.OnPacket(false, true, 1000, goodBase.Add(7*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback after verify fail, got %v", p.Mode())
	}
	// fallback 再 5 好窗口：不得直接回切（需要重新探测）
	for i := 0; i < 5; i++ {
		ts := goodBase.Add(time.Duration(i+8) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	// 结算第 5 个好窗口（goodStreak=5，primary 未确认，不会回切）
	if act := p.OnPacket(false, true, 1000, goodBase.Add(13*time.Second), false); act != ActionNone {
		t.Fatalf("after verify fail before probe must not rollback, got %v", act)
	}
	// 结算断言包会落入 13s 窗口，立即填满该窗口，
	// 避免"仅 1 个下行包"的低流量窗口在后续结算被判坏而清零 goodStreak
	fillWindow(p, goodBase.Add(13*time.Second), 100, 100, false)
	// 允许发起探测（说明探测状态已重置，未把旧结论当恢复）
	if !p.TryBeginProbe(goodBase.Add(13 * time.Second)) {
		t.Fatalf("probe state must reset after switch, probe must be allowed")
	}
	act := p.OnPacket(false, true, 1000, goodBase.Add(13*time.Second), false)
	if act != ActionNone {
		t.Fatalf("before re-probe result must not rollback, got %v", act)
	}
	// 重新探测成功（探测状态已重置，旧结论未干扰本次探测）
	p.OnPrimaryProbe(0, 5, goodBase.Add(13*time.Second))
	// 验证失败冷却期内（30s）：即使探测已成功也不回切
	if act := p.OnPacket(false, true, 1000, goodBase.Add(20*time.Second), false); act != ActionNone {
		t.Fatalf("rollback cooldown must gate re-rollback, got %v", act)
	}
	// 断言包落入 20s 窗口，立即填满避免低流量窗口在后续结算被判坏清零
	fillWindow(p, goodBase.Add(20*time.Second), 100, 100, false)
	// 冷却结束后，新好窗口结算即回切
	fillWindow(p, goodBase.Add(38*time.Second), 100, 100, false)
	if act := p.OnPacket(false, true, 1000, goodBase.Add(39*time.Second), false); act != ActionSwitchToPrimary {
		t.Fatalf("want rollback after cooldown + re-probe success, got %v", act)
	}
}
