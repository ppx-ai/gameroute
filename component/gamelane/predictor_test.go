package gamelane

import (
	"testing"
	"time"
)

// newTestPredictor 构造窗口 1s、冷却 30s 的预测器，时钟锚定 epoch+1000s 便于推进。
func newTestPredictor() *Predictor {
	p := NewPredictor(Config{
		WindowDuration:   time.Second,
		TriggerWindows:   3,
		Cooldown:         30 * time.Second,
		RollbackWindows:  5,
		LossBad:          0.05,
		LossGood:         0.02,
		JitterBadMs:      80,
		JitterGoodMs:     30,
		RateBadRatio:     0.4,
		RateGoodRatio:    0.8,
	})
	p.now = func() time.Time { return time.UnixMilli(1000000) }
	p.openWindow(p.now())
	return p
}

// fillWindow 在同一个窗口内喂入 sent 个上行包和 recv 个下行包，每个下行包携带 1000B。
// 所有包使用同一时刻 ts，保证落在同一窗口。
func fillWindow(p *Predictor, ts time.Time, sent, recv int, isQUIC bool) {
	for i := 0; i < sent; i++ {
		p.OnPacket(true, false, 0, ts, isQUIC)
	}
	for i := 0; i < recv; i++ {
		p.OnPacket(false, true, 1000, ts, isQUIC)
	}
}

// 阈值触发：连续 3 个坏窗口（丢包 10%）→ 应触发切换到 fallback
func TestPredictor_TriggerAfter3BadWindows(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(1000000)
	for i := 0; i < 3; i++ {
		fillWindow(p, base.Add(time.Duration(i)*time.Second), 100, 90, false)
		act := p.OnPacket(false, true, 1000, base.Add(time.Duration(i)*time.Second+900*time.Millisecond), false)
		if act != ActionNone {
			t.Fatalf("window %d: want ActionNone, got %v", i, act)
		}
	}
	// 第 3 个窗口结束后的下一个窗口边界触发评估
	act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	if act != ActionSwitchToFallback {
		t.Fatalf("want ActionSwitchToFallback after 3 bad windows, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback, got %v", p.Mode())
	}
}

// 不足阈值：仅 2 个坏窗口不触发
func TestPredictor_NotTriggerUnderThreshold(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(2000000)
	for i := 0; i < 2; i++ {
		fillWindow(p, base.Add(time.Duration(i)*time.Second), 100, 90, false)
		p.OnPacket(false, true, 1000, base.Add(time.Duration(i)*time.Second+900*time.Millisecond), false)
	}
	act := p.OnPacket(false, true, 1000, base.Add(2*time.Second), false)
	if act != ActionNone {
		t.Fatalf("2 bad windows must not trigger, got %v", act)
	}
}

// 回切：fallback 模式下连续 5 个稳定好窗口（丢包 0%、速率恢复），
// 且必须探测确认 primary 已恢复才回切
func TestPredictor_RollbackAfter5GoodWindows(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(4000000)
	// 先触发切换
	for i := 0; i < 3; i++ {
		fillWindow(p, base.Add(time.Duration(i)*time.Second), 100, 90, false)
		p.OnPacket(false, true, 1000, base.Add(time.Duration(i)*time.Second+900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback first, got %v", act)
	}
	// 5 个稳定好窗口：满收 + 稳定下行速率
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 5; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		act := p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
		if i < 4 && act != ActionNone {
			t.Fatalf("window %d want ActionNone, got %v", i, act)
		}
	}
	// 未探测确认 primary 恢复：不得回切
	act := p.OnPacket(false, true, 1000, goodBase.Add(5*time.Second), false)
	if act != ActionNone {
		t.Fatalf("must not rollback without probe, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback without probe, got %v", p.Mode())
	}
	// 断言包落入 5s 窗口，补填避免低流量窗口被判坏
	fillWindow(p, goodBase.Add(5*time.Second), 100, 100, false)
	// 探测确认 primary 恢复 → 下一好窗口结算回切
	p.OnPrimaryProbe(0, 5, goodBase.Add(5*time.Second))
	act = p.OnPacket(false, true, 1000, goodBase.Add(6*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("want rollback to primary after probe recovery, got %v", act)
	}
	if p.Mode() != modePrimary {
		t.Fatalf("want mode primary, got %v", p.Mode())
	}
}

// 回切不充分：恢复不足 5 窗口不回切
func TestPredictor_NoRollbackUnder5Good(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(5000000)
	for i := 0; i < 3; i++ {
		fillWindow(p, base.Add(time.Duration(i)*time.Second), 100, 90, false)
		p.OnPacket(false, true, 1000, base.Add(time.Duration(i)*time.Second+900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback first, got %v", act)
	}
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 4; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		if act := p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false); act != ActionNone {
			t.Fatalf("window %d want ActionNone, got %v", i, act)
		}
	}
	act := p.OnPacket(false, true, 1000, goodBase.Add(4*time.Second), false)
	if act != ActionNone {
		t.Fatalf("4 good windows must not rollback, got %v", act)
	}
}

// 坏窗口打断好窗口连续计数：3 好 1 坏 2 好 → 不回切
func TestPredictor_GoodStreakBroken(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(6000000)
	for i := 0; i < 3; i++ {
		fillWindow(p, base.Add(time.Duration(i)*time.Second), 100, 90, false)
		p.OnPacket(false, true, 1000, base.Add(time.Duration(i)*time.Second+900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback first, got %v", act)
	}
	goodBase := base.Add(10 * time.Second)
	for i := 0; i < 3; i++ {
		ts := goodBase.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	// 插入一个坏窗口
	badTs := goodBase.Add(3 * time.Second)
	fillWindow(p, badTs, 100, 80, false)
	p.OnPacket(false, true, 1000, badTs.Add(900*time.Millisecond), false)
	// 再 2 个好窗口
	for i := 0; i < 2; i++ {
		ts := goodBase.Add(time.Duration(i+4) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, goodBase.Add(6*time.Second), false); act != ActionNone {
		t.Fatalf("broken streak must not rollback, got %v", act)
	}
}

// 未命中零影响：从未观测的预测器任何时刻返回 None，且模式保持 primary
func TestPredictor_NoObservationZeroImpact(t *testing.T) {
	p := newTestPredictor()
	for i := 0; i < 10; i++ {
		ts := time.UnixMilli(int64(7000000 + i*100))
		if act := p.OnPacket(false, false, 0, ts, false); act != ActionNone {
			t.Fatalf("no observation must be ActionNone, got %v", act)
		}
	}
	if p.Mode() != modePrimary {
		t.Fatalf("mode must stay primary, got %v", p.Mode())
	}
}

// jitter 坏指标仅在 QUIC 会话生效：非 QUIC 高 jitter 不算坏窗口
func TestPredictor_JitterOnlyForQUIC(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(8000000)
	// 非 QUIC：3 个窗口丢包 0% 但抖动大 → 不触发
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		// 高 jitter：追加时间戳跨度大的下行包
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
		p.OnPacket(false, true, 1000, ts.Add(950*time.Millisecond), false)
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionNone {
		t.Fatalf("non-QUIC jitter must not trigger, got %v", act)
	}
}

// jitter≥80ms 且为 QUIC 会话时计入坏窗口
func TestPredictor_JitterTriggersForQUIC(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(9000000)
	// 每窗口丢包 0%，但 QUIC 高 jitter
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, true)
		// 模拟到达间隔 150ms 的抖动（全部落在 1s 窗口内，不跨边界）
		for j := 0; j < 5; j++ {
			p.OnPacket(false, true, 1000, ts.Add(time.Duration(100+j*150)*time.Millisecond), true)
		}
	}
	if act := p.OnPacket(false, true, 1000, base.Add(3*time.Second), false); act != ActionSwitchToFallback {
		t.Fatalf("QUIC jitter must trigger, got %v", act)
	}
}

// 未命中零影响：纯空窗口结算不推进 streak，且不阻塞后续触发
func TestPredictor_EmptyWindowNoEffect(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(3000000)
	// 超过 1 个窗口的空观察（无任何包），结算空窗口
	act := p.OnPacket(false, false, 0, base.Add(1500*time.Millisecond), false)
	if act != ActionNone {
		t.Fatalf("empty window must not trigger, got %v", act)
	}
	// 空窗口不推进 badStreak：随后 3 个坏窗口仍应触发
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i+2) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	act = p.OnPacket(false, true, 1000, base.Add(5*time.Second), false)
	if act != ActionSwitchToFallback {
		t.Fatalf("empty window must not block trigger, got %v", act)
	}
}

// 默认配置回填：零配置构造后使用默认阈值，坏窗口照常触发
func TestPredictor_DefaultConfigFill(t *testing.T) {
	p := NewPredictor(Config{})
	base := time.UnixMilli(4000000)
	p.now = func() time.Time { return time.UnixMilli(4000000) }
	p.openWindow(p.now())
	d := p.cfg.WindowDuration
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * d)
		fillWindow(p, ts, 100, 50, false) // 50% 丢包必然坏窗口
	}
	act := p.OnPacket(false, true, 1000, base.Add(3*d), false)
	if act != ActionSwitchToFallback {
		t.Fatalf("default config must trigger on heavy loss, got %v", act)
	}
}

// 单包跨多窗口：一次 OnPacket 循环结算多个到期窗口并评估
func TestPredictor_MultiWindowJump(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(5000000)
	fillWindow(p, base, 100, 90, false)               // w0 坏
	fillWindow(p, base.Add(time.Second), 100, 90, false) // w1 坏
	fillWindow(p, base.Add(2*time.Second), 100, 90, false) // w2 坏
	// 直接跳到 4 秒后：一次 OnPacket 结算 w2 与空窗口 w3 后评估
	act := p.OnPacket(false, true, 1000, base.Add(4*time.Second), false)
	if act != ActionSwitchToFallback {
		t.Fatalf("multi-window jump must trigger, got %v", act)
	}
}

// 速率坏窗口：建立基线后速率骤降触发坏窗口（不依赖丢包）
func TestPredictor_RateBadWindow(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(6000000)
	// 3 个好窗口建立基线（无丢包，速率 100kB/s）
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		p.OnPacket(false, true, 1000, ts.Add(900*time.Millisecond), false)
	}
	// 3 个坏窗口：丢包 0 但速率骤降（下行 10 包/窗口 = 10kB/s < 基线 40%）
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i+3) * time.Second)
		fillWindow(p, ts, 100, 10, false)
	}
	act := p.OnPacket(false, true, 1000, base.Add(6*time.Second), false)
	if act != ActionSwitchToFallback {
		t.Fatalf("rate collapse must trigger, got %v", act)
	}
}

// fallback 速率骤降：切换后 fallback 窗口丢包率虽低但下行速率远低于基线，
// 判定为坏窗口——按新语义维持 B（不回切 primary，避免绕过探测）。
func TestPredictor_FallbackRateBadRollback(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(7000000)
	// 先建基线：2 个全速好窗口
	for i := 0; i < 2; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	// 触发切换到 fallback：3 个坏窗口（丢 10%）
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i+2) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(5*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %v", p.Mode())
	}
	// fallback 低速率窗口（0 丢包但速率骤降）→ 坏窗口 → 维持 B
	ts := base.Add(5 * time.Second)
	fillWindow(p, ts, 5, 5, false)
	act := p.OnPacket(false, true, 1000, base.Add(6*time.Second), false)
	if act != ActionNone {
		t.Fatalf("fallback bad window must not bypass probe to rollback, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback, got %v", p.Mode())
	}
}

// fallback 出口恶化：切换后 fallback 出现坏窗口（如备用链路也丢包），
// 按新语义维持 B——回切只允许发生在探测确认 primary 恢复之后。
func TestPredictor_FallbackBadRollback(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(9000000)
	// 3 个坏窗口触发切换到 fallback
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %v", p.Mode())
	}
	// fallback 也恶化（全丢）：冷却期内也不得绕过探测回切 primary
	ts := base.Add(4 * time.Second)
	fillWindow(p, ts, 100, 0, false)
	act := p.OnPacket(false, true, 1000, base.Add(5*time.Second), false)
	if act != ActionNone {
		t.Fatalf("fallback bad window must not bypass probe to rollback, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback, got %v", p.Mode())
	}
}

// 回切验证期：回切 primary 后主链路仍坏（恒劣化场景），
// 首个坏窗口应立即切回 fallback，不等待 TriggerWindows 也不受冷却冻结。
// 按新语义：A 未确认恢复（无探测）时 B 再好也不得回切，乒乓消失。
func TestPredictor_RollbackVerifyPrimaryStillBad(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(11000000)
	// 3 个坏窗口触发切换到 fallback
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %v", p.Mode())
	}
	// fallback 连续 5 个好窗口：A 从未确认恢复 → 不得回切
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i+4) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	act := p.OnPacket(false, true, 1000, base.Add(9*time.Second), false)
	if act != ActionNone {
		t.Fatalf("must not rollback without primary recovery probe, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback without probe, got %v", p.Mode())
	}
	// 断言包落入 9s 窗口，补填避免低流量窗口被判坏
	fillWindow(p, base.Add(9*time.Second), 100, 100, false)
	// 探测确认 A 恢复 → 下一好窗口回切 primary
	p.OnPrimaryProbe(0, 5, base.Add(9*time.Second))
	act = p.OnPacket(false, true, 1000, base.Add(10*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("want rollback to primary after probe recovery, got %v", act)
	}
	if p.Mode() != modePrimary {
		t.Fatalf("want mode primary, got %v", p.Mode())
	}
	// primary 首个坏窗口（仍 10% 丢）：验证期应立即切回 fallback
	ts := base.Add(10 * time.Second)
	fillWindow(p, ts, 100, 90, false)
	act = p.OnPacket(false, true, 1000, base.Add(11*time.Second), false)
	if act != ActionSwitchToFallback {
		t.Fatalf("want immediate switch to fallback in verify window, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback, got %v", p.Mode())
	}
}


// 回切验证失败冷却：验证期失败切回 fallback 后，冷却期内即使 fallback
// 连续好窗口也不再尝试回切 primary（避免 primary 恒坏时周期性乒乓）；
// 冷却结束后才允许再次回切。
func TestPredictor_RollbackCooldownGate(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(12000000)
	// 3 个坏窗口触发切换到 fallback
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %v", p.Mode())
	}
	// fallback 连续 5 个好窗口：未探测 A 不得回切
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i+4) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	p.OnPacket(false, true, 1000, base.Add(9*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback without probe, got %v", p.Mode())
	}
	// 断言包落入 9s 窗口，补填避免低流量窗口被判坏
	fillWindow(p, base.Add(9*time.Second), 100, 100, false)
	// 探测确认 A 恢复 → 回切 primary 进入验证期
	p.OnPrimaryProbe(0, 5, base.Add(9*time.Second))
	act := p.OnPacket(false, true, 1000, base.Add(10*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("want rollback after probe, got %v", act)
	}
	if p.Mode() != modePrimary {
		t.Fatalf("want mode primary, got %v", p.Mode())
	}
	// 验证期 primary 首个坏窗口 → 立即切回 fallback 并进入回切冷却
	ts := base.Add(10 * time.Second)
	fillWindow(p, ts, 100, 90, false)
	p.OnPacket(false, true, 1000, base.Add(11*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback after verify fail, got %v", p.Mode())
	}
	// 冷却期内 fallback 连续 5 个好窗口：不得回切 primary
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i+11) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	act = p.OnPacket(false, true, 1000, base.Add(16*time.Second), false)
	if act != ActionNone {
		t.Fatalf("cooldown gate must block rollback, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback during rollback cooldown, got %v", p.Mode())
	}
	// 冷却结束后：仍需探测确认 primary 恢复才允许回切
	fillWindow(p, base.Add(16*time.Second), 100, 100, false)
	if !p.TryBeginProbe(base.Add(16 * time.Second)) {
		t.Fatalf("probe must be allowed after rollback cooldown")
	}
	p.OnPrimaryProbe(0, 5, base.Add(16*time.Second))
	// 冷却结束后新好窗口结算 → 回切 primary（冷却至 41s 止，42s 窗口已出冷却）
	fillWindow(p, base.Add(42*time.Second), 100, 100, false)
	act = p.OnPacket(false, true, 1000, base.Add(43*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("rollback must be allowed after cooldown + probe recovery, got %v", act)
	}
	if p.Mode() != modePrimary {
		t.Fatalf("want mode primary after cooldown, got %v", p.Mode())
	}
}

// LastSettledLossRate：未结算为 0，结算后回填触发切换的丢包率
func TestPredictor_LastSettledLossRate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WindowDuration = 100 * time.Millisecond
	cfg.TriggerWindows = 1
	p := NewPredictor(cfg)

	if p.LastSettledLossRate() != 0 {
		t.Fatalf("want initial 0, got %v", p.LastSettledLossRate())
	}

	base := time.Now()
	// 坏窗口触发：窗口内 100 上行 + 80 下行（sent/recv 逐包喂入，同毫秒）
	for i := 0; i < 100; i++ {
		p.OnPacketEx(true, false, 0, 0, base.Add(time.Duration(i)*time.Millisecond), false)
	}
	for i := 0; i < 80; i++ {
		p.OnPacketEx(false, true, 1000, 0, base.Add(time.Duration(i)*time.Millisecond), false)
	}
	// 下一个窗口边界处结算 → 坏窗口触发切换
	act := p.OnPacketEx(false, true, 1000, 0, base.Add(200*time.Millisecond), false)
	if act != ActionSwitchToFallback {
		t.Fatalf("want switch to fallback, got %v", act)
	}
	if got := p.LastSettledLossRate(); got <= 0 {
		t.Fatalf("settled loss must be >0 after switch, got %v", got)
	}
}

// rate 分支：dur<=0 返回 0；正常 dur 按 bytes/s 计算
func TestWindowStats_RateEdge(t *testing.T) {
	w := &windowStats{bytes: 1000}
	if w.rate(0) != 0 {
		t.Fatal("rate with zero duration must be 0")
	}
	if w.rate(-time.Second) != 0 {
		t.Fatal("rate with negative duration must be 0")
	}
	if got := w.rate(time.Second); got != 1000 {
		t.Fatalf("want 1000 bytes/s, got %v", got)
	}
}
