package gamelane

import (
	"math"
	"testing"
	"time"
)

// ---- 综合评分单元：scoreMetrics 三维加权（丢包 50% / RTT P50 30% / 抖动 20%）----

// 各维度满分：丢包 0%、RTT P50 40ms、抖动 10ms → 100 分
func TestScoreMetrics_Perfect(t *testing.T) {
	cfg := DefaultConfig()
	s := scoreMetrics(0, 40, 10, 1, cfg)
	if math.Abs(s-100) > 1e-6 {
		t.Fatalf("perfect link must score 100, got %v", s)
	}
}

// 各维度零分：丢包 50%（≥LossScoreBad）、RTT 400ms（≥RttScoreBad）、抖动 200ms（≥JitterScoreBad）→ 0 分
func TestScoreMetrics_Worst(t *testing.T) {
	cfg := DefaultConfig()
	s := scoreMetrics(0.5, 400, 200, 1, cfg)
	if math.Abs(s-0) > 1e-6 {
		t.Fatalf("worst link must score 0, got %v", s)
	}
}

// 丢包维度线性：丢包率 20% 恰好 0 分，2% 恰好 100 分，11% 恰为 50 分
func TestScoreMetrics_LossLinear(t *testing.T) {
	cfg := DefaultConfig()
	if s := lossScore(cfg.LossScoreBad, cfg); math.Abs(s) > 1e-6 {
		t.Fatalf("loss at LossScoreBad must score 0, got %v", s)
	}
	if s := lossScore(cfg.LossGood, cfg); math.Abs(s-100) > 1e-6 {
		t.Fatalf("loss at LossGood must score 100, got %v", s)
	}
	mid := (cfg.LossGood + cfg.LossScoreBad) / 2
	if s := lossScore(mid, cfg); math.Abs(s-50) > 1e-6 {
		t.Fatalf("loss midpoint must score 50, got %v", s)
	}
}

// RTT 维度线性：P50 300ms 恰好 0 分，80ms 恰好 100 分
func TestScoreMetrics_RttLinear(t *testing.T) {
	cfg := DefaultConfig()
	if s := rttScore(cfg.RttScoreBadMs, 1, cfg); math.Abs(s) > 1e-6 {
		t.Fatalf("rtt at RttScoreBad must score 0, got %v", s)
	}
	if s := rttScore(cfg.RttScoreGoodMs, 1, cfg); math.Abs(s-100) > 1e-6 {
		t.Fatalf("rtt at RttScoreGood must score 100, got %v", s)
	}
	mid := (cfg.RttScoreGoodMs + cfg.RttScoreBadMs) / 2
	if s := rttScore(mid, 1, cfg); math.Abs(s-50) > 1e-6 {
		t.Fatalf("rtt midpoint must score 50, got %v", s)
	}
}

// 抖动维度线性：抖动 120ms 恰好 0 分，30ms（JitterGoodMs）恰好 100 分
func TestScoreMetrics_JitterLinear(t *testing.T) {
	cfg := DefaultConfig()
	if s := jitterScore(cfg.JitterScoreBadMs, cfg); math.Abs(s) > 1e-6 {
		t.Fatalf("jitter at JitterScoreBad must score 0, got %v", s)
	}
	if s := jitterScore(cfg.JitterGoodMs, cfg); math.Abs(s-100) > 1e-6 {
		t.Fatalf("jitter at JitterGoodMs must score 100, got %v", s)
	}
}

// 加权正确性：丢包 10%（55.6 分）、RTT 190ms（50 分）、抖动 75ms（62.5 分）
// → 0.5*55.6 + 0.3*50 + 0.2*62.5 = 27.8+15+12.5 = 55.3
func TestScoreMetrics_WeightedMix(t *testing.T) {
	cfg := DefaultConfig()
	s := scoreMetrics(0.10, 190, 75, 1, cfg)
	want := 0.5*lossScore(0.10, cfg) + 0.3*rttScore(190, 1, cfg) + 0.2*jitterScore(75, cfg)
	if math.Abs(s-want) > 1e-6 {
		t.Fatalf("weighted mix wrong: got %v want %v", s, want)
	}
	if s <= 0 || s >= 100 {
		t.Fatalf("weighted mix must be interior, got %v", s)
	}
}

// 边界钳制：负值与超界输入钳制到 0~100
func TestScoreMetrics_Clamp(t *testing.T) {
	cfg := DefaultConfig()
	if s := lossScore(-0.1, cfg); math.Abs(s-100) > 1e-6 {
		t.Fatalf("negative loss must clamp to 100, got %v", s)
	}
	if s := rttScore(0, 1, cfg); math.Abs(s-100) > 1e-6 {
		t.Fatalf("zero rtt with sample must clamp to 100, got %v", s)
	}
	// E 修复：无 RTT 采样（recvCount==0）不得按 0ms 满分计算，直接判 0 分
	if s := rttScore(0, 0, cfg); math.Abs(s) > 1e-6 {
		t.Fatalf("zero rtt without sample must score 0, got %v", s)
	}
	if s := jitterScore(-1, cfg); math.Abs(s-100) > 1e-6 {
		t.Fatalf("negative jitter must clamp to 100, got %v", s)
	}
	if s := rttScore(100000, 1, cfg); s < 0 {
		t.Fatalf("huge rtt must clamp to >=0, got %v", s)
	}
}

// ---- 综合评分驱动坏窗口：单项未达硬阈值但组合劣化 → 综合分 < ScoreBad → 坏窗口 ----

// RTT 劣化（P50 400ms，0 分）+ QUIC 抖动 75ms（未达 JitterBadMs=80 硬阈值）
// 丢包 4%（未达 LossBad=5% 硬阈值）→ 综合分 54.7 < ScoreBad(60) → 坏窗口
// 3 个此类窗口触发切换到 fallback，证明劣化判定已升级为三维综合评分。
func TestPredictor_CompositeScoreTriggersBadWindow(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(13000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		// 100 上行 + 96 下行（丢包 4%，低于 LossBad 硬阈值），
		// 其中 86 个同毫秒、10 个分布在后半段构成抖动样本；
		// 全部下行带高 RTT（400ms）样本
		for j := 0; j < 100; j++ {
			p.OnPacketEx(true, false, 0, 0, ts, true)
		}
		for j := 0; j < 86; j++ {
			p.OnPacketEx(false, true, 1000, 400, ts, true)
		}
		for j := 0; j < 10; j++ {
			p.OnPacketEx(false, true, 1000, 400, ts.Add(time.Duration(100+j*75)*time.Millisecond), true)
		}
	}
	act := p.OnPacketEx(false, true, 1000, 400, base.Add(3*time.Second), true)
	if act != ActionSwitchToFallback {
		t.Fatalf("composite degradation must trigger switch, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback, got %v", p.Mode())
	}
}

// 单一维度轻微劣化不误触发：丢包 0%、RTT 150ms（高分）、非 QUIC → 综合分高，保持 primary
func TestPredictor_CompositeScoreNoFalseTrigger(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(14000000)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 100, false)
		// RTT 150ms（F8 后非 QUIC）：0.6*100 + 0.4*68.2 = 87.3 ≥ ScoreBad，不误触发
		p.OnPacketEx(false, true, 1000, 150, ts.Add(900*time.Millisecond), false)
	}
	act := p.OnPacketEx(false, true, 1000, 150, base.Add(5*time.Second), false)
	if act != ActionNone {
		t.Fatalf("mild single-dimension degradation must not trigger, got %v", act)
	}
	if p.Mode() != modePrimary {
		t.Fatalf("want mode primary, got %v", p.Mode())
	}
}

// ---- 综合评分驱动回切：primary 探测同样用综合分判定恢复 ----

// 探测 loss=0、rtt=5ms、jitter=5ms → 恢复，允许回切
func TestPredictor_ProbeScoreRecovered(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(15000000)
	// 触发切换到 fallback
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	if p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %v", p.Mode())
	}
	// fallback 5 个好窗口
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i+4) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	p.OnPacket(false, true, 1000, base.Add(9*time.Second), false)
	fillWindow(p, base.Add(9*time.Second), 100, 100, false)
	// 探测：质量满分 → 恢复
	p.OnPrimaryProbeEx(0, 5, 5, 1, base.Add(9*time.Second))
	act := p.OnPacket(false, true, 1000, base.Add(10*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("perfect probe must allow rollback, got %v", act)
	}
}

// 探测 RTT 500ms（低于 primaryRttGoodMs=1000 硬上限）但综合分 70 < ScoreGood(80)
// → 判定未恢复，禁止回切（综合分维度升级）
func TestPredictor_ProbeScoreHighRttNotRecovered(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(16000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i+4) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	p.OnPacket(false, true, 1000, base.Add(9*time.Second), false)
	fillWindow(p, base.Add(9*time.Second), 100, 100, false)
	// 探测：丢包 0 但 RTT 500ms（未超 1000ms 硬上限，但综合分 70 < 80）→ 未恢复
	p.OnPrimaryProbeEx(0, 500, 5, 1, base.Add(9*time.Second))
	act := p.OnPacket(false, true, 1000, base.Add(10*time.Second), false)
	if act != ActionNone {
		t.Fatalf("high-rtt probe must not allow rollback, got %v", act)
	}
	if p.Mode() != modeFallback {
		t.Fatalf("want mode fallback, got %v", p.Mode())
	}
}

// 探测丢包率超 LossGood：即使 RTT/抖动优秀也判定未恢复
func TestPredictor_ProbeScoreLossNotRecovered(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(17000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i+4) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	p.OnPacket(false, true, 1000, base.Add(9*time.Second), false)
	fillWindow(p, base.Add(9*time.Second), 100, 100, false)
	// 探测：丢包 3%（≥ LossGood=2%）→ 未恢复
	p.OnPrimaryProbeEx(0.03, 5, 5, 1, base.Add(9*time.Second))
	act := p.OnPacket(false, true, 1000, base.Add(10*time.Second), false)
	if act != ActionNone {
		t.Fatalf("lossy probe must not allow rollback, got %v", act)
	}
}

// ---- 旧 OnPrimaryProbe 兼容：jitter 缺省按满分处理，丢包 0/RTT 5ms → 恢复 ----

func TestPredictor_ProbeLegacySignature(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(18000000)
	for i := 0; i < 3; i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		fillWindow(p, ts, 100, 90, false)
	}
	p.OnPacket(false, true, 1000, base.Add(3*time.Second), false)
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i+4) * time.Second)
		fillWindow(p, ts, 100, 100, false)
	}
	p.OnPacket(false, true, 1000, base.Add(9*time.Second), false)
	fillWindow(p, base.Add(9*time.Second), 100, 100, false)
	p.OnPrimaryProbe(0, 5, base.Add(9*time.Second))
	act := p.OnPacket(false, true, 1000, base.Add(10*time.Second), false)
	if act != ActionSwitchToPrimary {
		t.Fatalf("legacy probe signature must still allow rollback, got %v", act)
	}
}

// ---- RTT 采样统计：窗口内 RTT P50 正确 ----

func TestWindowStats_RttP50(t *testing.T) {
	w := &windowStats{}
	w.rttMs = append(w.rttMs, 100, 200, 300, 400, 500) // P50 = 300
	if got := w.rttP50Ms(); math.Abs(got-300) > 1e-6 {
		t.Fatalf("P50 of odd sample must be middle, got %v", got)
	}
	w.rttMs = append(w.rttMs, 600) // 6 样本：P50 取中位区间上侧 (300+400)/2
	if got := w.rttP50Ms(); math.Abs(got-350) > 1e-6 {
		t.Fatalf("P50 of even sample must be mid-upper, got %v", got)
	}
	w.rttMs = w.rttMs[:0]
	if got := w.rttP50Ms(); got != 0 {
		t.Fatalf("empty rtt sample P50 must be 0, got %v", got)
	}
}

// OnPacketEx 收集 RTT 样本：窗口内 rtt 参与评分（高 RTT 拉低综合分 → 好窗口失败）
func TestPredictor_OnPacketExCollectsRtt(t *testing.T) {
	p := newTestPredictor()
	base := time.UnixMilli(19000000)
	// 丢包 0%、RTT 250ms（F8 后非 QUIC）：0.6*100 + 0.4*22.7 = 69.1 < ScoreGood
	ts := base
	fillWindow(p, ts, 100, 100, false)
	for j := 0; j < 10; j++ {
		p.OnPacketEx(false, true, 1000, 250, ts.Add(time.Duration(100+j*20)*time.Millisecond), false)
	}
	act := p.OnPacketEx(false, true, 1000, 250, ts.Add(900*time.Millisecond), false)
	if act != ActionNone {
		t.Fatalf("window must settle without action, got %v", act)
	}
	// 该窗口不是好窗口（综合分 76.8 < 80）：goodStreak 不推进
	if p.goodStreak != 0 {
		t.Fatalf("high-rtt window must not count as good, goodStreak=%d", p.goodStreak)
	}
}

