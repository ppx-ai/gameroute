package gamelane

import (
	"sort"
	"sync/atomic"
	"time"
)

// Action 表示预测器建议执行的切换动作。
type Action int

const (
	// ActionNone 无需动作
	ActionNone Action = iota
	// ActionSwitchToFallback 切换到备用出口（质量恶化）
	ActionSwitchToFallback
	// ActionSwitchToPrimary 回切快速通道主出口（质量恢复）
	ActionSwitchToPrimary
)

const (
	modePrimary = iota
	modeFallback
)

// Config 预测式切换参数（对应设计文档第 6 节 / 12.2 指标修订）。
type Config struct {
	WindowDuration  time.Duration // 观测窗口时长
	TriggerWindows  int           // 连续坏窗口数达到即触发切换
	Cooldown        time.Duration // 切换后冷却时长，防乒乓
	RollbackWindows int           // 回切需连续好窗口数
	LossBad         float64       // 坏窗口丢包率阈值（下行缺口 / 上行）
	LossGood        float64       // 好窗口丢包率阈值
	JitterBadMs     float64       // 坏窗口 jitter 阈值（仅 QUIC 会话生效）
	JitterGoodMs    float64       // 好窗口 jitter 阈值（仅 QUIC 会话生效）
	RateBadRatio    float64       // 坏窗口下行速率低于基线的比率阈值
	RateGoodRatio   float64       // 好窗口下行速率相对基线的恢复比率

	// 三维综合评分（二期）：丢包率 + RTT(P50) + 抖动合成链路质量分 0~100，
	// 劣化触发与回切判定均以综合分为准（丢包/QUIC-jitter 硬阈值仍保留）。
	ScoreBad          float64 // 综合分低于此视为坏窗口
	ScoreGood         float64 // 综合分达到此视为好窗口 / primary 恢复
	LossScoreBad      float64 // 丢包率 ≥ 此 → 丢包维度 0 分（≤ LossGood 满分）
	RttScoreGoodMs    float64 // RTT P50 ≤ 此 → 延迟维度 100 分
	RttScoreBadMs     float64 // RTT P50 ≥ 此 → 延迟维度 0 分
	JitterScoreBadMs  float64 // jitter ≥ 此 → 抖动维度 0 分（≤ JitterGoodMs 满分）

	// 候选池探测节奏：懒测 interval 下限（距上次候选探测完成不足该值则
	// 跳过新一轮探测）；整体探测超时（稀疏流量兜底，凑不齐样本按已收
	// 样本结算）。
	CooldownCandidateInterval time.Duration // 候选探测懒测间隔下限
	CandidateProbeTimeout     time.Duration // 候选探测整体超时
}

// DefaultConfig 返回设计文档指定的默认参数。
func DefaultConfig() Config {
	return Config{
		WindowDuration:  2 * time.Second,
		TriggerWindows:  3,
		Cooldown:        30 * time.Second,
		RollbackWindows: 5,
		LossBad:         0.05,
		LossGood:        0.02,
		JitterBadMs:     80,
		JitterGoodMs:    30,
		RateBadRatio:    0.4,
		RateGoodRatio:   0.8,
		ScoreBad:         60,
		ScoreGood:        80,
		LossScoreBad:     0.20,
		RttScoreGoodMs:   80,
		RttScoreBadMs:    300,
		JitterScoreBadMs: 120,
		CooldownCandidateInterval: 60 * time.Second,
		CandidateProbeTimeout:     5 * time.Second,
	}
}

// 综合评分权重：QUIC 会话丢包 50% + 延迟(P50) 30% + 抖动 20%。
// 固定权重保证可解释：丢包权重最高，任何单维度劣化不足以触发切换。
// F8 校准：非 QUIC 会话抖动维度不可观测，原实现直接丢弃 0.2 权重导致
// 综合分天花板只有 80（ScoreGood=80 几乎不可达，且 RTT>≈227ms 零丢包即
// 判坏窗口，是切换风暴的评分侧推手）；非 QUIC 改为 丢包 0.6 + RTT 0.4，
// 满分恢复 100，与 ScoreGood/ScoreBad 口径对齐。
const (
	weightLoss   = 0.5
	weightRtt    = 0.3
	weightJitter = 0.2

	weightLossNQ = 0.6 // 非 QUIC：丢包权重（含并入的抖动份额）
	weightRttNQ  = 0.4 // 非 QUIC：RTT 权重
)

// scoreMetrics 三维综合评分（0~100）：丢包率 + RTT(P50) + 抖动，
// 各维度 0~100 线性分档后加权求和。recvCount > 0 时才计入 RTT 分，
// 无采样（recvCount == 0）时整体判 0 分（不可用），防止无样本被当 0ms 满分。
func scoreMetrics(lossRate, rttP50Ms, jitterMs float64, recvCount uint64, cfg Config) float64 {
	if recvCount == 0 {
		// 无任何回包采样：整体判不可用，杜绝中性/满分维度（如 jitter=0）把
		// 无回包节点抬成分数，保证 sent>0 且 recv=0 的候选评分直接为 0。
		return 0
	}
	return weightLoss*lossScore(lossRate, cfg) +
		weightRtt*rttScore(rttP50Ms, recvCount, cfg) +
		weightJitter*jitterScore(jitterMs, cfg)
}

// lossScore 丢包维度分：≤ LossGood 满分，≥ LossScoreBad 零分，之间线性。
func lossScore(lossRate float64, cfg Config) float64 {
	if lossRate <= cfg.LossGood {
		return 100
	}
	if lossRate >= cfg.LossScoreBad {
		return 0
	}
	return 100 * (cfg.LossScoreBad - lossRate) / (cfg.LossScoreBad - cfg.LossGood)
}

// rttScore 延迟维度分（P50）：≤ RttScoreGoodMs 满分，≥ RttScoreBadMs 零分，之间线性。
// recvCount == 0 表示无 RTT 采样，直接判不可用（0 分），防止“无样本被当 0ms 满分”。
func rttScore(rttP50Ms float64, recvCount uint64, cfg Config) float64 {
	if recvCount == 0 {
		return 0
	}
	if rttP50Ms <= cfg.RttScoreGoodMs {
		return 100
	}
	if rttP50Ms >= cfg.RttScoreBadMs {
		return 0
	}
	return 100 * (cfg.RttScoreBadMs - rttP50Ms) / (cfg.RttScoreBadMs - cfg.RttScoreGoodMs)
}

// rttRecvCount 由平均 RTT 反推采样计数：rttMs <= 0 视为无 RTT 采样（0 分），>0 视为有采样。
func rttRecvCount(rttMs float64) uint64 {
	if rttMs > 0 {
		return 1
	}
	return 0
}

// jitterScore 抖动维度分：≤ JitterGoodMs 满分，≥ JitterScoreBadMs 零分，之间线性。
func jitterScore(jitterMs float64, cfg Config) float64 {
	if jitterMs <= cfg.JitterGoodMs {
		return 100
	}
	if jitterMs >= cfg.JitterScoreBadMs {
		return 0
	}
	return 100 * (cfg.JitterScoreBadMs - jitterMs) / (cfg.JitterScoreBadMs - cfg.JitterGoodMs)
}

// windowStats 单个观测窗口的聚合统计。
type windowStats struct {
	start  time.Time
	sent   uint64
	recv   uint64
	bytes  uint64
	tsMs   []int64   // 下行包到达时间戳（毫秒），用于 jitter 计算
	rttMs  []float64 // 下行包 RTT 采样（毫秒），用于 P50 计算
	isQUIC bool
}

// lossRate 下行缺口丢包率：sent 为 0 时返回 0；
// recv 多于 sent（无缺口或抖动）按 0 处理，避免 uint64 下溢。
func (w *windowStats) lossRate() float64 {
	if w.sent == 0 {
		return 0
	}
	sent := float64(w.sent)
	recv := float64(w.recv)
	if recv >= sent {
		return 0
	}
	return (sent - recv) / sent
}

// rate 下行速率（bytes/s）。
func (w *windowStats) rate(dur time.Duration) float64 {
	if dur <= 0 {
		return 0
	}
	return float64(w.bytes) / dur.Seconds()
}

// jitterMs 窗口内下行包到达抖动（相邻间隔绝对差的均值）。
func (w *windowStats) jitterMs() float64 {
	return jitterMsFrom(w.tsMs)
}

// rttP50Ms 窗口内下行包 RTT 采样的 P50（中位数）。无采样返回 0。
// 偶数样本取中位区间均值（上侧与下侧中点），与通用 P50 口径一致。
// nRTT 返回本窗口 RTT 采样数（回包样本数）。
func (w *windowStats) nRTT() uint64 {
	return uint64(len(w.rttMs))
}

func (w *windowStats) rttP50Ms() float64 {
	n := len(w.rttMs)
	if n == 0 {
		return 0
	}
	s := make([]float64, n)
	copy(s, w.rttMs)
	sort.Float64s(s)
	mid := n / 2
	if n%2 == 0 {
		return (s[mid-1] + s[mid]) / 2
	}
	return s[mid]
}

// score 窗口综合质量分（0~100）：丢包 + RTT(P50) + 抖动三维加权。
// 抖动维度仅 QUIC 会话参与，非 QUIC 按满分中性处理。
// recv == 0 时无 RTT 采样 → rttScore 判 0 分，防止无样本被当 0ms 满分。
func (w *windowStats) score(cfg Config) float64 {
	if w.isQUIC && w.nRTT() == 0 {
		// QUIC 无 RTT 采样 → 抖动维度判 0，仅 loss 维度
		return weightLoss*lossScore(w.lossRate(), cfg)
	}
	if !w.isQUIC {
		// 非 QUIC（F8）：抖动维度不可观测，权重并入丢包(0.6)/RTT(0.4)，
		// 满分恢复 100。零丢包会话不再因 RTT 单维度被判坏窗口，
		// 劣化判定回归“丢包硬阈值 + 综合分”双保险。
		return weightLossNQ*lossScore(w.lossRate(), cfg) +
			weightRttNQ*rttScore(w.rttP50Ms(), w.recv, cfg)
	}
	return scoreMetrics(w.lossRate(), w.rttP50Ms(), w.jitterMs(), w.recv, cfg)
}

// jitterMsFrom 计算给定到达时间戳序列（ms）的抖动：相邻间隔绝对差的均值。
// 少于 2 个采样返回 0；同毫秒突发（间隔 0）不参与抖动统计。
func jitterMsFrom(ts []int64) float64 {
	if len(ts) < 2 {
		return 0
	}
	prev := ts[0]
	var sum float64
	var n int
	for _, t := range ts[1:] {
		d := float64(t - prev)
		if d < 0 {
			d = -d
		}
		prev = t
		if d == 0 {
			continue
		}
		sum += d
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// Predictor 预测式切换决策器：按固定时长窗口聚合会话观测，
// 连续坏窗口触发切换到 fallback，连续好窗口回切 primary，
// 切换后进入冷却期防止乒乓抖动。
type Predictor struct {
	cfg Config
	now func() time.Time

	cur  *windowStats
	hist []windowStats // 已结算窗口，最多保留最近 8 个

	baseline    float64 // 下行速率基线（bytes/s），EMA 更新
	hasBaseline bool

	mode         int
	badStreak    int
	goodStreak   int
	cooldownTill time.Time

	// lastSettledLossRate 最近一次评估窗口的下行丢包率；触发切换时由
	// evaluateWindow 记录，供上层（SessionConn → M3Stats）上报全局状态。
	lastSettledLossRate float64

	// rollbackPending 回切验证期：回切 primary 后若首个坏窗口立即出现，
	// 说明 primary 尚未恢复，应立即切回 fallback，防止恒劣化主链路乒乓。
	rollbackPending bool
	// rollbackCooldownTill 验证失败冷却：回切验证期失败切回 fallback 后，
	// 冷却期内禁止再次尝试回切，避免 primary 恒坏时周期性乒乓。
	rollbackCooldownTill time.Time

	// primary 恢复探测：回切前必须先确认 primary 已恢复（探测成功），
	// 避免 B 好窗口→回切 A→A 坏→切回 B 的乒乓。
	// primaryProbed 是否已完成至少一次探测；primaryRecovered 最近一次探测结论；
	// probeCooldownTill 探测失败后的冷却，防止 A 未恢复时反复探测。
	// 三者均用原子类型：probeLoop 结算回填与 afterPacket 触发探测并发，
	// 非原子读写会让并发 goroutine 读到旧值，导致恢复结论被后续失败探测覆盖。
	primaryProbed     atomic.Bool
	primaryRecovered  atomic.Bool
	probeCooldownTill atomic.Int64 // UnixNano；0 表示无冷却
	probePending      atomic.Bool  // 探测进行中，防并发重复发起

	// candLastFinish 候选池探测完成时间戳（UnixMilli）；懒测 interval 下限：
	// 距上次候选探测完成不足 60s 时跳过新一轮候选探测。
	candLastFinish atomic.Int64
}

// primaryRttGoodMs primary 探测可接受的往返上限（ms），
// 无回包/超时视为未恢复。
const primaryRttGoodMs = 1000.0

// NewPredictor 构造预测器，cfg 缺省字段自动回填默认值。
func NewPredictor(cfg Config) *Predictor {
	def := DefaultConfig()
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = def.WindowDuration
	}
	if cfg.TriggerWindows <= 0 {
		cfg.TriggerWindows = def.TriggerWindows
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = def.Cooldown
	}
	if cfg.RollbackWindows <= 0 {
		cfg.RollbackWindows = def.RollbackWindows
	}
	if cfg.LossBad <= 0 {
		cfg.LossBad = def.LossBad
	}
	if cfg.LossGood <= 0 {
		cfg.LossGood = def.LossGood
	}
	if cfg.JitterBadMs <= 0 {
		cfg.JitterBadMs = def.JitterBadMs
	}
	if cfg.JitterGoodMs <= 0 {
		cfg.JitterGoodMs = def.JitterGoodMs
	}
	if cfg.RateBadRatio <= 0 {
		cfg.RateBadRatio = def.RateBadRatio
	}
	if cfg.RateGoodRatio <= 0 {
		cfg.RateGoodRatio = def.RateGoodRatio
	}
	if cfg.ScoreBad <= 0 {
		cfg.ScoreBad = def.ScoreBad
	}
	if cfg.ScoreGood <= 0 {
		cfg.ScoreGood = def.ScoreGood
	}
	if cfg.LossScoreBad <= 0 {
		cfg.LossScoreBad = def.LossScoreBad
	}
	if cfg.RttScoreGoodMs <= 0 {
		cfg.RttScoreGoodMs = def.RttScoreGoodMs
	}
	if cfg.RttScoreBadMs <= 0 {
		cfg.RttScoreBadMs = def.RttScoreBadMs
	}
	if cfg.JitterScoreBadMs <= 0 {
		cfg.JitterScoreBadMs = def.JitterScoreBadMs
	}
	p := &Predictor{cfg: cfg, now: time.Now, mode: modePrimary}
	p.openWindow(p.now())
	return p
}

func (p *Predictor) openWindow(ts time.Time) {
	p.cur = &windowStats{start: ts, isQUIC: false}
}

// Mode 返回当前模式（primary / fallback），供日志与测试断言。
func (p *Predictor) Mode() int {
	return p.mode
}

// LastSettledLossRate 返回最近一次评估窗口的下行丢包率。
// 从未结算过任何窗口时返回 0；触发切换后即为该次切换的触发丢包率。
func (p *Predictor) LastSettledLossRate() float64 {
	return p.lastSettledLossRate
}

// TryBeginProbe 尝试发起一次 primary 恢复探测。
// 前置条件：处于 fallback 模式、B 好窗口连续计数达到 RollbackWindows、
// primary 尚未确认恢复、且不在探测冷却期内；满足时原子占用探测槽防并发重复。
// 由上层（SessionConn）在每包观测后调用，探测结果经 OnPrimaryProbe 回填。
func (p *Predictor) TryBeginProbe(ts time.Time) bool {
	if p.mode != modeFallback {
		return false
	}
	if p.goodStreak < p.cfg.RollbackWindows {
		return false
	}
	if p.primaryProbed.Load() && p.primaryRecovered.Load() {
		return false // 已确认恢复，等窗口结算回切即可
	}
	if p.primaryProbed.Load() && ts.Before(time.Unix(0, p.probeCooldownTill.Load())) {
		return false // 探测失败冷却中，不反复尝试
	}
	return p.probePending.CompareAndSwap(false, true)
}

// OnPrimaryProbe 回填一次 primary 探测结果（兼容旧签名，jitter 按满分处理）：
// lossRate 为探测丢包率，rttMs 为平均往返（ms）。recvCount 由 rttMs>0 推断
// （旧调用点仅用于建连失败回填，rtt=0 → 无样本判 0 分）。
func (p *Predictor) OnPrimaryProbe(lossRate, rttMs float64, ts time.Time) {
	p.OnPrimaryProbeEx(lossRate, rttMs, 0, rttRecvCount(rttMs), ts)
}

// OnPrimaryProbeEx 回填一次 primary 探测结果（二期综合评分版）：
// lossRate 为探测丢包率，rttMs 为平均往返（ms），jitterMs 为抖动（ms），
// recvCount 为真实回包样本数（recv==0 时 rttScore 判 0 分，防止无样本
// 按 0ms 满分误判恢复）。
// 判定恢复：丢包低于 LossGood、RTT 在可接受范围内、且三维综合分 ≥ ScoreGood；
// 未恢复则进入探测冷却（Cooldown），期间 TryBeginProbe 返回 false。
func (p *Predictor) OnPrimaryProbeEx(lossRate, rttMs, jitterMs float64, recvCount uint64, ts time.Time) {
	recovered := lossRate < p.cfg.LossGood &&
		rttMs < primaryRttGoodMs &&
		scoreMetrics(lossRate, rttMs, jitterMs, recvCount, p.cfg) >= p.cfg.ScoreGood
	// 顺序关键：先回填探测结论，最后释放 probePending。
	// 否则并发 TryBeginProbe 会在 probePending=false 与 primaryProbed=true
	// 之间的窗口读到旧值，再次发起探测并覆盖本次结论。
	p.primaryProbed.Store(true)
	p.primaryRecovered.Store(recovered)
	if !recovered {
		p.probeCooldownTill.Store(ts.Add(p.cfg.Cooldown).UnixNano())
	}
	p.probePending.Store(false)
}

// resetProbe 使探测结论作废：任何一次切换动作后都必须重新探测
// 才能允许回切，防止把旧结论当 primary 当前状态。
func (p *Predictor) resetProbe() {
	p.primaryProbed.Store(false)
	p.primaryRecovered.Store(false)
	p.probeCooldownTill.Store(0)
}

// OnPacket 喂入一次包观测（兼容旧签名，RTT 未知按 0 处理）：
// sent=true 表示上行包发出，recv=true 表示下行包收到（n 为下行字节数）。
func (p *Predictor) OnPacket(sent, recv bool, n int, ts time.Time, isQUIC bool) Action {
	return p.OnPacketEx(sent, recv, n, 0, ts, isQUIC)
}

// OnPacketEx 喂入一次包观测（二期 RTT 版）：rttMs 为该下行包往返（ms，未知传 0）。
// sent=true 表示上行包发出，recv=true 表示下行包收到（n 为下行字节数）。
// 仅当发生窗口边界结算时才推进 streak 并评估切换动作，避免重复推进。
func (p *Predictor) OnPacketEx(sent, recv bool, n int, rttMs float64, ts time.Time, isQUIC bool) Action {
	settled := false
	lastAct := ActionNone
	// 循环结算所有已到期的窗口（含一次跨多个窗口的跳变），
	// 窗口边界固定按 cur.start+WindowDuration 推进，避免漂移。
	// 每个新结算窗口独立推进 streak 并评估动作，最后一次动作胜出。
	if p.cur != nil && ts.Sub(p.cur.start) >= p.cfg.WindowDuration {
		for ts.Sub(p.cur.start) >= p.cfg.WindowDuration {
			p.settle(p.cur)
			w := *p.cur
			p.hist = append(p.hist, w)
			if len(p.hist) > 8 {
				p.hist = p.hist[len(p.hist)-8:]
			}
			p.openWindow(p.cur.start.Add(p.cfg.WindowDuration))
			if act := p.evaluateWindow(&w, ts); act != ActionNone {
				lastAct = act
			}
		}
		settled = true
	}
	if sent {
		p.cur.sent++
	}
	if recv {
		p.cur.recv++
		p.cur.bytes += uint64(n)
		p.cur.tsMs = append(p.cur.tsMs, ts.UnixMilli())
		if len(p.cur.tsMs) > 256 {
			p.cur.tsMs = p.cur.tsMs[len(p.cur.tsMs)-256:]
		}
		if rttMs > 0 {
			p.cur.rttMs = append(p.cur.rttMs, rttMs)
			if len(p.cur.rttMs) > 256 {
				p.cur.rttMs = p.cur.rttMs[len(p.cur.rttMs)-256:]
			}
		}
	}
	p.cur.isQUIC = p.cur.isQUIC || isQUIC

	if !settled {
		return ActionNone
	}
	return lastAct
}

// settle 将窗口统计并入基线（仅好窗口更新基线）。
func (p *Predictor) settle(w *windowStats) {
	if w.sent == 0 && w.recv == 0 {
		return // 空窗口不参与评估与基线
	}
	rate := w.rate(p.cfg.WindowDuration)
	good := p.isGoodWindow(w, rate)
	if good && rate > 0 {
		if !p.hasBaseline {
			p.baseline = rate
			p.hasBaseline = true
		} else {
			p.baseline = 0.7*p.baseline + 0.3*rate
		}
	}
}

// isBadWindow 判定坏窗口：丢包率超硬阈值、或（QUIC 且 jitter 超硬阈值）、
// 或下行速率低于基线比例、或三维综合评分低于 ScoreBad。
// 综合分维度使「丢包未达硬阈值但 RTT/抖动明显劣化」的链路同样被识别，
// 且与回切共用同一评分函数，保证劣化与恢复判定口径一致。
func (p *Predictor) isBadWindow(w *windowStats, rate float64) bool {
	if w.sent == 0 && w.recv == 0 {
		return false
	}
	if w.lossRate() >= p.cfg.LossBad {
		return true
	}
	if w.isQUIC && w.jitterMs() >= p.cfg.JitterBadMs {
		return true
	}
	if p.hasBaseline && rate < p.baseline*p.cfg.RateBadRatio {
		return true
	}
	if w.score(p.cfg) < p.cfg.ScoreBad {
		return true
	}
	return false
}

// isGoodWindow 判定好窗口（回切条件）：丢包率低、jitter 低（QUIC）、速率恢复、
// 且三维综合评分达到 ScoreGood。
func (p *Predictor) isGoodWindow(w *windowStats, rate float64) bool {
	if w.sent == 0 {
		return false
	}
	if w.lossRate() >= p.cfg.LossGood {
		return false
	}
	if w.isQUIC && w.jitterMs() >= p.cfg.JitterGoodMs {
		return false
	}
	if p.hasBaseline && rate <= p.baseline*p.cfg.RateGoodRatio {
		return false
	}
	if w.score(p.cfg) < p.cfg.ScoreGood {
		return false
	}
	return true
}

// evaluateWindow 依据单个新结算窗口推进 streak 并产出动作。
// 空窗口不推进任何 streak，实现"未命中零影响"。
// 冷却期仅冻结坏窗口计数（防乒乓）；回切不受冷却限制，但回切会重置冷却。
func (p *Predictor) evaluateWindow(w *windowStats, ts time.Time) Action {
	if w.sent == 0 && w.recv == 0 {
		return ActionNone
	}
	rate := w.rate(p.cfg.WindowDuration)
	// 冷却判定基于窗口起始时间：窗口本身落在冷却期内则冻结坏窗口计数
	inCooldown := w.start.Before(p.cooldownTill)

	switch {
	case p.isBadWindow(w, rate):
		// 坏窗口总是打断好窗口连续计数
		p.goodStreak = 0
		if p.mode == modeFallback {
			// fallback(B) 坏窗口：维持 B，不得直接回切 primary。
			// 旧实现"fallback 坏窗口立即回切 primary 保底"会绕过探测确认——
			// primary(A) 恒劣时形成 B坏→回切A→A坏→切回B 乒乓；
			// 回切只允许发生在探测确认 primary 恢复之后。
			// 处于验证失败冷却期内同样维持 B（验证期刚失败，回切大概率再次失败）。
			return ActionNone
		}
		// 回切验证期：primary 首个坏窗口说明主链路未恢复，立即切回 fallback
		if p.rollbackPending {
			p.rollbackPending = false
			p.mode = modeFallback
			p.badStreak = 0
			// 设置验证失败冷却：冷却期内禁止再次回切 primary，
			// 避免 primary 恒坏时每 N 好窗口周期性乒乓。
			p.rollbackCooldownTill = ts.Add(p.cfg.Cooldown)
			p.cooldownTill = ts.Add(p.cfg.Cooldown)
			// 验证失败说明 primary 仍未恢复：探测结论作废
			p.resetProbe()
			p.lastSettledLossRate = w.lossRate()
			return ActionSwitchToFallback
		}
		if inCooldown {
			return ActionNone
		}
		p.badStreak++
		if p.badStreak >= p.cfg.TriggerWindows {
			p.mode = modeFallback
			p.badStreak = 0
			p.cooldownTill = ts.Add(p.cfg.Cooldown)
			// 切到 fallback 后 primary 状态未知：探测结论作废
			p.resetProbe()
			p.lastSettledLossRate = w.lossRate()
			return ActionSwitchToFallback
		}
	case p.isGoodWindow(w, rate):
		p.goodStreak++
		p.badStreak = 0
		if p.mode == modeFallback && p.goodStreak >= p.cfg.RollbackWindows && !w.start.Before(p.rollbackCooldownTill) {
			// 回切前必须确认 primary 已恢复：仅当探测完成且结论为恢复
			// 才允许回切；未探测或探测失败（含冷却中）则维持 fallback，
			// 由上层按 TryBeginProbe 发起探测。这消除了
			// "B 好窗口→回切 A→A 坏→切回 B"的恒劣化乒乓。
			if p.primaryProbed.Load() && p.primaryRecovered.Load() {
				p.mode = modePrimary
				p.goodStreak = 0
				// 进入回切验证期；回切本身不设触发冷却，
				// 让 primary 未恢复时的坏窗口能立即切回 fallback。
				// 但回切受"验证失败冷却"gate：验证期失败后冷却期内不再尝试回切，
				// 避免 primary 恒坏时每 N 好窗口乒乓。
				p.rollbackPending = true
				// 回切后探测结论作废：后续若再切 fallback 需重新探测
				p.resetProbe()
				p.lastSettledLossRate = w.lossRate()
				return ActionSwitchToPrimary
			}
		}
		// primary 连续 2 个稳定窗口后退出回切验证期
		if p.rollbackPending && p.goodStreak >= 2 {
			p.rollbackPending = false
		}
	default:
		// 中性窗口（如 sent==0 的纯下行）：不推进
		p.badStreak = 0
		p.goodStreak = 0
	}
	return ActionNone
}
