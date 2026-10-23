package gamelane

// 2026-10-21 可观测性 P0 单测：
//   P0-1 flow 低分/疑似未升级 → miss 表出现 reason=flow_low_score 且带 score 明细
//   P0-2 /diag/miss 入口分母 observed_total / registered_total（单调且 observed ≥ registered）
// 运行：go test -tags with_gvisor ./component/gamelane -run TestMissP020261021 -count=1 -v

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// stubFlowProc 把进程反查固定成给定 exe 名（避免真实全表扫描，保证 miss 条目
// 的 process_path 稳定可断言）。返回 restore 函数。
func stubFlowProc(t *testing.T, name string) func() {
	t.Helper()
	old := findProcess
	findProcess = func(m *C.Metadata) (uint32, string) { return 4242, name }
	return func() { findProcess = old }
}

// TestMissP020261021_FlowLowScore 用例 1：低分 UDP 流（非游戏端口、无回复包 →
// 对称性 0 分）经完整观察期后进入低分忽略分支，必须落一条 flow_low_score，
// 且 flow_score/flow_threshold 有值（threshold = 疑似线 60）。
func TestMissP020261021_FlowLowScore(t *testing.T) {
	missTableReset()
	restore := stubFlowProc(t, "NotAGame.exe")
	defer restore()

	m := newDefaultManager()
	m.SetEnabled(true)

	meta := testMeta("45.56.121.2", 9000)
	// 30 包 × 200ms ≈ 6s：满足 ≥20 包 / ≥5s 观察期，无回复包 → 对称性 0。
	if feed(t, m, meta, 30, 80, 200*time.Millisecond) {
		t.Fatal("低分单向流不应注册")
	}

	rep := MissSnapshot()
	var hit *MissEntry
	for i := range rep.Entries {
		if rep.Entries[i].Reasons[MissReasonFlowLowScore] > 0 {
			hit = &rep.Entries[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("未出现 reason=%s 的 miss 条目：entries=%+v", MissReasonFlowLowScore, rep.Entries)
	}
	if hit.Reasons[MissReasonFlowLowScore] == 0 {
		t.Fatalf("reasons[flow_low_score] = 0, hit=%+v", hit)
	}
	if hit.ExeName != "notagame.exe" {
		t.Fatalf("exe_name = %q, want notagame.exe", hit.ExeName)
	}
	if hit.FlowThreshold != flowScoreSuspect {
		t.Fatalf("flow_threshold = %d, want %d", hit.FlowThreshold, flowScoreSuspect)
	}
	// 低分忽略与"疑似但未连续上升"两条分支都落在 [0, 高分线) 区间。
	if hit.FlowScore < 0 || hit.FlowScore >= flowScoreHigh {
		t.Fatalf("flow_score = %d，期望 [0, %d)", hit.FlowScore, flowScoreHigh)
	}
	if hit.FlowScore != flowScoreSuspect {
		t.Logf("note: score=%d 走的是低分忽略分支（< 疑似线 %d）", hit.FlowScore, flowScoreSuspect)
	}
	if len(hit.SampleDsts) == 0 || hit.SampleDsts[0] != "45.56.121.2:9000" {
		t.Fatalf("sample_dsts = %v, want 含 45.56.121.2:9000", hit.SampleDsts)
	}

	// 子用例：大包单向流（payload 1200 → 非小包，且无回复包）→ 分数应低于
	// 疑似线，覆盖"低分忽略"分支（与上面疑似分支分开，用不同进程名分桶）。
	restore() // 恢复原反查
	restore2 := stubFlowProc(t, "BigFlow.exe")
	defer restore2()
	meta2 := testMeta("45.56.121.5", 9002)
	if feed(t, m, meta2, 30, 1200, 200*time.Millisecond) {
		t.Fatal("大包单向流不应注册")
	}
	var low *MissEntry
	rep2 := MissSnapshot()
	for i := range rep2.Entries {
		if rep2.Entries[i].ExeName == "bigflow.exe" {
			low = &rep2.Entries[i]
			break
		}
	}
	if low == nil {
		t.Fatalf("大包流未落 miss 条目：entries=%+v", rep2.Entries)
	}
	if low.FlowScore >= flowScoreSuspect {
		t.Fatalf("大包单向流 flow_score = %d，期望 < %d（低分忽略分支）", low.FlowScore, flowScoreSuspect)
	}
	if low.FlowThreshold != flowScoreSuspect {
		t.Fatalf("低分条目 flow_threshold = %d, want %d", low.FlowThreshold, flowScoreSuspect)
	}
	t.Logf("low-score 分支：score=%d threshold=%d hits=%d", low.FlowScore, low.FlowThreshold,
		low.Reasons[MissReasonFlowLowScore])
}

// TestMissP020261021_EntryDenominator 用例 2：入口分母。
// observed_total 随 ObserveUDPFlow 调用单调递增，registered_total 只在注册成功
// 时 +1，且 observed_total ≥ registered_total；/diag/metrics 同口径。
func TestMissP020261021_EntryDenominator(t *testing.T) {
	missTableReset()
	metricsObservedFlowTotal.Store(0)
	metricsRegisteredTotal.Store(0)

	restore := stubFlowProc(t, "TslGame.exe")
	defer restore()

	m := newDefaultManager()
	m.SetEnabled(true)

	// 已知游戏端口（PUBG 27015）→ 免打分快速注册，覆盖 registered 侧。
	meta := testMeta("45.56.121.3", 27015)
	if !feed(t, m, meta, 30, 80, 200*time.Millisecond) {
		t.Fatal("已知游戏端口高频小包流应注册成功")
	}

	rep := MissSnapshot()
	if rep.ObservedTotal < 20 {
		t.Fatalf("observed_total = %d, want >= 20（每次 ObserveUDPFlow 调用 +1）", rep.ObservedTotal)
	}
	if rep.RegisteredTotal != 1 {
		t.Fatalf("registered_total = %d, want 1", rep.RegisteredTotal)
	}
	if rep.ObservedTotal < rep.RegisteredTotal {
		t.Fatalf("observed_total(%d) < registered_total(%d)", rep.ObservedTotal, rep.RegisteredTotal)
	}

	// 已注册目标重复喂入不应再次 +1（幂等：covered 检查直接 false）。
	before := rep.RegisteredTotal
	m.ObserveUDPFlow(meta, 80)
	rep2 := MissSnapshot()
	if rep2.RegisteredTotal != before {
		t.Fatalf("重复流导致 registered_total 从 %d 变为 %d", before, rep2.RegisteredTotal)
	}
	if rep2.ObservedTotal <= rep.ObservedTotal {
		t.Fatalf("observed_total 未单调递增：%d -> %d", rep.ObservedTotal, rep2.ObservedTotal)
	}

	// /diag/metrics 与 miss 端点同口径。
	dm := DiagMetricsSnapshot()
	if dm.ObservedFlowTotal != rep2.ObservedTotal || dm.RegisteredTotal != rep2.RegisteredTotal {
		t.Fatalf("diag/metrics 与 miss 分母不一致：metrics=%d/%d miss=%d/%d",
			dm.ObservedFlowTotal, dm.RegisteredTotal, rep2.ObservedTotal, rep2.RegisteredTotal)
	}
	if dm.ObservedFlowTotal < dm.RegisteredTotal {
		t.Fatalf("observed_flow_total(%d) < registered_total(%d)", dm.ObservedFlowTotal, dm.RegisteredTotal)
	}
}

// TestMissP020261021_DisabledNotCounted 用例 3：GameLane 未激活时不计入口分母
// （口径 = 激活态流经的 UDP 包，避免关闭态把分母灌成假阳性）。
func TestMissP020261021_DisabledNotCounted(t *testing.T) {
	missTableReset()
	metricsObservedFlowTotal.Store(0)
	metricsRegisteredTotal.Store(0)

	m := newDefaultManager() // 未 SetEnabled(true)
	meta := testMeta("45.56.121.4", 9000)
	for i := 0; i < 20; i++ {
		m.ObserveUDPFlow(meta, 80)
	}
	rep := MissSnapshot()
	if rep.ObservedTotal != 0 {
		t.Fatalf("disabled 状态 observed_total = %d, want 0", rep.ObservedTotal)
	}
	if rep.RegisteredTotal != 0 || rep.Total != 0 {
		t.Fatalf("disabled 状态 registered/total = %d/%d, want 0/0", rep.RegisteredTotal, rep.Total)
	}
}
