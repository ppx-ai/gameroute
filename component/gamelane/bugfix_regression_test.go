package gamelane

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// 构造"探测已完成（全部 done）、但 finishCandidateProbe 尚未结算"的候选探测状态。
func makeFinishedCandidateProbe() *candidateProbeState {
	return &candidateProbeState{
		names:     []string{"B"},
		conns:     []C.PacketConn{nil},
		sent:      []int{16},
		recv:      []int{16},
		rttSum:    []time.Duration{0},
		sendTimes: [][]time.Time{{time.Now(), time.Now()}},
		lastSend:  []time.Time{time.Now()},
		deadline:  time.Now().Add(time.Second),
		maxPkts:   16,
		scores:    []candidateScore{{name: "B", score: 85}},
		done:      []bool{true},
	}
}

// S1：Auto-Pick Primary 换优切换（探测完成选最优，比当前临时主节点更优才切）
// 必须走静默切换路径——不增加 switch_count / 不写 last_switch_at / 不改 loss_rate，
// current_proxy 由 SetPrimaryObserver 回报（RecordM3Active）单独刷新。
func TestSessionConn_AutoPickUpgradeIsSilent(t *testing.T) {
	pc := newFakePacketConn(t, "A")
	defer pc.Close()

	var (
		called   atomic.Bool
		swTo     atomic.Bool
		silentAt atomic.Bool
	)
	var sc *SessionConn
	sc = NewSessionConn(pc, "k", false, DefaultConfig(), func(toPrimary bool) error {
		called.Store(true)
		swTo.Store(toPrimary)
		silentAt.Store(sc.SwitchSilent())
		return nil
	})
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证的是探测完成后的切换路径
	sc.SetAutoPick(true)
	sc.SetCurrentPrimary("A")

	sc.candMu.Lock()
	sc.candProbe = makeFinishedCandidateProbe()
	sc.candMu.Unlock()

	sc.finishCandidateProbe()

	// 切换为异步 goroutine，轮询等待执行完成（最长 100ms）
	for i := 0; i < 50 && !called.Load(); i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if !called.Load() {
		t.Fatal("autoPick upgrade must trigger switch to best candidate")
	}
	if swTo.Load() {
		t.Fatal("autoPick upgrade must switch to fallback (toPrimary=false), not primary")
	}
	if !silentAt.Load() {
		t.Fatal("autoPick upgrade switch must be silent (must not count switch_count)")
	}
}

// SE1：会话 Close 后，候选探测完成不得再触发切换并新建连接（泄漏）。
// Close 必须清空 candProbe，使 finishCandidateProbe 安全返回。
func TestSessionConn_CloseStopsPendingCandidateSwitch(t *testing.T) {
	pc := newFakePacketConn(t, "A")
	defer pc.Close()

	var called atomic.Bool
	sc := NewSessionConn(pc, "k", false, DefaultConfig(), func(toPrimary bool) error {
		called.Store(true)
		return nil
	})
	sc.SetFallbacks([]string{"B"})

	sc.candMu.Lock()
	sc.candProbe = makeFinishedCandidateProbe()
	sc.candMu.Unlock()

	_ = sc.Close()
	sc.finishCandidateProbe()

	time.Sleep(100 * time.Millisecond) // 给异步 doSwitchAsync goroutine 机会执行
	if called.Load() {
		t.Fatal("candidate probe must not trigger switch after Close")
	}
}

// P1：Observer 必须按 上行发送时刻 → 下行到达时刻 配对计算 RTT。
func TestObserver_RttPairing(t *testing.T) {
	o := newObserver(false)
	base := time.Now()
	o.OnSent(base)
	o.OnRecv(10, base.Add(30*time.Millisecond))
	rtt := o.LastRTTMs()
	if rtt < 29 || rtt > 31 {
		t.Fatalf("want ~30ms RTT, got %v", rtt)
	}
	// 第二次下行与第二次上行配对（时间戳 FIFO）
	o.OnRecv(10, base.Add(60*time.Millisecond))
	if o.LastRTTMs() < 29 || o.LastRTTMs() > 31 {
		t.Fatalf("want second RTT ~30ms, got %v", o.LastRTTMs())
	}
}

// P1：afterPacket 必须把观测到的 RTT 喂给预测器窗口（rttMs > 0），
// 否则 RTT 维度（权重 30%）永久中性，RTT 劣化永不参与评分。
func TestSessionConn_AfterPacketFeedsRtt(t *testing.T) {
	pc := newFakePacketConn(t, "primary")
	defer pc.Close()
	sc := NewSessionConn(pc, "k", false, DefaultConfig(), func(toPrimary bool) error { return nil })

	sc.obs.OnSent(time.Now())
	time.Sleep(15 * time.Millisecond)
	sc.afterPacket(false, true, 10) // recv → 内部 OnRecv(now) → RTT≈15ms → OnPacketEx(rttMs)

	if len(sc.p.cur.rttMs) == 0 {
		t.Fatal("afterPacket must feed rttMs into predictor window")
	}
}

// G1：MatchTarget 在执行期间必须持有读锁（直到 findProcess 与 ensureAutoPicked
// 全部完成），否则 SetTargets/SetAllProxies/SetRTTTable 并发替换会让
// ensureAutoPicked 的写入作用在即将被替换的旧切片上（写回丢失 / 指针指向悬空）。
func TestManager_MatchTargetSerializesWithSetTargets(t *testing.T) {
	old := findProcess
	entered := make(chan struct{})
	release := make(chan struct{})
	findProcess = func(m *C.Metadata) (uint32, string) {
		close(entered)
		<-release
		return 0, ""
	}
	defer func() { findProcess = old }()

	m := newManager(true, []Target{{
		Proxy: "P1",
		CIDR:  []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")},
	}})
	m.SetAllProxies([]string{"P1"})
	m.SetRTTTable(map[string]int{"P1": 10})

	matched := make(chan struct{})
	go func() {
		m.MatchTarget(testMetadata("", "1.2.3.9"), false)
		close(matched)
	}()

	<-entered // findProcess 已进入，MatchTarget 正在执行

	setDone := make(chan struct{})
	go func() {
		m.SetTargets([]Target{})
		close(setDone)
	}()

	select {
	case <-setDone:
		t.Fatal("SetTargets must be blocked while MatchTarget holds read lock")
	case <-time.After(100 * time.Millisecond):
		// 期望：MatchTarget 持锁 → SetTargets 阻塞
	}

	close(release) // 放行 findProcess
	<-matched
	select {
	case <-setDone:
		// 期望：MatchTarget 完成 → SetTargets 得以执行
	case <-time.After(2 * time.Second):
		t.Fatal("SetTargets should complete after MatchTarget")
	}
}
