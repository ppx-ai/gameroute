package gamelane

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// candidateFakeConn 候选体检模拟连接：WriteTo 后按配置延迟/丢包向自身队列
// "回包"，模拟候选出口的 RTT 与丢包特性（无需真实对端参与）。
type candidateFakeConn struct {
	queue    chan []byte
	delay    time.Duration // 模拟候选 RTT
	lossStep int           // 每 N 个包丢 1 个；0 表示不丢
	seq      int
	addr     net.Addr
}

func newCandidateFakeConn(delay time.Duration, lossStep int) *candidateFakeConn {
	return &candidateFakeConn{
		queue:    make(chan []byte, 256),
		delay:    delay,
		lossStep: lossStep,
		addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9998},
	}
}

func (c *candidateFakeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.seq++
	if c.lossStep > 0 && c.seq%c.lossStep == 0 {
		return len(p), nil // 模拟丢包：不回包
	}
	data := append([]byte(nil), p...)
	go func() {
		time.Sleep(c.delay)
		c.queue <- data
	}()
	return len(p), nil
}

func (c *candidateFakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case data := <-c.queue:
		return copy(b, data), c.addr, nil
	case <-time.After(3 * time.Second):
		return 0, nil, net.ErrClosed
	}
}

func (c *candidateFakeConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	select {
	case data := <-c.queue:
		return data, func() {}, c.addr, nil
	case <-time.After(3 * time.Second):
		return nil, nil, nil, net.ErrClosed
	}
}

func (c *candidateFakeConn) Close() error                       { return nil }
func (c *candidateFakeConn) LocalAddr() net.Addr                { return c.addr }
func (c *candidateFakeConn) SetDeadline(time.Time) error        { return nil }
func (c *candidateFakeConn) SetReadDeadline(time.Time) error    { return nil }
func (c *candidateFakeConn) SetWriteDeadline(time.Time) error   { return nil }
func (c *candidateFakeConn) Chains() C.Chain                    { return nil }
func (c *candidateFakeConn) ProviderChains() C.Chain            { return nil }
func (c *candidateFakeConn) AppendToChains(C.ProxyAdapter)      {}
func (c *candidateFakeConn) RemoteDestination() string          { return "" }
func (c *candidateFakeConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

// 验收场景：主出口劣化（15% 丢包触发），候选池 B1 延迟高 / B2 延迟低，
// 切换前对候选逐个体检评分 → 应自动选中低延迟的 B2 并切换。
func TestSessionConn_CandidateProbeSelectsBest(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 150 * time.Millisecond

	var mu sync.Mutex
	var switchedTo string
	var toFallbackCalls int
	var sc *SessionConn
	sc = NewSessionConn(pcP, "kcand", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls++
			switchedTo = sc.SelectedFallback()
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证候选体检选中切换
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	// 候选池：B1 延迟高、B2 延迟低，均无丢包 → 综合分 B2 更高
	sc.SetFallbacks([]string{"B1", "B2"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		switch name {
		case "B1":
			return newCandidateFakeConn(150*time.Millisecond, 0), nil
		case "B2":
			return newCandidateFakeConn(20*time.Millisecond, 0), nil
		}
		return nil, net.ErrClosed
	})

	// 轮询喂坏窗口直到切到 fallback（触发候选体检，切换在体检完成后发生）
	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	// 候选体检可能已在喂包期间完成（B2 低延迟：16 包在 fillSessionWindow
	// 的 sleep 内即可收满），此处不要求 candProbe 仍在探测中；
	// 仅要求最终完成并选中最优出口（下面等待循环 + 断言覆盖）。

	// 等待候选体检完成（candProbe 置空）；期间持续喂上行包提供镜像样本
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sc.candMu.Lock()
		done := sc.candProbe == nil
		sc.candMu.Unlock()
		if done {
			break
		}
		fillSessionWindow(t, sc, peer, 40, 0)
		time.Sleep(20 * time.Millisecond)
	}
	sc.candMu.Lock()
	done := sc.candProbe == nil
	sc.candMu.Unlock()
	if !done {
		t.Fatal("candidate probe must finish")
	}
	if got := sc.SelectedFallback(); got != "B2" {
		t.Fatalf("want selected fallback B2 (low RTT), got %q", got)
	}
	mu.Lock()
	st, tf := switchedTo, toFallbackCalls
	mu.Unlock()
	if st != "B2" {
		t.Fatalf("want switch to B2, got %q", st)
	}
	if tf != 1 {
		t.Fatalf("want 1 fallback switch, got %d", tf)
	}
}

// 回归：单候选（或未注入候选 dialer）保持旧行为——劣化直接切换，
// 不创建候选体检、不引入额外延迟，避免乒乓（切换次数恒为 1）。
func TestSessionConn_CandidateProbeSingleFallbackDirectSwitch(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 150 * time.Millisecond

	var mu sync.Mutex
	var toFallbackCalls int
	sc := NewSessionConn(pcP, "kcand1", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls++
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证单候选直接切换
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	// 单候选：即使注入了候选 dialer，也不应启动体检
	sc.SetFallbacks([]string{"B1"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		return newCandidateFakeConn(10*time.Millisecond, 0), nil
	})

	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	time.Sleep(80 * time.Millisecond)
	sc.candMu.Lock()
	cp := sc.candProbe
	sc.candMu.Unlock()
	if cp != nil {
		t.Fatal("single fallback must not start candidate probe")
	}
	if got := sc.SelectedFallback(); got != "B1" {
		t.Fatalf("SelectedFallback = %q, want B1", got)
	}
	mu.Lock()
	tf := toFallbackCalls
	mu.Unlock()
	if tf != 1 {
		t.Fatalf("want exactly 1 fallback switch (no ping-pong), got %d", tf)
	}
}

// 稀疏流量兜底：候选连接始终无回包（全部超时 0 分），体检不应卡死，
// 兜底切候选池首元素；切换发生在探测超时（5s）之后而非永远挂起。
func TestSessionConn_CandidateProbeSparseTrafficFallbackFirst(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 150 * time.Millisecond
	cfg.CandidateProbeTimeout = 300 * time.Millisecond // 缩短超时加速测试

	var mu sync.Mutex
	var switchedTo string
	var toFallbackCalls int
	var sc *SessionConn
	sc = NewSessionConn(pcP, "kcandSparse", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls++
			switchedTo = sc.SelectedFallback()
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证稀疏流量兜底切换
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	// 两个候选均无回包（delay 极大，超过探测超时）
	sc.SetFallbacks([]string{"FIRST", "SECOND"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		return newCandidateFakeConn(10*time.Second, 0), nil
	})

	// 喂坏窗口触发候选体检
	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	// 等待兜底切换完成（最坏耗时 = 探测超时，不卡死）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		st, tf := switchedTo, toFallbackCalls
		mu.Unlock()
		if tf >= 1 {
			if st != "FIRST" {
				t.Fatalf("sparse traffic must fall back to first candidate, got %q", st)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	st, tf := switchedTo, toFallbackCalls
	mu.Unlock()
	if tf != 1 {
		t.Fatalf("sparse traffic must switch exactly once, got %d", tf)
	}
	if st != "FIRST" {
		t.Fatalf("want fallback to FIRST, got %q", st)
	}
	if got := sc.SelectedFallback(); got != "FIRST" {
		t.Fatalf("SelectedFallback = %q, want FIRST", got)
	}
}

// 懒测 interval 下限：一次候选体检完成后，60s（CooldownCandidateInterval）
// 内再次劣化不应重复发起体检，直接切换并保持既有选中结果。
func TestSessionConn_CandidateProbeCooldownSkips(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 150 * time.Millisecond
	cfg.CooldownCandidateInterval = 60 * time.Second

	var mu sync.Mutex
	var switchedTo string
	var toFallbackCalls int
	var sc *SessionConn
	sc = NewSessionConn(pcP, "kcandCd", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls++
			switchedTo = sc.SelectedFallback()
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证冷却期跳过体检
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	sc.SetFallbacks([]string{"B1", "B2"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		switch name {
		case "B1":
			return newCandidateFakeConn(150*time.Millisecond, 0), nil
		case "B2":
			return newCandidateFakeConn(20*time.Millisecond, 0), nil
		}
		return nil, net.ErrClosed
	})

	// 第一次劣化：体检完成选中 B2 并切换
	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		st, tf := switchedTo, toFallbackCalls
		mu.Unlock()
		if tf >= 1 && st == "B2" {
			break
		}
		fillSessionWindow(t, sc, peer, 40, 0)
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	st, tf := switchedTo, toFallbackCalls
	mu.Unlock()
	if st != "B2" || tf != 1 {
		t.Fatalf("first round: want switch B2 once, got %q x%d", st, tf)
	}

	// 模拟回切 primary（重置预测器到 primary 模式），再次劣化：
	// 60s 冷却内不得重复体检，candProbe 必须保持 nil（直接 doSwitchAsync）
	sc.p.mode = modePrimary
	sc.p.badStreak = 0
	sc.p.goodStreak = 0
	sc.p.cooldownTill = time.Time{}
	sc.p.rollbackPending = false
	sc.p.rollbackCooldownTill = time.Time{}
	sc.protectedSince.Store(0) // 首次切换后保护期已重置，第二次劣化前需再次绕过
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	// cur 仍为 pcP（体检完成仅触发上层回调，不替换会话连接），无需再 Switch
	// 冷却期模拟：candLastFinish 已由首次体检写入（距现在不足 60s）
	// 再触发第二次劣化
	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	time.Sleep(120 * time.Millisecond)
	sc.candMu.Lock()
	cp := sc.candProbe
	sc.candMu.Unlock()
	if cp != nil {
		t.Fatal("candidate probe must be skipped within cooldown interval")
	}
	mu.Lock()
	tf2 := toFallbackCalls
	mu.Unlock()
	if tf2 != 2 {
		t.Fatalf("want 2nd direct fallback switch, got %d", tf2)
	}
	// 选中结果仍沿用首次体检结论
	if got := sc.SelectedFallback(); got != "B2" {
		t.Fatalf("SelectedFallback = %q, want B2 (kept from first probe)", got)
	}
}

// 候选 dial 失败：记录 0 分并推进下一个；全部失败时退化为选最高分候选切换，
// 会话不因体检失败而卡死。
func TestSessionConn_CandidateProbeDialFailFallsThrough(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 150 * time.Millisecond

	var mu sync.Mutex
	var switchedTo string
	var toFallbackCalls int
	var sc *SessionConn
	sc = NewSessionConn(pcP, "kcand2", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if !toPrimary {
			toFallbackCalls++
			switchedTo = sc.SelectedFallback()
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证建连失败退化为最优候选
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	sc.SetFallbacks([]string{"BAD1", "BAD2", "GOOD3"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		switch name {
		case "GOOD3":
			return newCandidateFakeConn(10*time.Millisecond, 0), nil
		default:
			return nil, net.ErrClosed // BAD1/BAD2 建连失败
		}
	})

	// 喂坏窗口触发候选体检（BAD1/BAD2 建连失败记 0 分，GOOD3 胜出）
	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	time.Sleep(60 * time.Millisecond)
	// 等待体检完成并切换到 GOOD3（探测可能在 60ms 内已完成）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		st, tf := switchedTo, toFallbackCalls
		mu.Unlock()
		if tf >= 1 && st == "GOOD3" {
			break
		}
		fillSessionWindow(t, sc, peer, 40, 0)
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	st, tf := switchedTo, toFallbackCalls
	mu.Unlock()
	if st != "GOOD3" {
		t.Fatalf("want switch to GOOD3, got %q", st)
	}
	if tf != 1 {
		t.Fatalf("want 1 fallback switch, got %d", tf)
	}
	if got := sc.SelectedFallback(); got != "GOOD3" {
		t.Fatalf("SelectedFallback = %q, want GOOD3", got)
	}
}

// 并发 2 路上限：dialer 内统计同时在建连的候选数，必须 ≤2；
// 3 个候选均慢速建连，确保第 3 个等待前两个释放槽位后才开始。
func TestSessionConn_CandidateProbeConcurrencyLimit(t *testing.T) {
	pcP := newFakePacketConn(t, "primary")
	defer pcP.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 150 * time.Millisecond
	cfg.CandidateProbeTimeout = 3 * time.Second

	var mu sync.Mutex
	var active, peak int
	slowConn := func(name string) C.PacketConn {
		// 模拟慢速建连：占用槽位 300ms
		c := newCandidateFakeConn(10*time.Millisecond, 0)
		time.Sleep(300 * time.Millisecond)
		return c
	}
	sc := NewSessionConn(pcP, "kcandConc", false, cfg, func(toPrimary bool) error { return nil })
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证候选探测并发上限
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	sc.SetFallbacks([]string{"C1", "C2", "C3"})
	sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		return slowConn(name), nil
	})

	// 喂坏窗口触发候选体检（3 候选并发上限 4，v6.1 放宽 2-4 路）
	for i := 0; i < 15 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	// 等待体检完成
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		sc.candMu.Lock()
		done := sc.candProbe == nil
		sc.candMu.Unlock()
		if done {
			break
		}
		fillSessionWindow(t, sc, peer, 20, 0)
		time.Sleep(30 * time.Millisecond)
	}
	sc.candMu.Lock()
	done := sc.candProbe == nil
	sc.candMu.Unlock()
	if !done {
		t.Fatal("candidate probe must finish")
	}
	mu.Lock()
	pk := peak
	mu.Unlock()
	if pk > 4 {
		t.Fatalf("candidate probe concurrency exceeded limit: peak=%d, want <=4", pk)
	}
	if pk < 1 {
		t.Fatal("candidate probe concurrency never observed")
	}
}
