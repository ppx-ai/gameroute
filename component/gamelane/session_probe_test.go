package gamelane

import (
	"net"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// fillSessionWindow 真实时间喂满一个观测窗口：上行 sent 包 + 下行 recv 包，
// 下行包通过 WaitReadFrom 读回触发观测，睡眠跨过窗口边界触发结算。
func fillSessionWindow(t *testing.T, sc *SessionConn, peer *net.UDPConn, sent, recv int) {
	t.Helper()
	peerAddr := peer.LocalAddr()
	for i := 0; i < sent; i++ {
		if _, err := sc.WriteTo([]byte("probe"), peerAddr); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for i := 0; i < recv; i++ {
		if _, err := peer.WriteTo([]byte("down"), sc.Current().LocalAddr()); err != nil {
			t.Fatalf("peer write: %v", err)
		}
		if _, _, _, err := sc.WaitReadFrom(); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	time.Sleep(220 * time.Millisecond)
}

// 探测机制闭环：fallback 模式 B 好窗口达标后自动发起探测，
// 探测连接走 primary 出口（会话流量仍走 B），镜像会话上行包，
// 回包无丢包 → 探测成功回填 → 下一好窗口回切 primary。
func TestSessionConn_ProbeTriggerMirrorAndRollback(t *testing.T) {
	pcA := newFakePacketConn(t, "probeA")
	defer pcA.Close()
	pcB := newFakePacketConn(t, "sessionB")
	defer pcB.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 200 * time.Millisecond

	var mu sync.Mutex
	var toPrimaryCalls, toFallbackCalls int
	sc := NewSessionConn(pcB, "kprobe", false, cfg, func(toPrimary bool) error {
		mu.Lock()
		if toPrimary {
			toPrimaryCalls++
		} else {
			toFallbackCalls++
		}
		mu.Unlock()
		return nil
	})
	defer sc.Close()
	sc.protectedSince.Store(0) // 绕过初始保护期：本用例验证探测/回切机制
	sc.lastRecvAt.Store(0)     // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）
	sc.SetProbeDialer(func() (C.PacketConn, error) { return pcA, nil })

	// 轮询喂坏窗口直到切到 fallback（窗口相位漂移容忍）；死链 recv=0 才放行
	for i := 0; i < 10 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	time.Sleep(60 * time.Millisecond) // 等待异步切换
	mu.Lock()
	fc := toFallbackCalls
	mu.Unlock()
	if fc != 1 {
		t.Fatalf("want 1 switch to fallback, got %d", fc)
	}
	if sc.p.Mode() != modeFallback {
		t.Fatalf("want fallback mode, got %d", sc.p.Mode())
	}

	// 轮询喂好窗口直到自动发起探测（探测连接=pcA）
	probeStarted := false
	for i := 0; i < 15 && !probeStarted; i++ {
		fillSessionWindow(t, sc, peer, 100, 100)
		sc.probeMu.Lock()
		probeStarted = sc.probe != nil
		sc.probeMu.Unlock()
		if !probeStarted {
			time.Sleep(20 * time.Millisecond)
		}
	}
	sc.probeMu.Lock()
	pr := sc.probe
	sc.probeMu.Unlock()
	if pr == nil {
		t.Fatal("probe must begin after goodStreak reached")
	}
	// 探测在 fillSessionWindow 发包中途发起，窗口剩余上行包已被镜像并占满
	// sendTimes（旧时刻无对应 echo，会让 RTT 虚高到窗口 sleep 量级）。
	// 重置探测样本，使下方 mirror+echo 循环形成干净配对。
	sc.probeMu.Lock()
	if p := sc.probe; p != nil {
		p.sent = 0
		p.recv = 0
		p.rttSum = 0
		p.lastSend = time.Time{}
		p.sendTimes = p.sendTimes[:0]
	}
	sc.probeMu.Unlock()
	// 会话流量未切走：当前连接仍是 B
	if sc.Current() != pcB {
		t.Fatal("session must stay on B during probe")
	}

	// 探测期间镜像：会话上行包同时发往探测连接 pcA（≥32 触发结束），
	// 对端对每个 mirror 立即向探测连接回 echo（模拟 primary 恢复后正常回包，
	// RTT 为真实往返），同时向会话连接回包，维持观测窗口丢包平衡
	for i := 0; i < 40; i++ {
		if _, err := sc.WriteTo([]byte("mirror"), peer.LocalAddr()); err != nil {
			t.Fatalf("mirror write: %v", err)
		}
		if _, err := peer.WriteTo([]byte("echo"), pcA.LocalAddr()); err != nil {
			t.Fatalf("probe echo: %v", err)
		}
		if _, err := peer.WriteTo([]byte("down"), pcB.LocalAddr()); err != nil {
			t.Fatalf("session echo: %v", err)
		}
		if _, _, _, err := sc.WaitReadFrom(); err != nil {
			t.Fatalf("session read: %v", err)
		}
	}
	time.Sleep(120 * time.Millisecond)
	// 等待探测结算（读循环 20ms 超时轮询 + 结算；echo 立即回包会使探测在读循环内提前结算并置 probe=nil）
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sc.probeMu.Lock()
		done := sc.probe == nil
		sc.probeMu.Unlock()
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sc.probeMu.Lock()
	done := sc.probe == nil
	sc.probeMu.Unlock()
	if !done {
		t.Fatal("probe must finish and settle")
	}
	// probe=nil 仅表示槽位释放，结论回填在 OnPrimaryProbe 内稍后完成；
	// 轮询等待 primaryProbed 置位，避免断言读到回填前的旧值。
	probeSettled := false
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !probeSettled {
		probeSettled = sc.p.primaryProbed.Load()
		if !probeSettled {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !probeSettled {
		t.Fatal("probe conclusion must be settled")
	}
	if !sc.p.primaryRecovered.Load() {
		t.Fatal("probe with zero loss must mark primary recovered")
	}
	sc.protectedSince.Store(0) // 切到 fallback 后保护期已重置，回切 primary 前需再次绕过

	// 下一好窗口：探测结论已置位，但会话存活（期间仍持续收到回包，
	// lastRecvAt 不断刷新）——v2.8 第一刀：对局会话有回包即严禁任何
	// rebuild session，回切 primary 同样禁止（钉死进场节点）。
	switchedBack := false
	for i := 0; i < 15 && !switchedBack; i++ {
		fillSessionWindow(t, sc, peer, 100, 100)
		mu.Lock()
		switchedBack = toPrimaryCalls >= 1
		mu.Unlock()
		if !switchedBack {
			time.Sleep(20 * time.Millisecond)
		}
	}
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	tp := toPrimaryCalls
	mu.Unlock()
	if tp != 0 {
		t.Fatalf("v2.8: session alive (recv within 10s) must NOT rollback to primary, got %d calls (mode=%d probed=%v recovered=%v streak=%d)",
			tp, sc.p.Mode(), sc.p.primaryProbed.Load(), sc.p.primaryRecovered.Load(), sc.p.goodStreak)
	}
	// 连接必须保持 fallback（钉死进场节点）：predictor 内部模式可能因探测
	// 结论翻回 primary，但实际连接不得切换/重建（toPrimaryCalls==0 已验
	// 证 switchFn 未被调用）。当前连接仍为 pcB 即表示零 rebuild session。
	if sc.Current() != pcB {
		t.Fatal("switchFn no-op: current must remain B")
	}
}

// 探测失败：镜像无回包 → 探测判定 primary 未恢复，会话维持 B、不回切。
func TestSessionConn_ProbeFailureKeepsFallback(t *testing.T) {
	pcA := newFakePacketConn(t, "probeA")
	defer pcA.Close()
	pcB := newFakePacketConn(t, "sessionB")
	defer pcB.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	cfg := DefaultConfig()
	cfg.WindowDuration = 200 * time.Millisecond
	var mu sync.Mutex
	var toPrimaryCalls int
	sc := NewSessionConn(pcB, "kprobe2", false, cfg, func(toPrimary bool) error {
		if toPrimary {
			mu.Lock()
			toPrimaryCalls++
			mu.Unlock()
		}
		return nil
	})
	defer sc.Close()
	sc.SetProbeDialer(func() (C.PacketConn, error) { return pcA, nil })
	sc.lastRecvAt.Store(0) // 无回包 = 真死链（v2.8 第一刀：10s 内有回包严禁切换）

	// 轮询喂坏窗口直到切到 fallback；死链 recv=0 才放行
	for i := 0; i < 10 && sc.p.Mode() != modeFallback; i++ {
		fillSessionWindow(t, sc, peer, 100, 0)
	}
	time.Sleep(60 * time.Millisecond)
	if sc.p.Mode() != modeFallback {
		t.Fatalf("want fallback, got %d", sc.p.Mode())
	}
	// 轮询喂好窗口直到探测发起
	probeStarted := false
	for i := 0; i < 15 && !probeStarted; i++ {
		fillSessionWindow(t, sc, peer, 100, 100)
		sc.probeMu.Lock()
		probeStarted = sc.probe != nil
		sc.probeMu.Unlock()
		if !probeStarted {
			time.Sleep(20 * time.Millisecond)
		}
	}
	sc.probeMu.Lock()
	started := sc.probe != nil
	sc.probeMu.Unlock()
	if !started {
		t.Fatal("probe must start on goodStreak")
	}
	// 触发探测：发送 40 镜像包（同步会话回包平衡窗口），但绝不向探测连接回包
	for i := 0; i < 40; i++ {
		_, _ = sc.WriteTo([]byte("mirror"), peer.LocalAddr())
		_, _ = peer.WriteTo([]byte("down"), pcB.LocalAddr())
		_, _, _, _ = sc.WaitReadFrom()
	}
	// 等待探测超时/结算
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		sc.probeMu.Lock()
		done := sc.probe == nil
		sc.probeMu.Unlock()
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sc.p.primaryRecovered.Load() {
		// 预期未恢复
	}
	if sc.p.primaryRecovered.Load() {
		t.Fatal("probe with no echo must NOT mark primary recovered")
	}
	if sc.p.Mode() != modeFallback {
		t.Fatalf("must stay fallback on probe failure, got %d", sc.p.Mode())
	}
	mu.Lock()
	tp := toPrimaryCalls
	mu.Unlock()
	if tp != 0 {
		t.Fatalf("no rollback allowed on probe failure, got %d calls", tp)
	}
}

