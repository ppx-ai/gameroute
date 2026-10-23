package gamelane

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// fakePacketConn 是基于真实 UDP socket 的 C.PacketConn 实现，用于验证数据流转与切换原子性。
type fakePacketConn struct {
	*net.UDPConn
	name   string
	closed atomic.Bool
}

func newFakePacketConn(t *testing.T, name string) *fakePacketConn {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp %s: %v", name, err)
	}
	return &fakePacketConn{UDPConn: uc, name: name}
}

func (f *fakePacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	buf := make([]byte, 65536)
	n, a, e := f.ReadFrom(buf)
	if e != nil {
		return nil, nil, a, e
	}
	return buf[:n], func() {}, a, nil
}

func (f *fakePacketConn) Chains() C.Chain                          { return nil }
func (f *fakePacketConn) ProviderChains() C.Chain                  { return nil }
func (f *fakePacketConn) AppendToChains(C.ProxyAdapter)            {}
func (f *fakePacketConn) RemoteDestination() string                { return "" }
func (f *fakePacketConn) ResolveUDP(context.Context, *C.Metadata) error { return nil }

func (f *fakePacketConn) Close() error {
	f.closed.Store(true)
	return f.UDPConn.Close()
}

// 测试用 SessionConn：直接注入 PacketConn，纯观测不切换
func newTestSessionConn(pc C.PacketConn, key string, isQUIC bool) *SessionConn {
	return NewSessionConn(pc, key, isQUIC, DefaultConfig(), nil)
}

// 计数：WriteTo 上行计数、WaitReadFrom 下行计数正确
func TestSessionConn_Counters(t *testing.T) {
	pc := newFakePacketConn(t, "primary")
	defer pc.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	sc := newTestSessionConn(pc, "k1", false)
	defer sc.Close()

	// 10 个上行包
	for i := 0; i < 10; i++ {
		if _, err := sc.WriteTo([]byte("up"), peer.LocalAddr()); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// 对端回 8 个下行包
	for i := 0; i < 8; i++ {
		if _, err := peer.WriteTo([]byte("down"), pc.LocalAddr()); err != nil {
			t.Fatalf("peer write: %v", err)
		}
	}
	for i := 0; i < 8; i++ {
		_, _, _, err := sc.WaitReadFrom()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}

	sent, recv := sc.Observer().Counters()
	if sent != 10 || recv != 8 {
		t.Fatalf("want sent=10 recv=8, got sent=%d recv=%d", sent, recv)
	}
}

// 原子切换：替换后读写走新连接，旧连接已关闭
func TestSessionConn_SwitchAtomic(t *testing.T) {
	pcA := newFakePacketConn(t, "A")
	defer pcA.Close()
	pcB := newFakePacketConn(t, "B")
	defer pcB.Close()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	sc := newTestSessionConn(pcA, "k2", false)
	defer sc.Close()

	// 切到 B：替换读路径并关闭旧连接
	sc.Switch(pcB)

	if pcA.closed.Load() != true {
		t.Fatal("old conn must be closed after switch")
	}
	if sc.Current() != pcB {
		t.Fatal("current conn must be B after switch")
	}

	// 读写走 B
	if _, err := sc.WriteTo([]byte("viaB"), peer.LocalAddr()); err != nil {
		t.Fatalf("write via B: %v", err)
	}
	// 只有 B 的地址能收到对端回包
	if _, err := peer.WriteTo([]byte("downB"), pcB.LocalAddr()); err != nil {
		t.Fatalf("peer write to B: %v", err)
	}
	if _, _, _, err := sc.WaitReadFrom(); err != nil {
		t.Fatalf("read via B: %v", err)
	}
}

// 未命中零影响：无任何会话时计数器保持零且不 panic
func TestSessionConn_NoSessionZeroImpact(t *testing.T) {
	var o Observer
	sent, recv := o.Counters()
	if sent != 0 || recv != 0 {
		t.Fatalf("empty observer must be zero, got %d/%d", sent, recv)
	}
}

// Observer 暴露可读统计供 predictor 使用
func TestSessionConn_ObserverSnapshot(t *testing.T) {
	pc := newFakePacketConn(t, "primary")
	defer pc.Close()
	sc := newTestSessionConn(pc, "k3", false)
	defer sc.Close()
	if sc.Observer().IsQUIC() {
		t.Fatal("isQUIC must be false")
	}
}

// Observer 时间戳上限：超过 256 个下行包后截断，Snapshot 仍返回非零 jitter
func TestSessionConn_ObserverTsCap(t *testing.T) {
	pc := newFakePacketConn(t, "primary")
	defer pc.Close()
	sc := newTestSessionConn(pc, "k4", false)
	defer sc.Close()

	// 285 个下行包，间隔 1ms，超出 256 上限触发截断
	for i := 0; i < 285; i++ {
		sc.Observer().OnRecv(64, time.UnixMilli(1000+int64(i)))
	}
	sent, recv, bytes, jitter := sc.Observer().Snapshot()
	if sent != 0 || recv != 285 || bytes != 285*64 {
		t.Fatalf("snapshot counters wrong: sent=%d recv=%d bytes=%d", sent, recv, bytes)
	}
	if jitter <= 0 {
		t.Fatalf("jitter must be > 0 after cap, got %v", jitter)
	}
}

// Switch 后再次 Switch：旧连接被逐个关闭，当前连接始终指向最新
func TestSessionConn_DoubleSwitch(t *testing.T) {
	pcA := newFakePacketConn(t, "A")
	defer pcA.Close()
	pcB := newFakePacketConn(t, "B")
	defer pcB.Close()
	pcC := newFakePacketConn(t, "C")
	defer pcC.Close()

	sc := newTestSessionConn(pcA, "k5", false)
	defer sc.Close()
	sc.Switch(pcB)
	sc.Switch(pcC)

	if pcA.closed.Load() != true || pcB.closed.Load() != true {
		t.Fatal("old conns must be closed after double switch")
	}
	if sc.Current() != pcC {
		t.Fatal("current conn must be C")
	}
	if sc.Close() != nil {
		t.Fatal("close must be nil")
	}
	// 重复 Close 幂等
	if sc.Close() != nil {
		t.Fatal("double close must be idempotent nil")
	}
}

// PacketConn/C.Connection 透传方法委托当前连接；Key 与 LastSettledLossRate 访问器
func TestSessionConn_DelegatesAndAccessors(t *testing.T) {
	pc := newFakePacketConn(t, "delegate")
	defer pc.Close()
	sc := NewSessionConn(pc, "kdelegate", false, DefaultConfig(), func(bool) error { return nil })
	defer sc.Close()

	if sc.Key() != "kdelegate" {
		t.Fatalf("want key kdelegate, got %q", sc.Key())
	}
	if sc.LastSettledLossRate() != 0 {
		t.Fatalf("want initial settled loss 0, got %v", sc.LastSettledLossRate())
	}
	if sc.LocalAddr() != pc.LocalAddr() {
		t.Fatal("LocalAddr must delegate to current conn")
	}
	if err := sc.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := sc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := sc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(sc.Chains()) != len(pc.Chains()) || len(sc.ProviderChains()) != len(pc.ProviderChains()) {
		t.Fatal("chain delegates must forward")
	}
	sc.AppendToChains(nil) // no panic
	if sc.RemoteDestination() != pc.RemoteDestination() {
		t.Fatal("RemoteDestination must delegate")
	}
	if err := sc.ResolveUDP(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	// ReadFrom 委托计数：写入下行包后可读回
	go func() {
		_, _ = pc.WriteTo([]byte("down"), sc.LocalAddr())
	}()
	buf := make([]byte, 64)
	n, _, err := sc.ReadFrom(buf)
	if err != nil || n == 0 {
		t.Fatalf("ReadFrom must delegate read, n=%d err=%v", n, err)
	}
	if sc.obs.recv.Load() == 0 {
		t.Fatal("ReadFrom must count received packet")
	}
}

// 未注入 ProbeDialer 时 beginProbe 按未恢复结算（覆盖 closed 与 nil dialer 分支）
func TestSessionConn_ProbeDialerNilSettlesUnrecovered(t *testing.T) {
	pc := newFakePacketConn(t, "nilprobe")
	defer pc.Close()
	sc := NewSessionConn(pc, "knilprobe", false, DefaultConfig(), func(bool) error { return nil })
	defer sc.Close()
	sc.beginProbe()
	if sc.p.primaryRecovered.Load() {
		t.Fatal("probe without dialer must not mark recovered")
	}
	// closed 分支：关闭后 beginProbe 同样按未恢复结算
	_ = sc.Close()
	sc.beginProbe()
	if sc.p.primaryRecovered.Load() {
		t.Fatal("probe on closed session must not mark recovered")
	}
}

