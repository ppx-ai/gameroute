package gamelane

import (
	"context"
	"net"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// fakeConn 最小 PacketConn：写路径记录写入内容，读路径从收包队列取数据。
type fakeConn struct {
	written [][]byte
	queue   chan []byte
	closed  bool
	addr    net.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{queue: make(chan []byte, 256), addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}}
}

func (f *fakeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	f.written = append(f.written, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case data := <-f.queue:
		n := copy(b, data)
		return n, f.addr, nil
	case <-time.After(2 * time.Second):
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	select {
	case data := <-f.queue:
		return data, func() {}, f.addr, nil
	case <-time.After(2 * time.Second):
		return nil, nil, nil, net.ErrClosed
	}
}

func (f *fakeConn) Close() error                       { f.closed = true; return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return f.addr }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }
func (f *fakeConn) Chains() C.Chain                    { return nil }
func (f *fakeConn) ProviderChains() C.Chain            { return nil }
func (f *fakeConn) AppendToChains(adapter C.ProxyAdapter) {}
func (f *fakeConn) RemoteDestination() string          { return "" }
func (f *fakeConn) ResolveUDP(ctx context.Context, metadata *C.Metadata) error { return nil }
