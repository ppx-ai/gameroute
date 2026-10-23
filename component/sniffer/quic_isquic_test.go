package sniffer

import "testing"

// P2：quicPacketSender 必须能向 tunnel 层暴露"本会话是否已 sniff 判定为 QUIC"，
// 否则 NewSessionConn 的 isQUIC 恒为 false（RTT 权重与 jitter 维度永不生效）。
func TestQuicPacketSender_IsQUIC(t *testing.T) {
	q := &quicPacketSender{done: make(chan struct{})}
	if q.IsQUIC() {
		t.Fatal("must be false before sniff result")
	}
	q.lock.Lock()
	q.result = "example.com"
	q.lock.Unlock()
	if !q.IsQUIC() {
		t.Fatal("must be true after sniff result")
	}
	q.closed = true
	if q.IsQUIC() {
		t.Fatal("must be false after closed")
	}
}
