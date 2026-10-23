package gamelane

import (
	"net/netip"
	"testing"
)

// TestTargetExtFieldsSnapshot 验证：命中 → recordTargetHit 写入扩展字段
// → GetTargets 快照能读到 packets/current_proxy/current_region/last_seen。
func TestTargetExtFieldsSnapshot(t *testing.T) {
	m := newManager(true, nil)
	prefix, _ := netip.ParsePrefix("100.58.89.106/32")
	m.SetTargets([]Target{
		{CIDR: []netip.Prefix{prefix}, Proxy: "auto"},
	})
	m.SetAllProxies([]string{"香港-01", "新加坡-01"})
	m.SetRTTTable(map[string]int{"香港-01": 22, "新加坡-01": 35})

	// 命中：dstIP 落在 CIDR 内
	md := gameMetadata("100.58.89.106", 443)
	tgt, ok := m.MatchTarget(md, true)
	if !ok {
		t.Fatal("want match hit")
	}
	if tgt == nil {
		t.Fatal("want non-nil target")
	}
	// 命中后扩展字段应已写入
	tgt.extMu.RLock()
	packets := tgt.Packets
	cp := tgt.CurrentProxy
	cr := tgt.CurrentRegion
	ls := tgt.LastSeen
	tgt.extMu.RUnlock()
	if packets == 0 {
		t.Fatal("want packets>0 after hit")
	}
	if cp == "" {
		t.Fatal("want current_proxy set after hit")
	}
	if cr == "" {
		t.Fatal("want current_region set after hit")
	}
	if ls == nil {
		t.Fatal("want last_seen set after hit")
	}

	// GetTargets 快照应包含扩展字段
	ts := m.GetTargets()
	if len(ts) != 1 {
		t.Fatalf("want 1 target, got %d", len(ts))
	}
	got := ts[0]
	if got.Packets != packets {
		t.Fatalf("want packets=%d via snapshot, got %d", packets, got.Packets)
	}
	if got.CurrentProxy != cp {
		t.Fatalf("want current_proxy=%s via snapshot, got %s", cp, got.CurrentProxy)
	}
	if got.CurrentRegion != cr {
		t.Fatalf("want current_region=%s via snapshot, got %s", cr, got.CurrentRegion)
	}
	if got.LastSeen == nil {
		t.Fatal("want last_seen via snapshot")
	}
}

// TestTargetExtFieldsTCP 验证 TCP 固定通道命中也会更新扩展字段。
func TestTargetExtFieldsTCP(t *testing.T) {
	m := newManager(true, nil)
	prefix, _ := netip.ParsePrefix("100.58.89.106/32")
	m.SetTargets([]Target{
		{CIDR: []netip.Prefix{prefix}, Proxy: "auto"},
	})
	m.SetAllProxies([]string{"香港-01", "新加坡-01"})
	m.SetRTTTable(map[string]int{"香港-01": 22, "新加坡-01": 35})

	md := gameMetadata("100.58.89.106", 443)
	px, ok := m.MatchTCP(md, true)
	if !ok {
		t.Fatal("want tcp match hit")
	}
	if px == "" {
		t.Fatal("want tcp proxy chosen")
	}
	ts := m.GetTargets()
	if len(ts) != 1 {
		t.Fatalf("want 1 target, got %d", len(ts))
	}
	got := ts[0]
	if got.Packets == 0 {
		t.Fatal("want packets>0 after tcp hit")
	}
	if got.CurrentProxy != px {
		t.Fatalf("want current_proxy=%s after tcp hit, got %s", px, got.CurrentProxy)
	}
	if got.LastSeen == nil {
		t.Fatal("want last_seen after tcp hit")
	}
}
