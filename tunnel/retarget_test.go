package tunnel

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/gamelane"
	C "github.com/metacubex/mihomo/constant"
)

func TestDstMatchTargets(t *testing.T) {
	targets := []gamelane.Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("20.198.217.103/32")}},
		{CIDR: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
	}
	cases := []struct {
		dst  string
		want bool
	}{
		{"20.198.217.103", true},   // /32 精确命中
		{"10.1.2.3", true},         // 网段命中
		{"20.198.217.104", false},  // 未命中
		{"8.8.8.8", false},         // 无关目标
		{"", false},                // 空目标
		{"not-an-ip", false},       // 非法 IP
		{"2001:db8::1", false},     // IPv6 不命中 IPv4 前缀
	}
	for _, c := range cases {
		if got := dstMatchTargets(c.dst, targets); got != c.want {
			t.Errorf("dstMatchTargets(%q) = %v, want %v", c.dst, got, c.want)
		}
	}
}

func TestCollectRetargetKeys(t *testing.T) {
	// v6.6：collectRetargetKeys 遍历 natTable 真实会话，dst 判定用 laneCache。
	// 清理历史残留后再注入本用例的会话。
	natTable.Range(func(key string, _ C.PacketSender) bool {
		natTable.Delete(key)
		return true
	})

	cache := xsync.NewMap[string, *laneEntry]()
	// 在 lane 上的会话若 dst 命中 targets 同样强制重建（v6.6 全表扫描语义）
	natTable.GetOrCreate("lane-ok", newPacketSender)
	cache.Store("lane-ok", &laneEntry{onLane: true, dst: "20.198.217.103"})
	// 未在 lane 上且目标命中新 targets → 应删除
	natTable.GetOrCreate("miss-hit", newPacketSender)
	cache.Store("miss-hit", &laneEntry{onLane: false, dst: "20.198.217.103"})
	// 未在 lane 上但目标不命中 → 保留
	natTable.GetOrCreate("miss-no", newPacketSender)
	cache.Store("miss-no", &laneEntry{onLane: false, dst: "8.8.8.8"})
	// 未在 lane 上且无 dst → 无法判定，保留
	natTable.GetOrCreate("miss-empty", newPacketSender)
	cache.Store("miss-empty", &laneEntry{onLane: false, dst: ""})

	targets := []gamelane.Target{
		{CIDR: []netip.Prefix{netip.MustParsePrefix("20.198.217.103/32")}},
	}

	keys := collectRetargetKeys(cache, targets)
	if len(keys) != 2 {
		t.Fatalf("collectRetargetKeys = %v, want exactly [lane-ok miss-hit] (any order)", keys)
	}
	got := make(map[string]bool, len(keys))
	for _, k := range keys {
		got[k] = true
	}
	if !got["lane-ok"] || !got["miss-hit"] {
		t.Fatalf("collectRetargetKeys = %v, want [lane-ok miss-hit]", keys)
	}
}

func TestCollectRetargetKeysEmptyTargets(t *testing.T) {
	cache := xsync.NewMap[string, *laneEntry]()
	cache.Store("miss-hit", &laneEntry{onLane: false, dst: "20.198.217.103"})
	// 空 targets 不触发任何删除（避免误伤）
	keys := collectRetargetKeys(cache, nil)
	if len(keys) != 0 {
		t.Fatalf("empty targets should not retarget, got %v", keys)
	}
}
