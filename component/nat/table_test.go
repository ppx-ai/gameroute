package nat

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestTableRange(t *testing.T) {
	tbl := New()
	if tbl == nil {
		t.Fatal("New() returned nil")
	}
	// 空表 Range 应直接结束
	count := 0
	tbl.Range(func(key string, _ C.PacketSender) bool {
		count++
		return true
	})
	if count != 0 {
		t.Fatalf("empty table Range returned %d entries, want 0", count)
	}

	// 插入若干条目（GetOrCreate 创建的会话都应被遍历）
	_, _ = tbl.GetOrCreate("k1", func() C.PacketSender { return nil })
	_, _ = tbl.GetOrCreate("k2", func() C.PacketSender { return nil })
	_, _ = tbl.GetOrCreate("k3", func() C.PacketSender { return nil })

	seen := map[string]bool{}
	tbl.Range(func(key string, _ C.PacketSender) bool {
		seen[key] = true
		return true
	})
	for _, k := range []string{"k1", "k2", "k3"} {
		if !seen[k] {
			t.Fatalf("Range missing key %s", k)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("Range returned %d entries, want 3", len(seen))
	}

	// 提前终止（返回 false）应停止遍历
	visited := 0
	tbl.Range(func(key string, _ C.PacketSender) bool {
		visited++
		return false
	})
	if visited != 1 {
		t.Fatalf("Range did not stop on false, visited=%d", visited)
	}
}
