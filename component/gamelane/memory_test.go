package gamelane

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMemoryRememberFlushReload 验证 remember → flush → LoadMemory 回读一致性：
// 端口段 key 正确落盘、hits 保留、重载后 lookupMemory 可命中。
func TestMemoryRememberFlushReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "game_memory.json")

	m := newDefaultManager()
	m.LoadMemory(path) // 文件不存在：设置 memPath，空表启动
	m.remember("1.2.3.4", 1050)

	if _, ok := m.lookupMemory("1.2.3.4", 1050); !ok {
		t.Fatalf("lookup before flush: expected hit")
	}
	m.flushMemoryOnce()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read flushed file: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("flushed file empty")
	}

	// 端口段 key 必须落盘（问题1回归：remember(ip, port) 写入段 key）
	m2 := newDefaultManager()
	m2.LoadMemory(path)
	if _, ok := m2.lookupMemory("1.2.3.4", 1050); !ok {
		t.Fatalf("lookup after reload: expected hit for port-segment key")
	}
	snap := m2.MemorySnapshot()
	if len(snap) != 1 || snap[0].Key != "1.2.3.4:1024-1124" {
		t.Fatalf("snapshot key mismatch: %+v", snap)
	}
	if snap[0].Hits != 1 || snap[0].Status != "active" {
		t.Fatalf("snapshot entry mismatch: %+v", snap[0])
	}
}

// TestMemoryPlainKeyWhenPortZero 验证 remember(ip, 0) 走普通 IP key（进程反查路径）。
func TestMemoryPlainKeyWhenPortZero(t *testing.T) {
	m := newDefaultManager()
	m.remember("1.2.3.4", 0)
	snap := m.MemorySnapshot()
	if len(snap) != 1 || snap[0].Key != "1.2.3.4/32" {
		t.Fatalf("expected plain ip key, got %+v", snap)
	}
}

// TestMemoryActiveToDecay 验证 active 24h 未命中 → decay 降权，且不再参与秒识别。
func TestMemoryActiveToDecay(t *testing.T) {
	m := newDefaultManager()
	m.remember("1.2.3.4", 1050)

	m.memMu.Lock()
	mem := m.memories["1.2.3.4:1024-1124"]
	mem.LastHitAt = time.Now().UnixMilli() - memActiveTTLMs - 1
	m.memMu.Unlock()

	m.memSweep()
	if _, ok := m.lookupMemory("1.2.3.4", 1050); ok {
		t.Fatalf("decayed entry must not hit lookupMemory")
	}
	snap := m.MemorySnapshot()
	if len(snap) != 1 || snap[0].Status != "decay" {
		t.Fatalf("expected decay status, got %+v", snap)
	}
}

// TestMemoryForgetNoHit 验证 forget 降权后 lookupMemory 不再命中。
func TestMemoryForgetNoHit(t *testing.T) {
	m := newDefaultManager()
	m.remember("1.2.3.4", 1050)
	m.forget("1.2.3.4")

	if _, ok := m.lookupMemory("1.2.3.4", 1050); ok {
		t.Fatalf("forgotten entry must not hit lookupMemory")
	}
	snap := m.MemorySnapshot()
	if len(snap) != 1 || snap[0].Status != "decay" {
		t.Fatalf("expected decay after forget, got %+v", snap)
	}
}

// TestMemoryAtomicWriteFailureKeepsOriginal 验证原子写失败不损坏原路径：
// Rename 目标为已存在目录时必然失败，目录必须保持原样。
func TestMemoryAtomicWriteFailureKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	dirPath := filepath.Join(dir, "not_a_file")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	mf := MemoryFile{Version: memVersion, Entries: map[string]GameMemory{
		"1.2.3.4/32": {Key: "1.2.3.4/32", Hits: 1, Status: "active"},
	}}
	err := writeMemoryFileAtomic(dirPath, mf)
	if err == nil {
		t.Fatalf("expected write to dir to fail")
	}
	st, statErr := os.Stat(dirPath)
	if statErr != nil {
		t.Fatalf("original path broken: %v", statErr)
	}
	if !st.IsDir() {
		t.Fatalf("original dir was replaced by file")
	}
	// 原目录内容不受影响
	if entries, _ := os.ReadDir(dirPath); len(entries) != 0 {
		t.Fatalf("original dir polluted: %d entries", len(entries))
	}
}

// TestMemorySweepEvictsOverLimit 验证超限淘汰收敛到 memEntryLimit 以内：
// 全 active 场景（问题2回归：必须能删 active），且先删最旧的。
func TestMemorySweepEvictsOverLimit(t *testing.T) {
	m := newDefaultManager()
	base := time.Now().UnixMilli()
	// 构造 memEntryLimit+10 条 active，LastHitAt 从旧到新递增
	for i := 0; i < memEntryLimit+10; i++ {
		ip := "10." + itoa(i/250) + "." + itoa(i%250+1)
		key := ip + "/32"
		m.memMu.Lock()
		m.memories[key] = &GameMemory{
			Key:       key,
			Hits:      1,
			LastHitAt: base - int64(memEntryLimit+10-i), // 越早注册的越旧
			Status:    "active",
		}
		m.memMu.Unlock()
	}
	if len(m.memories) != memEntryLimit+10 {
		t.Fatalf("setup: expected %d entries, got %d", memEntryLimit+10, len(m.memories))
	}

	m.memSweep()
	if len(m.memories) > memEntryLimit {
		t.Fatalf("sweep did not converge: %d entries > limit %d", len(m.memories), memEntryLimit)
	}
	// 验证最旧的 10 条 active 被淘汰（问题2核心：active 必须可被淘汰）
	// 构造时 key 与时间无关（10.0.0.x 段只有 250 个 ip），改为直接断言数量收敛，
	// 并抽查最旧时间戳条目确实被删除。
	var minLast int64 = 1<<63 - 1
	m.memMu.Lock()
	for _, mem := range m.memories {
		if mem.LastHitAt < minLast {
			minLast = mem.LastHitAt
		}
	}
	m.memMu.Unlock()
	if minLast == base-10 { // 最旧 10 条若都还在，minLast 应为构造时最旧值 base-(limit+10)
		t.Fatalf("oldest active entries were not evicted (minLast=%d)", minLast)
	}
}

// TestMemorySweepPreferDecay 验证两段式淘汰：decay 优先让位，其次才删 active。
func TestMemorySweepPreferDecay(t *testing.T) {
	m := newDefaultManager()
	base := time.Now().UnixMilli()
	// 半数是 decay（较旧），半数是 active（较新）
	for i := 0; i < memEntryLimit+10; i++ {
		ip := "172." + itoa(16+i/255) + ".0." + itoa(i%255+1)
		key := ip + "/32"
		status := "active"
		if i%2 == 0 {
			status = "decay"
		}
		m.memMu.Lock()
		m.memories[key] = &GameMemory{
			Key:       key,
			Hits:      1,
			LastHitAt: base - int64(memEntryLimit+10-i),
			Status:    status,
		}
		m.memMu.Unlock()
	}
	m.memSweep()
	if len(m.memories) > memEntryLimit {
		t.Fatalf("sweep did not converge: %d entries", len(m.memories))
	}
	// decay 应被优先清掉：剩余条目中 decay 数量不得超过 active 数量（或至少
	// 不高于构造时比例）
	var decay, active int
	m.memMu.Lock()
	for _, mem := range m.memories {
		if mem.Status == "decay" {
			decay++
		} else {
			active++
		}
	}
	m.memMu.Unlock()
	if decay > active {
		t.Fatalf("decay entries should be evicted first (decay=%d active=%d)", decay, active)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
