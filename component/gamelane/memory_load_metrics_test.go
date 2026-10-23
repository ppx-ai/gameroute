package gamelane

import (
	"path/filepath"
	"testing"
	"time"
)

// TestLoadMemoryDoesNotPolluteProcKeywordHit 是 v2.10.2 的回归用例：
// 加载记忆文件时对 source=process 条目做污染校验，绝不能计入
// proc_keyword_hit（该计数器只允许反映运行期真实进程判定）。
func TestLoadMemoryDoesNotPolluteProcKeywordHit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "game_memory.json")
	now := time.Now().UnixMilli()
	mf := MemoryFile{Version: memVersion, Entries: map[string]GameMemory{
		"1.1.1.1/32": {Key: "1.1.1.1/32", Hits: 1, LastHitAt: now, Status: "active",
			Source: "process", ProcessName: `D:\steam\steamapps\common\Apex Legends\r5apex_dx12.exe`},
		"2.2.2.2/32": {Key: "2.2.2.2/32", Hits: 1, LastHitAt: now, Status: "active",
			Source: "process", ProcessName: "r5apex.exe"},
		"3.3.3.3/32": {Key: "3.3.3.3/32", Hits: 1, LastHitAt: now, Status: "active",
			Source: "process", ProcessName: "msedge.exe"}, // 污染条目，应被剔除
	}}
	if err := writeMemoryFileAtomic(path, mf); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	hitBefore := metricsProcKeywordHit.Load()
	validatedBefore := metricsMemoryProcValidated.Load()

	m := newDefaultManager()
	m.LoadMemory(path)

	if got := metricsProcKeywordHit.Load() - hitBefore; got != 0 {
		t.Fatalf("LoadMemory polluted proc_keyword_hit: +%d", got)
	}
	if got := metricsMemoryProcValidated.Load() - validatedBefore; got != 3 {
		t.Fatalf("memory_proc_validated: want +3, got +%d", got)
	}
	// 污染条目必须被剔除，游戏条目保留
	if _, ok := m.lookupMemory("3.3.3.3", 0); ok {
		t.Fatalf("polluted entry (msedge.exe) must be purged")
	}
	if _, ok := m.lookupMemory("2.2.2.2", 0); !ok {
		t.Fatalf("valid game-process entry must survive")
	}
}

// TestLoadMemoryIdempotent 验证两条幂等路径都不会重复遍历/校验：
//  1. 同一 Manager 实例重复调用 → 直接跳过；
//  2. 配置重载新建 Manager → 继承运行期快照。
func TestLoadMemoryIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "game_memory.json")
	now := time.Now().UnixMilli()
	mf := MemoryFile{Version: memVersion, Entries: map[string]GameMemory{
		"1.1.1.1/32": {Key: "1.1.1.1/32", Hits: 1, LastHitAt: now, Status: "active",
			Source: "process", ProcessName: "r5apex.exe"},
	}}
	if err := writeMemoryFileAtomic(path, mf); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	m := newDefaultManager()
	m.LoadMemory(path)
	validatedBase := metricsMemoryProcValidated.Load()

	// 同实例重复加载：不得再校验、不得重复载入
	m.LoadMemory(path)
	if got := metricsMemoryProcValidated.Load() - validatedBase; got != 0 {
		t.Fatalf("same-instance reload re-validated %d entries", got)
	}

	// 新实例（模拟配置重载）：必须继承快照，同样不重新校验
	m2 := newDefaultManager()
	loadedBefore := metricsMemoryLoaded.Load()
	m2.LoadMemory(path)
	if got := metricsMemoryProcValidated.Load() - validatedBase; got != 0 {
		t.Fatalf("new-instance reload re-validated %d entries", got)
	}
	if got := metricsMemoryLoaded.Load() - loadedBefore; got != 0 {
		t.Fatalf("new-instance reload re-counted memory_loaded: +%d", got)
	}
	if _, ok := m2.lookupMemory("1.1.1.1", 0); !ok {
		t.Fatalf("inherited snapshot lost entry")
	}
}
