package gamelane

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// 2026-10-21 miss.go（未命中聚合表）单测：TestMiss20261021_*
// 运行：go test -tags with_gvisor ./component/gamelane -run TestMiss20261021 -count=1 -v

// TestMiss20261021_Aggregate 用例 1：同 processPath 记录 3 次 → 1 条 entry。
func TestMiss20261021_Aggregate(t *testing.T) {
	missTableReset()
	dst := netip.MustParseAddr("1.2.3.4")
	const p = `C:\Games\Demo\demo.exe`
	for i := 0; i < 3; i++ {
		missRecord(p, dst, 27015, MissReasonUnrecognized)
	}
	rep := MissSnapshot()
	if rep.Total != 1 {
		t.Fatalf("total = %d, want 1", rep.Total)
	}
	if rep.Capacity != MissTableCapacity || rep.TTLSec != MissTTLSec {
		t.Fatalf("capacity/ttl = %d/%d, want %d/%d", rep.Capacity, rep.TTLSec, MissTableCapacity, MissTTLSec)
	}
	e := rep.Entries[0]
	if e.HitCount != 3 {
		t.Fatalf("hit_count = %d, want 3", e.HitCount)
	}
	if e.Reasons[MissReasonUnrecognized] != 3 {
		t.Fatalf("reasons = %v, want unrecognized=3", e.Reasons)
	}
	if e.ExeName != "demo.exe" {
		t.Fatalf("exe_name = %q, want demo.exe", e.ExeName)
	}
	if e.ProcessPath != strings.ToLower(p) {
		t.Fatalf("process_path = %q, want %q", e.ProcessPath, strings.ToLower(p))
	}
	if len(e.SampleDsts) != 1 || e.SampleDsts[0] != "1.2.3.4:27015" {
		t.Fatalf("sample_dsts = %v, want [1.2.3.4:27015]", e.SampleDsts)
	}
	if e.FirstSeen == 0 || e.LastSeen < e.FirstSeen {
		t.Fatalf("first/last seen = %d/%d", e.FirstSeen, e.LastSeen)
	}
}

// TestMiss20261021_Capacity 用例 2：塞入 >256 个不同路径 → 不超容量。
// 淘汰策略：单条淘汰（优先级最低者优先，同优先级淘汰 lastSeen 最旧者）。
func TestMiss20261021_Capacity(t *testing.T) {
	missTableReset()
	dst := netip.MustParseAddr("1.2.3.4")
	const keep = `C:\Program Files (x86)\Steam\steamapps\common\KeepGame\keep.exe`
	missRecord(keep, dst, 27015, MissReasonUnrecognized) // priority 最高，先插入
	for i := 0; i < MissTableCapacity*2; i++ {
		missRecord(fmt.Sprintf(`C:\noise\proc%03d.exe`, i), dst, 27015, MissReasonUnknownPID)
	}
	if n := missTableSize(); n != MissTableCapacity {
		t.Fatalf("table size = %d, want %d", n, MissTableCapacity)
	}
	rep := MissSnapshot()
	if rep.Total > MissTableCapacity {
		t.Fatalf("total = %d, want <= %d", rep.Total, MissTableCapacity)
	}
	found := false
	for _, e := range rep.Entries {
		if strings.Contains(e.ProcessPath, "keep.exe") {
			found = true
			if e.Priority < 3 {
				t.Fatalf("keep.exe priority = %d, want >= 3", e.Priority)
			}
		}
	}
	if !found {
		t.Fatal("高优先级条目（steamapps 路径）被噪音流量淘汰")
	}
}

// TestMiss20261021_TTL 用例 3：lastSeen 超 10min → 读取后条目被清理。
func TestMiss20261021_TTL(t *testing.T) {
	missTableReset()
	dst := netip.MustParseAddr("5.6.7.8")
	const p = `C:\Games\Ttl\ttl.exe`
	missRecord(p, dst, 27015, MissReasonAux)
	if MissSnapshot().Total != 1 {
		t.Fatal("entry not recorded")
	}
	// 手工推进 lastSeen 到 11 分钟前
	missMu.Lock()
	missTable[strings.ToLower(p)].LastSeen = time.Now().Add(-11 * time.Minute).UnixMilli()
	missMu.Unlock()
	if rep := MissSnapshot(); rep.Total != 0 || len(rep.Entries) != 0 {
		t.Fatalf("expired entry not pruned: total=%d", rep.Total)
	}
	if n := missTableSize(); n != 0 {
		t.Fatalf("table size after ttl = %d, want 0", n)
	}
}

// TestMiss20261021_Sort 用例 4：priority desc, hitCount desc, lastSeen desc。
func TestMiss20261021_Sort(t *testing.T) {
	missTableReset()
	dst := netip.MustParseAddr("9.9.9.9")
	// A: steamapps 路径 → priority 3（+1 exeName 命中 game）
	pA := `C:\Program Files (x86)\Steam\steamapps\common\Alpha\alphagame.exe`
	missRecord(pA, dst, 27015, MissReasonUnrecognized)
	// B: 普通路径 + 25 次命中 → priority 2
	pB := `C:\Tools\beta.exe`
	for i := 0; i < 25; i++ {
		missRecord(pB, dst, 27015, MissReasonUnrecognized)
	}
	// C: 普通路径 + 1 次命中 → priority 0
	pC := `C:\Windows\System32\svchost.exe`
	missRecord(pC, dst, 27015, MissReasonAux)

	rep := MissSnapshot()
	if rep.Total != 3 {
		t.Fatalf("total = %d, want 3", rep.Total)
	}
	got := []string{rep.Entries[0].ProcessPath, rep.Entries[1].ProcessPath, rep.Entries[2].ProcessPath}
	want := []string{strings.ToLower(pA), strings.ToLower(pB), strings.ToLower(pC)}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
	if rep.Entries[0].Priority <= rep.Entries[1].Priority {
		t.Fatalf("priority order wrong: %d vs %d", rep.Entries[0].Priority, rep.Entries[1].Priority)
	}
	if rep.Entries[1].Priority <= rep.Entries[2].Priority {
		t.Fatalf("priority order wrong: %d vs %d", rep.Entries[1].Priority, rep.Entries[2].Priority)
	}
}

// TestMiss20261021_Mask 用例 5：C:\Users\Admin\ → C:\Users\<U>\。
func TestMiss20261021_Mask(t *testing.T) {
	missTableReset()
	dst := netip.MustParseAddr("10.1.1.1")
	const p = `C:\Users\Admin\AppData\Local\SomeGame\SomeGame-Win64-Shipping.exe`
	missRecord(p, dst, 27015, MissReasonUnrecognized)
	rep := MissSnapshot()
	if rep.Total != 1 {
		t.Fatalf("total = %d, want 1", rep.Total)
	}
	e := rep.Entries[0]
	if !strings.Contains(strings.ToLower(e.ProcessPath), `c:\users\<u>\`) {
		t.Fatalf("process_path not masked: %q", e.ProcessPath)
	}
	if strings.Contains(strings.ToLower(e.ProcessPath), "admin") {
		t.Fatalf("process_path leaks user name: %q", e.ProcessPath)
	}
	if !strings.Contains(strings.ToLower(e.CheckedDir), `c:\users\<u>\`) {
		t.Fatalf("checked_dir not masked: %q", e.CheckedDir)
	}
	// 非用户目录不受影响
	if got := missMaskPath(`D:\Games\x\y.exe`); got != `D:\Games\x\y.exe` {
		t.Fatalf("mask changed unrelated path: %q", got)
	}
}

// TestMiss20261021_Concurrency 用例 6：50 goroutine 并发写读（-race 下须无竞态）。
func TestMiss20261021_Concurrency(t *testing.T) {
	missTableReset()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dst := netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
			p := fmt.Sprintf(`C:\Games\C%02d\game%02d.exe`, i%7, i)
			reason := MissReasonUnrecognized
			if i%3 == 0 {
				reason = MissReasonAux
			}
			for j := 0; j < 20; j++ {
				missRecord(p, dst, uint16(27015+j), reason)
				if j%5 == 0 {
					_ = MissSnapshot()
				}
			}
		}(i)
	}
	wg.Wait()
	rep := MissSnapshot()
	if rep.Total == 0 || rep.Total > MissTableCapacity {
		t.Fatalf("total = %d, want 1..%d", rep.Total, MissTableCapacity)
	}
	for _, e := range rep.Entries {
		if e.HitCount == 0 {
			t.Fatalf("zero hit entry: %+v", e)
		}
	}
}

// TestMiss20261021_Wiring 接线验证：走真实 RegisterGameTargetIfNeeded，
// 端口总闸（8125）拒绝时 miss 表必须落一条 port 记录，且返回 false 语义不变。
func TestMiss20261021_Wiring(t *testing.T) {
	missTableReset()
	m := Default()
	prev := m.Enabled()
	m.SetEnabled(true)
	defer m.SetEnabled(prev)

	md := &C.Metadata{}
	md.DstIP = netip.MustParseAddr("1.1.1.1")
	md.DstPort = 8125
	if got := m.RegisterGameTargetIfNeeded(md, false); got {
		t.Fatal("RegisterGameTargetIfNeeded(8125) = true, want false")
	}
	rep := MissSnapshot()
	if rep.Total != 1 {
		t.Fatalf("total = %d, want 1 (端口总闸未埋点)", rep.Total)
	}
	e := rep.Entries[0]
	if e.ProcessPath != "" {
		t.Fatalf("process_path = %q, want empty (<<no_proc>> 桶)", e.ProcessPath)
	}
	if e.Reasons[MissReasonPort] != 1 {
		t.Fatalf("reasons = %v, want port=1", e.Reasons)
	}
	if len(e.SampleDsts) != 1 || e.SampleDsts[0] != "1.1.1.1:8125" {
		t.Fatalf("sample_dsts = %v", e.SampleDsts)
	}
	missTableReset()
}

func TestMiss20261021_ReasonMapping(t *testing.T) {
	cases := []struct {
		ident string
		want  string
	}{
		{"", MissReasonUnrecognized},
		{"aux", MissReasonAux},
		{"vscode", MissReasonAux},
	}
	for _, c := range cases {
		if got := missReasonForIdent(c.ident); got != c.want {
			t.Fatalf("missReasonForIdent(%q) = %q, want %q", c.ident, got, c.want)
		}
	}

	// isAutoRegCandidate=false 的细分：8125 → port；公网 IP → excluded
	port := &C.Metadata{DstPort: 8125}
	if got := missReasonForCandidate(port); got != MissReasonPort {
		t.Fatalf("candidate(8125) = %q, want %q", got, MissReasonPort)
	}
	excl := &C.Metadata{DstPort: 27015}
	if got := missReasonForCandidate(excl); got != MissReasonExcluded {
		t.Fatalf("candidate(27015) = %q, want %q", got, MissReasonExcluded)
	}

	// 无身份桶：unknown_pid → <<unknown_pid>>，其余（port/fakeip）→ <<no_proc>>
	if got := missAggregateKey("", MissReasonUnknownPID); got != missKeyUnknownPID {
		t.Fatalf("key(unknown_pid) = %q", got)
	}
	for _, r := range []string{MissReasonPort, MissReasonFakeIP} {
		if got := missAggregateKey("", r); got != missKeyNoProc {
			t.Fatalf("key(%s) = %q, want %q", r, got, missKeyNoProc)
		}
	}
	// 真实路径入表：命中各原因码均落到同一 entry
	missTableReset()
	dst := netip.MustParseAddr("8.8.8.8")
	const p = `C:\Games\Mix\mix.exe`
	missRecord(p, dst, 27015, MissReasonPort)
	missRecord(p, dst, 27015, MissReasonExcluded)
	missRecord(p, dst, 27015, MissReasonFakeIP)
	rep := MissSnapshot()
	if rep.Total != 1 || rep.Entries[0].HitCount != 3 {
		t.Fatalf("mixed reasons aggregate wrong: %+v", rep)
	}
	if len(rep.Entries[0].Reasons) != 3 {
		t.Fatalf("reasons = %v, want 3 kinds", rep.Entries[0].Reasons)
	}
}
