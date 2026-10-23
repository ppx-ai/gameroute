package gamelane

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v2.12《GameLane 无词表通用识别改造》清单3/4/5 单测（2026-10-22）：
//   清单4 大陆 IPv4 路由表（china_ip.go）
//   清单3 系统服务 UDP 端口排除表（ports_exclude.go）
//   清单5 假大陆 IP 反悔接管（fakecn.go）
// 所有用例均以内存构造数据 + 可替换判定入口，不依赖外网与本地真实配置。

// ---------- 清单4：大陆路由表 ----------

func TestChinaIP20261022_BuildAndMatch(t *testing.T) {
	txt := "1.2.4.0/24\n1.1.8.0/24\n# 注释行\n\n8.8.8.8/32\nbad-line\n2001:db8::/32\n"
	tab := buildChinaIPTable(txt, "unit-test")
	if tab == nil {
		t.Fatal("路由表构建失败")
	}
	if tab.count != 3 {
		t.Fatalf("有效 CIDR 应为 3 条（IPv6/注释/脏行跳过），实际 %d", tab.count)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"1.2.4.5", true},
		{"1.1.8.1", true},
		{"8.8.8.8", true},
		{"8.8.9.8", false},
		{"203.0.113.9", false},
	}
	for _, c := range cases {
		if got := tab.trie.IsContainForString(c.ip); got != c.want {
			t.Fatalf("%s 命中应为 %v，实际 %v", c.ip, c.want, got)
		}
	}
}

func TestChinaIP20261022_EmbeddedUsable(t *testing.T) {
	n, src := ChinaIPTableStats()
	if n < chinaIPMinValidCIDRs {
		t.Fatalf("内置路由表条目过少：%d（来源 %s）", n, src)
	}
	// 内置 chnroutes2 必含的稳定大段（阿里云 8.0.0.0/8 内、腾讯 43.128.0.0/10 等
	// 会随数据更新变化，故只断言"非空且能判定海外为 false"）。
	if !isChinaMainlandIP(netip.MustParseAddr("1.2.4.6")) {
		t.Fatal("1.2.4.6 应属大陆路由表")
	}
	if isChinaMainlandIP(netip.MustParseAddr("8.8.9.8")) {
		t.Fatal("8.8.9.8（Google DNS）不应属大陆路由表")
	}
}

func TestChinaIP20261022_OverrideRejectTooFew(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "china_ip.txt")
	// 仅 3 条，远低于 chinaIPMinValidCIDRs → 必须拒绝，保留原表。
	if err := os.WriteFile(p, []byte("10.1.0.0/16\n10.2.0.0/16\n10.3.0.0/16\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := ChinaIPTableStats()
	LoadChinaMainlandTable(p)
	after, _ := ChinaIPTableStats()
	if before != after {
		t.Fatalf("残缺覆盖文件应被拒绝，条目数不应变化：%d → %d", before, after)
	}
	if isChinaMainlandIP(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("被拒绝的覆盖文件不应生效")
	}
}

func TestChinaIP20261022_OverrideApplied(t *testing.T) {
	chinaIPMu.RLock()
	old := chinaIPNow
	chinaIPMu.RUnlock()
	t.Cleanup(func() {
		chinaIPMu.Lock()
		chinaIPNow = old
		chinaIPMu.Unlock()
	})

	dir := t.TempDir()
	p := filepath.Join(dir, "china_ip.txt")
	var sb []byte
	for i := 0; i < chinaIPMinValidCIDRs+5; i++ {
		sb = append(sb, []byte("10."+itoaTest(i)+".0.0/16\n")...)
	}
	if err := os.WriteFile(p, sb, 0o644); err != nil {
		t.Fatal(err)
	}
	LoadChinaMainlandTable(p)
	if !isChinaMainlandIP(netip.MustParseAddr("10.0.1.1")) {
		t.Fatal("合法覆盖文件应整体替换内置表并生效")
	}
	if isChinaMainlandIP(netip.MustParseAddr("1.2.4.6")) {
		t.Fatal("替换后不应再命中内置表网段")
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ---------- 清单3：系统服务 UDP 端口排除表 ----------

func TestUDPPorts20261022_Builtin(t *testing.T) {
	for _, p := range []uint16{53, 123, 443, 8081, 5353, 1900, 8125} {
		if !IsExcludedAutoRegPort(p) {
			t.Fatalf("内置排除端口 %d 应被排除", p)
		}
	}
	for _, p := range []uint16{3478, 27015, 3074, 7777} {
		if IsExcludedAutoRegPort(p) {
			t.Fatalf("端口 %d 不应被排除（3478 为对局端口红线，其余为游戏端口）", p)
		}
	}
}

func TestUDPPorts20261022_FileMergeAnd3478Guard(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, udpSysPortsFileName)
	payload := udpSysPortsFile{
		Version: "1",
		Ports: []udpSysPortItem{
			{Port: 27015, Service: "srcds"},
			{Port: stunPort3478, Service: "stun"},
			{Port: 0},
			{Port: 70000},
			{Port: 5353}, // 已在内置表，重复合并应幂等
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if n := LoadUDPExcludePorts(p); n == 0 {
		t.Fatal("合法端口表应至少合并 1 条")
	}
	if !IsExcludedAutoRegPort(27015) {
		t.Fatal("文件声明的 27015 应被排除")
	}
	if IsExcludedAutoRegPort(stunPort3478) {
		t.Fatal("3478 即使出现在文件中也必须被忽略（对局端口红线）")
	}
	// 清理：避免污染其他用例（端口表是包级全局）。
	skipPortsMu.Lock()
	delete(skipAutoRegPorts, 27015)
	skipPortsMu.Unlock()
}

func TestUDPPorts20261022_MissingFileNoop(t *testing.T) {
	if n := LoadUDPExcludePorts(filepath.Join(t.TempDir(), "absent.json")); n != 0 {
		t.Fatalf("缺失文件应返回 0 且不改表，实际 %d", n)
	}
	if !IsExcludedAutoRegPort(53) {
		t.Fatal("缺失文件时内置兜底端口应保持有效")
	}
	if IsExcludedAutoRegPort(3478) {
		t.Fatal("内置表永远不含 3478")
	}
}

// ---------- 清单5：假大陆 IP 反悔接管 ----------

// withTempFakeCNStore 隔离全局反悔记录：临时文件 + 干净表，用例结束恢复。
func withTempFakeCNStore(t *testing.T) func() {
	t.Helper()
	fakeCNAutoOverrideEnabled = true
	oldNow := fakeCNNow
	now := int64(1700000000000)
	fakeCNNow = func() int64 { return now }
	advance := func(ms int64) { now += ms }

	fakeCNOverrideStore.Lock()
	oldPath := fakeCNOverrideStore.path
	oldEntries := fakeCNOverrideStore.entries
	oldLoaded := fakeCNOverrideStore.loaded
	fakeCNOverrideStore.path = filepath.Join(t.TempDir(), fakeCNDefaultOverrideRel)
	fakeCNOverrideStore.entries = make(map[string]fakeCNOverrideEntry)
	fakeCNOverrideStore.loaded = true
	fakeCNOverrideStore.Unlock()

	// 观察窗计数是包级原子量：用例内从 0 起算，结束恢复原值，避免跨用例串扰。
	oldActive := fakeCNWatchActive.Load()
	fakeCNWatchActive.Store(0)

	_ = advance // 由调用方通过 setFakeCNNow 推进
	return func() {
		fakeCNOverrideStore.Lock()
		fakeCNOverrideStore.path = oldPath
		fakeCNOverrideStore.entries = oldEntries
		fakeCNOverrideStore.loaded = oldLoaded
		fakeCNOverrideStore.Unlock()
		fakeCNWatchActive.Store(oldActive)
		fakeCNNow = oldNow
	}
}

func TestFakeCN20261022_NoReplyTakeover(t *testing.T) {
	withChinaMainland20261021(t, true)
	restore := withTempFakeCNStore(t)
	defer restore()
	base := fakeCNNow()
	setFakeCNNow(t, base)

	m := newAutoManager(true, nil)
	const ip = "203.0.113.90"
	// 进程目标路径（MatchTarget）登记的观察窗：两个端口 → 零回包判据只要 5 包。
	m.startFakeCNWatch(ip, "game.exe", 3074)
	m.startFakeCNWatch(ip, "game.exe", 3075)
	if fakeCNWatchActive.Load() != 1 {
		t.Fatalf("观察窗计数应为 1，实际 %d", fakeCNWatchActive.Load())
	}

	setFakeCNNow(t, base+3100)
	for i := 0; i < 5; i++ {
		if m.fakeCNAccountOutbound(ip, 3074) {
			if i < 4 {
				t.Fatalf("第 %d 包即反悔，过早（判据为 ≥%d 包）", i+1, fakeCNMinPackets)
			}
		}
	}
	if !m.hasFakeCNOverride(ip) {
		t.Fatal("零回包应生成持久反悔记录")
	}
	if len(m.targets) != 1 {
		t.Fatalf("反悔接管后目标应被注册为游戏目标，实际目标数 %d", len(m.targets))
	}
	if fakeCNWatchActive.Load() != 0 {
		t.Fatalf("反悔完成后观察窗计数应归零，实际 %d", fakeCNWatchActive.Load())
	}
}

func TestFakeCN20261022_SinglePortNeedsMorePackets(t *testing.T) {
	withChinaMainland20261021(t, true)
	restore := withTempFakeCNStore(t)
	defer restore()
	base := fakeCNNow()

	m := newAutoManager(true, nil)
	const ip = "203.0.113.91"
	m.startFakeCNWatch(ip, "game.exe", 3074)

	setFakeCNNow(t, base+3100)
	for i := 0; i < fakeCNMinPackets; i++ { // 5 包 < 单端口要求 20 包
		if m.fakeCNAccountOutbound(ip, 3074) {
			t.Fatalf("单端口 5 包不应触发反悔（判据 %d 包）", fakeCNMinPacketsOnePort)
		}
	}
	if m.hasFakeCNOverride(ip) {
		t.Fatal("未达判据不应生成反悔记录")
	}
}

func TestFakeCN20261022_HighRTTTakeover(t *testing.T) {
	withChinaMainland20261021(t, true)
	restore := withTempFakeCNStore(t)
	defer restore()
	base := fakeCNNow()

	m := newAutoManager(true, nil)
	const ip = "203.0.113.92"
	m.startFakeCNWatch(ip, "game.exe", 3074)
	m.startFakeCNWatch(ip, "game.exe", 3075)

	// 3 次"出站 → 100ms 后回包"，最小 RTT=100ms > 70ms 且多端口。
	now := base
	for i := 0; i < fakeCNMinRTTSamples; i++ {
		setFakeCNNow(t, now)
		if m.fakeCNAccountOutbound(ip, 3074) {
			t.Fatalf("第 %d 轮不应提前反悔", i+1)
		}
		now += 100
		setFakeCNNow(t, now)
		m.fakeCNAccountReply(ip)
		now += 10
	}
	setFakeCNNow(t, now)
	if !m.fakeCNAccountOutbound(ip, 3075) {
		t.Fatal("直连最小 RTT 100ms、样本 ≥3、多端口 → 应反悔接管")
	}
	if !m.hasFakeCNOverride(ip) {
		t.Fatal("高延迟反悔应生成持久记录")
	}
}

func TestFakeCN20261022_GoodRTTKeepsDirect(t *testing.T) {
	withChinaMainland20261021(t, true)
	restore := withTempFakeCNStore(t)
	defer restore()
	base := fakeCNNow()

	m := newAutoManager(true, nil)
	const ip = "203.0.113.93"
	m.startFakeCNWatch(ip, "game.exe", 3074)
	m.startFakeCNWatch(ip, "game.exe", 3075)

	now := base
	for i := 0; i < 10; i++ {
		setFakeCNNow(t, now)
		if m.fakeCNAccountOutbound(ip, 3074) {
			t.Fatal("RTT 正常（20ms）且有回包，不应反悔接管")
		}
		now += 20
		setFakeCNNow(t, now)
		m.fakeCNAccountReply(ip)
		now += 50
	}
	if m.hasFakeCNOverride(ip) {
		t.Fatal("链路正常不应产生反悔记录（直连语义不变）")
	}
}

func TestFakeCN20261022_OverridePersistRoundTrip(t *testing.T) {
	restore := withTempFakeCNStore(t)
	defer restore()
	m := newAutoManager(true, nil)
	const ip = "203.0.113.94"
	m.rememberFakeCNOverride(ip, "game.exe", 3074, "no_reply", 0, 12)

	fakeCNOverrideStore.RLock()
	path := fakeCNOverrideStore.path
	fakeCNOverrideStore.RUnlock()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("反悔记录应已落盘：%v", err)
	}
	var f fakeCNOverrideFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("落盘 JSON 应可解析：%v", err)
	}
	if _, ok := f.Entries[ip]; !ok {
		t.Fatal("落盘文件应含该 IP 记录")
	}
	// 幂等：重复写入不改变内容。
	m.rememberFakeCNOverride(ip, "game.exe", 3074, "no_reply", 0, 12)
	if snap := FakeCNOverrideSnapshot(); len(snap) != 1 {
		t.Fatalf("同一 IP 只应保留 1 条记录，实际 %d", len(snap))
	}
	// 人工清空入口。
	if n := ClearFakeCNOverride(ip); n != 1 {
		t.Fatalf("ClearFakeCNOverride 应返回 1，实际 %d", n)
	}
	if m.hasFakeCNOverride(ip) {
		t.Fatal("清空后不应再命中反悔记录")
	}
}

func TestFakeCN20261022_NoteDomesticDirectGuards(t *testing.T) {
	restore := withTempFakeCNStore(t)
	defer restore()

	m := newAutoManager(true, nil)
	withChinaMainland20261021(t, false)
	m.noteDomesticDirect("203.0.113.95", 3074, `D:\我的游戏\abc\abc.exe`)
	if len(m.fakeCNWatchSnapshot()) != 0 {
		t.Fatal("表外目标不应登记反悔观察窗")
	}

	withChinaMainland20261021(t, true)
	m.noteDomesticDirect("203.0.113.95", 3074, `D:\我的游戏\abc\abc.exe`)
	if len(m.fakeCNWatchSnapshot()) != 1 {
		t.Fatal("大陆路由表内目标应登记反悔观察窗")
	}

	// 段表命中的目标永不直连 → 无需观察窗。
	const segIP = "155.133.238.178"
	m.noteDomesticDirect(segIP, 3074, `D:\我的游戏\abc\abc.exe`)
	for _, st := range m.fakeCNWatchSnapshot() {
		if st.IP == segIP {
			t.Fatal("已知游戏段目标不应登记反悔观察窗")
		}
	}
}

// setFakeCNNow 推进测试时间源。
func setFakeCNNow(t *testing.T, ms int64) {
	t.Helper()
	fakeCNNow = func() int64 { return ms }
}

// ---------- 清单1.5 第二批 aux 词（2026-10-22） ----------

// TestFakeCN20261022_PersistedSkipWatch 已有持久反悔记录的 IP 二次启动
// 直接按海外处理，不再开观察窗（指令 5.4 第 5 条）。
func TestFakeCN20261022_PersistedSkipWatch(t *testing.T) {
	restore := withTempFakeCNStore(t)
	defer restore()
	withChinaMainland20261021(t, true)
	defer withChinaMainland20261021(t, false)

	m := newAutoManager(true, nil)
	const ip = "203.0.113.88"
	const proc = `D:\我的游戏\abc\abc.exe`
	m.rememberFakeCNOverride(ip, proc, 3074, "no_reply", 0, 9)
	if !m.hasFakeCNOverride(ip) {
		t.Fatal("已写入的反悔记录应可命中")
	}
	m.noteDomesticDirect(ip, 3074, proc)
	if n := len(m.fakeCNWatchSnapshot()); n != 0 {
		t.Fatalf("已持久反悔的 IP 不应再开观察窗，实际 %d 条", n)
	}
}

// TestNoList20261022AuxInternationalSoftware 第二批国际软件 aux 词生效，
// 且它们绝不能被游戏关键字表命中（第一版曾误置于 gameProcessKeywords）。
func TestNoList20261022AuxInternationalSoftware(t *testing.T) {
	paths := []string{
		`C:\Program Files\Telegram Desktop\Telegram.exe`,
		`C:\Users\U\AppData\Roaming\Spotify\Spotify.exe`,
		`C:\Program Files\Hysteria\hysteria.exe`,
		`C:\Program Files\sing-box\sing-box.exe`,
		`C:\Program Files\BitComet\BitComet.exe`,
		`C:\Program Files\Microsoft Teams\current\Teams.exe`,
		`C:\Program Files (x86)\NVIDIA Corporation\NvContainer\nvcontainer.exe`,
		`C:\Program Files\Tailscale\tailscaled.exe`,
	}
	for _, p := range paths {
		if !isAuxProcessName(p) {
			t.Fatalf("第二批 aux 词应命中：%q", p)
		}
		if ok, _ := isGameProcess(p); ok {
			t.Fatalf("aux 进程不得判定为游戏：%q", p)
		}
	}
	// 国内软件禁止进 aux（国内目标由大陆路由表直连拦下，加词零收益）。
	for _, p := range []string{
		`C:\Program Files\Tencent\WeMeet\wemeetapp.exe`,
		`C:\Program Files\leigod\leigod.exe`,
		`C:\Program Files\Sunlogin\SunloginClient.exe`,
	} {
		if isAuxProcessName(p) {
			t.Fatalf("国内软件不应加入 aux 表：%q", p)
		}
	}
	// 游戏关键字表必须干净：不得出现代理/BT/IM 词。
	for _, name := range []string{"telegram.exe", "spotify.exe", "hysteria.exe", "bitcomet.exe"} {
		if matchGameProcessKeyword(strings.ToLower(name)) {
			t.Fatalf("游戏关键字表混入非游戏词：%q", name)
		}
	}
}

// TestFakeCN20261022_OnlyGameProcessObserved 红线第 6 条：观察窗只服务
// 已确认游戏进程，aux / 未知进程一律不建窗。
func TestFakeCN20261022_OnlyGameProcessObserved(t *testing.T) {
	restore := withTempFakeCNStore(t)
	defer restore()
	withChinaMainland20261021(t, true)
	defer withChinaMainland20261021(t, false)

	m := newAutoManager(true, nil)
	m.noteDomesticDirect("203.0.113.61", 3074, `C:\Program Files\Discord\Discord.exe`)
	m.noteDomesticDirect("203.0.113.62", 3074, "unknownapp.exe")
	m.noteDomesticDirect("203.0.113.63", 3074, "")
	if n := len(m.fakeCNWatchSnapshot()); n != 0 {
		t.Fatalf("非游戏/未知进程不得进入观察窗，实际 %d 条", n)
	}
	m.noteDomesticDirect("203.0.113.64", 3074, `D:\我的游戏\abc\abc.exe`)
	if n := len(m.fakeCNWatchSnapshot()); n != 1 {
		t.Fatalf("已确认游戏进程应建观察窗，实际 %d 条", n)
	}
}

// TestFakeCN20261022_MemoryAuditMark 接管后记忆条目须带 fakecn_override 审计标记。
func TestFakeCN20261022_MemoryAuditMark(t *testing.T) {
	restore := withTempFakeCNStore(t)
	defer restore()

	m := newAutoManager(true, nil)
	const ip = "203.0.113.77"
	m.remember(ip, 3074)
	m.rememberFakeCNOverrideMark(ip, "no_reply")

	m.memMu.Lock()
	found := false
	var first int64
	for k, mem := range m.memories {
		if !strings.HasPrefix(k, ip) {
			continue
		}
		found = true
		first = mem.FakeCNOverrideAt
		if !mem.FakeCNOverride || mem.FakeCNReason != "no_reply" || first == 0 {
			t.Fatalf("记忆条目审计标记缺失：key=%s %+v", k, mem)
		}
	}
	m.memMu.Unlock()
	if !found {
		t.Fatal("未找到待标记的记忆条目")
	}
	// 幂等：重复标记不改变已有时间戳与原因。
	m.rememberFakeCNOverrideMark(ip, "high_rtt")
	m.memMu.Lock()
	for k, mem := range m.memories {
		if !strings.HasPrefix(k, ip) {
			continue
		}
		if mem.FakeCNOverrideAt != first || mem.FakeCNReason != "no_reply" {
			t.Fatalf("重复标记应幂等：key=%s %+v", k, mem)
		}
	}
	m.memMu.Unlock()
}
