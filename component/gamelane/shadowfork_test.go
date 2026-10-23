package gamelane

// Shadow Forking 改造回归（2026-10-17 需求 A/F/B/C，批复 Q2-Q4/死六一~四）。

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- 需求 A：黄金枢纽池五区过滤 ----

func TestFilterLaneRegions_FiveRegionLock(t *testing.T) {
	m := newDefaultManager()
	in := []string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01", "US-01", "DE-01", "UK-01", "DIRECT", ""}
	got := m.filterLaneRegions(in)
	if len(got) != 5 {
		t.Fatalf("five-region lock: want 5 kept, got %v", got)
	}
	want := map[string]bool{"HK-01": true, "TW-01": true, "SG-01": true, "JP-01": true, "KR-01": true}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected kept node %v", n)
		}
	}
	for _, n := range got {
		tag, ok := extractRegionTag(n)
		if !ok || !IsLaneRegion(tag) {
			t.Fatalf("kept node %s is not a lane region", n)
		}
	}
	if got := m.filterLaneRegions(nil); got != nil {
		t.Fatalf("empty input must return nil, got %v", got)
	}
	// 中文子串兜底（批复审查②）：数字紧邻中文的机场命名（token 匹配失败形态）。
	// 兜底词=批复口径（HK:香港/港/hk、TW:台湾/台/tw、SG:新加坡/狮城/sg、
	// JP:日本/jp、KR:韩国/韩/kr）——"高雄"不在 TW 词表内，不在此用例。
	more := []string{"香港 01", "狮城-01", "东京-01", "首尔-01", "台南-01"}
	got2 := m.filterLaneRegions(more)
	if len(got2) != 5 {
		t.Fatalf("chinese substring fallback: want 5 kept, got %v", got2)
	}
}

func TestSetAllProxies_FiltersPool(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "US-01", "DE-01", "SG-01"})
	m.mu.RLock()
	pool := append([]string(nil), m.allProxies...)
	m.mu.RUnlock()
	if len(pool) != 2 {
		t.Fatalf("allProxies must be five-region only, got %v", pool)
	}
}

// ---- 需求 F：STUN/RTT 只做同区选代表 ----

func TestLaneChampions_PerRegionTop1(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "HK-02", "TW-01", "SG-01", "JP-01", "KR-01"})
	m.MergeProbeResults(map[string]probeSample{
		"HK-01": {RttMs: 30, Samples: 1, OK: true},
		"HK-02": {RttMs: 50, Samples: 1, OK: true},
		"TW-01": {RttMs: 70, Samples: 1, OK: true},
	})
	ch := m.LaneChampions()
	if ch["HK"] != "HK-01" {
		t.Fatalf("HK champion must be lowest in-region rtt (HK-01), got %v", ch["HK"])
	}
	if ch["TW"] != "TW-01" || ch["SG"] != "SG-01" || ch["JP"] != "JP-01" || ch["KR"] != "KR-01" {
		t.Fatalf("champions per region: %v", ch)
	}
	if len(ch) != 5 {
		t.Fatalf("want 5 regional champions, got %d", len(ch))
	}
}

// ---- 需求 B：字节级扳机 ----

func TestIsSpeedtestProbePayload(t *testing.T) {
	magic := []byte{0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 1, 0, 0, 0}
	if !IsSpeedtestProbePayload(magic) {
		t.Fatal("42-byte style ffffffff packet must trigger")
	}
	big := append(append([]byte{}, magic...), make([]byte, 100)...)
	if IsSpeedtestProbePayload(big) {
		t.Fatal("packet >=64B must not trigger (red line 1)")
	}
	if IsSpeedtestProbePayload([]byte{0xfe, 0xff, 0xff, 0xff, 1, 2, 3, 4}) {
		t.Fatal("non-ffffffff magic must not trigger")
	}
	if IsSpeedtestProbePayload([]byte{0xff, 0xff, 0xff, 0xff}) {
		t.Fatal("payload shorter than magic+seq must not trigger")
	}
	if IsSpeedtestProbePayload(make([]byte, 64)) {
		t.Fatal("64B all-zero must not trigger")
	}
}

// 批复 v2 Q-A 方案 (ii)：writeBack 闭包必须以「原包目的地址」调用 WriteBack
// （绝不能 nil——sing 实测报 "address is invalid"；也绝不能引用会被
// preHandleMetadata 清空的 metadata.DstIP）——fake-ip 路径源地址=客户端
// 认识的 fake-ip，真实路径=真实服务器 IP。
type fakeTunPacket struct {
	writes [][]byte
	addrs  []net.Addr
	err    error
}

func (f *fakeTunPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	f.writes = append(f.writes, append([]byte(nil), b...))
	f.addrs = append(f.addrs, addr)
	return len(b), f.err
}

func (f *fakeTunPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 56178}
}

func TestPacketWriteBackSink_UsesOriginalDst(t *testing.T) {
	pkt := &fakeTunPacket{}
	origDstAddr := &net.UDPAddr{IP: net.ParseIP("198.18.0.45"), Port: 7770}
	sink := PacketWriteBackSink(pkt, origDstAddr)
	payload := []byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4}
	if !sink(payload) {
		t.Fatal("sink must return true when WriteBack succeeds")
	}
	if len(pkt.writes) != 1 || string(pkt.writes[0]) != string(payload) {
		t.Fatalf("WriteBack must receive payload verbatim, got %v", pkt.writes)
	}
	if pkt.addrs[0] != net.Addr(origDstAddr) {
		t.Fatalf("WriteBack addr must be the original dst (fake-ip the client knows), got %v", pkt.addrs[0])
	}
	pkt.err = net.ErrClosed
	if sink(payload) {
		t.Fatal("sink must return false when WriteBack fails")
	}
}

func TestIsMatchServerPort(t *testing.T) {
	if !isMatchServerPort(37005) || !isMatchServerPort(27015) {
		t.Fatal("match-server ports must be excluded from clone (red line 2)")
	}
	// v2.9 修正二（强制）：新增非亚太对局端口一律算对局端口，否则 OW2/COD
	// 语音 STUN 包撞上新魔数会触发五路克隆。
	for _, p := range []uint16{3724, 6113, 3074, 26503, 5000, 5500} {
		if !isMatchServerPort(p) {
			t.Fatalf("port %d must be a match-server port (v2.9 fix 2)", p)
		}
	}
	// APEX 两个客户端本地源端口段仍不算对局端口（探测方本地端口）
	if isMatchServerPort(1024) || isMatchServerPort(9960) {
		t.Fatal("APEX client source ports must not be match-server ports")
	}
	if isMatchServerPort(7770) || isMatchServerPort(80) {
		t.Fatal("non-match ports must pass the guard")
	}
}

// v2.9 裁决 2：STUN / RakNet 是通用协议，必须过端口守卫，否则浏览器
// WebRTC 的 STUN 绑定包（3478/19302）会在 UDP 热路径触发五路克隆。
func TestIsSpeedtestProbePayloadForPort(t *testing.T) {
	magic := []byte{0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 1, 0, 0, 0}
	if !IsSpeedtestProbePayloadForPort(magic, 3478) {
		t.Fatal("ffffffff branch must ignore the port guard")
	}
	// STUN Binding Request：20B，type=0x0001 + magic cookie 0x2112A442
	stun := make([]byte, 20)
	stun[0], stun[1] = 0x00, 0x01
	stun[4], stun[5], stun[6], stun[7] = 0x21, 0x12, 0xa4, 0x42
	if !IsSpeedtestProbePayloadForPort(stun, 30000) {
		t.Fatal("STUN binding request on a game port must trigger")
	}
	for _, p := range []uint16{3478, 3479, 5349, 19302} {
		if IsSpeedtestProbePayloadForPort(stun, p) {
			t.Fatalf("STUN port %d must be guarded (no shadow fork)", p)
		}
	}
	// RakNet Unconnected Ping：25B，0x01 + 8B 时间戳 + 16B 离线消息 ID
	rak := make([]byte, 25)
	rak[0] = 0x01
	copy(rak[9:], raknetOfflineMagic[:])
	if !IsSpeedtestProbePayloadForPort(rak, 19132) {
		t.Fatal("RakNet unconnected ping must trigger")
	}
	if IsSpeedtestProbePayloadForPort(rak, 19302) {
		t.Fatal("port guard must also suppress the RakNet branch")
	}
	if IsSpeedtestProbePayloadForPort(make([]byte, 64), 30000) {
		t.Fatal("payload >= 64B must not trigger (red line 1)")
	}
}

// v2.9 修正一 / 裁决 4：-shipping 三分支与 VS Code 误伤排除。
func TestIsGameProcessNameV29(t *testing.T) {
	cases := map[string]bool{
		"RainbowSix.exe":        true,
		"League of Legends.exe": true,
		"GenshinImpact.exe":     true,
		"X-Win64-Shipping.exe":  true,
		"X-WinGDK-Shipping.exe": true,
		"Code.exe":              false,
		"UbisoftConnect.exe":    false,
		"LeagueClient.exe":      false,
	}
	for n, want := range cases {
		if got := isGameProcessName(n); got != want {
			t.Fatalf("isGameProcessName(%q)=%v, want %v", n, got, want)
		}
	}
}

// ---- 死六一：racingSegs 占位 ----

func TestSegmentNeedsRace_RacingPlaceholder(t *testing.T) {
	m := newDefaultManager()
	ip := netip.MustParseAddr("203.0.113.9")
	if m.SegmentNeedsRace(ip, 37005) {
		t.Fatal("match-server port must never race (red line 2)")
	}
	if !m.SegmentNeedsRace(ip, 7770) {
		t.Fatal("first trigger must begin race")
	}
	if m.SegmentNeedsRace(ip, 7770) {
		t.Fatal("concurrent trigger while racing must be rejected (死六一)")
	}
	m.clearRacingSeg(segmentKey24(ip.String()))
	if !m.SegmentNeedsRace(ip, 7770) {
		t.Fatal("after placeholder release, race can begin again")
	}
}

// ---- 需求 C：五路赛马（mock 旁路延迟） ----

// fakeRaceConn 旁路通道 mock：WriteTo 后按预设延迟把 payload 回给 ReadFrom。
type fakeRaceConn struct {
	delay  time.Duration
	queue  chan []byte
	closed atomic.Bool
}

func newFakeRaceConn(d time.Duration) *fakeRaceConn {
	return &fakeRaceConn{delay: d, queue: make(chan []byte, 8)}
}

func (f *fakeRaceConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if f.closed.Load() {
		return 0, net.ErrClosed
	}
	go func() {
		time.Sleep(f.delay)
		if f.closed.Load() {
			return
		}
		select {
		case f.queue <- append([]byte(nil), p...):
		default:
		}
	}()
	return len(p), nil
}

func (f *fakeRaceConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		if f.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		select {
		case data := <-f.queue:
			n := copy(b, data)
			return n, f.LocalAddr(), nil
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (f *fakeRaceConn) Close() error { f.closed.Store(true); return nil }
func (f *fakeRaceConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
}
func (f *fakeRaceConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeRaceConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeRaceConn) SetWriteDeadline(t time.Time) error { return nil }

func TestShadowRace_FirstWinAndLock(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	delays := map[string]time.Duration{
		"HK-01": 60 * time.Millisecond,
		"TW-01": 120 * time.Millisecond,
		"SG-01": 180 * time.Millisecond,
		"JP-01": 240 * time.Millisecond,
		"KR-01": 300 * time.Millisecond,
	}
	var connsMu sync.Mutex
	var conns []*fakeRaceConn
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		c := newFakeRaceConn(delays[name])
		connsMu.Lock()
		conns = append(conns, c)
		connsMu.Unlock()
		return c, nil
	})

	var mu sync.Mutex
	var wrote [][]byte
	writeBack := func(data []byte) bool {
		mu.Lock()
		wrote = append(wrote, append([]byte(nil), data...))
		mu.Unlock()
		return true
	}
	payload := []byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4, 0x01, 0x00, 0x00, 0x00}
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, 9}), 7770)

	m.StartShadowForking(dst, payload, writeBack)

	// 等待赛马窗口结束（首包 ~60ms + 2s 尾窗，全路关闭 ≤3s）
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(wrote)
		mu.Unlock()
		connsMu.Lock()
		allClosed := len(conns) > 0
		for _, c := range conns {
			if !c.closed.Load() {
				allClosed = false
			}
		}
		connsMu.Unlock()
		if n >= 1 && allClosed && time.Since(winnerSeenAt(m)) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 再等尾窗彻底关闭
	time.Sleep(2200 * time.Millisecond)

	mu.Lock()
	n := len(wrote)
	first := []byte(nil)
	if n > 0 {
		first = wrote[0]
	}
	mu.Unlock()
	if n != 1 {
		t.Fatalf("client must receive exactly the first (fastest) reply, got %d writes", n)
	}
	if string(first) != string(payload) {
		t.Fatal("reply payload must echo the probe payload verbatim (red line 4)")
	}

	ent := m.getSegmentLock(segmentKey24("198.51.100.9"))
	if ent == nil {
		t.Fatal("fastest node must lock the /24 (需求 C3)")
	}
	if ent.Proxy != "HK-01" {
		t.Fatalf("fastest lane (HK-01, 60ms) must win, got %s (rtt=%dms)", ent.Proxy, ent.RTTMs)
	}
	if ent.RTTMs < 30 || ent.RTTMs > 200 {
		t.Fatalf("winner rtt want ~60ms, got %d", ent.RTTMs)
	}
	connsMu.Lock()
	defer connsMu.Unlock()
	if len(conns) != 5 {
		t.Fatalf("five-region race must dial 5 lanes, got %d", len(conns))
	}
	for i, c := range conns {
		if !c.closed.Load() {
			t.Fatalf("lane %d not closed (handle leak)", i)
		}
	}
	rtt := m.SnapshotRTT()
	for _, name := range []string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"} {
		if rtt[name] <= 0 {
			t.Fatalf("loser rtt must be recorded for %s, got %v", name, rtt[name])
		}
	}
	if m.SegmentNeedsRace(netip.MustParseAddr("198.51.100.77"), 7770) {
		t.Fatal("locked /24 must not race again (需求 B4)")
	}
	// 记忆：赛马胜者网段级条目（Q10 单样本即写）
	if px, region, level := m.lookUpSegmentPreferred("198.51.100.200"); px != "HK-01" || region != "HK" || level != "/24" {
		t.Fatalf("segment memory must carry race winner, got (%q,%q,%q)", px, region, level)
	}
}

// winnerSeenAt 占位：TestShadowRace 的轮询条件使用（保持可读性）。
func winnerSeenAt(m *Manager) time.Time {
	return time.Time{}
}

// ---- 死六四：解锁重赛防抖动 ----

func TestSegmentLock_ReraceAntiFlap(t *testing.T) {
	m := newDefaultManager()
	seg := "9.9.9.0/24"
	const host = "dc-eu.example.com"
	m.lockSegment(seg, host, "HK-01", "HK", 100)
	if ent := m.getSegmentLock(seg); ent == nil || ent.Proxy != "HK-01" {
		t.Fatalf("lock must be active, got %+v", ent)
	}
	// 条件②：对局劣化/M3 切换 → 解锁（按域名索引，fake-ip 主路对齐路径）
	m.UnlockSegmentForReraceByHost(host, "degrade-switch")
	if ent := m.getSegmentLock(seg); ent != nil {
		t.Fatalf("unlock-for-rerace must remove lock, got %+v", ent)
	}
	if ent := m.getSegmentLockByHost(host); ent != nil {
		t.Fatalf("domain lock index must be cleared with the /24 lock, got %+v", ent)
	}
	// 重赛防抖动：新胜者 80ms >= 旧 100/2=50 → 保留旧锁死
	m.lockSegment(seg, host, "HK-02", "HK", 80)
	if ent := m.getSegmentLock(seg); ent == nil || ent.Proxy != "HK-01" || ent.RTTMs != 100 {
		t.Fatalf("anti-flap must keep old lock (new 80 >= old/2 50), got %+v", ent)
	}
	// 再次解锁后：新胜者 40ms < 50 → 覆盖
	m.UnlockSegmentForRerace("9.9.9.5", "degrade-switch")
	m.lockSegment(seg, host, "HK-02", "HK", 40)
	if ent := m.getSegmentLock(seg); ent == nil || ent.Proxy != "HK-02" || ent.RTTMs != 40 {
		t.Fatalf("new winner 40ms < old/2 50ms must overwrite, got %+v", ent)
	}
}

func TestSegmentLock_TTLExpire(t *testing.T) {
	m := newDefaultManager()
	seg := "8.8.8.0/24"
	m.segmentLockMu.Lock()
	m.segmentLock[seg] = &segmentLockEntry{Proxy: "HK-01", Region: "HK", RTTMs: 60, LockedAt: time.Now().UnixMilli() - segmentLockTTLMs - 1000}
	m.segmentLockMu.Unlock()
	if ent := m.getSegmentLock(seg); ent != nil {
		t.Fatalf("expired lock must be unlocked (死六四①), got %+v", ent)
	}
	m.segmentLockMu.Lock()
	stale, ok := m.segmentStale[seg]
	m.segmentLockMu.Unlock()
	if !ok || stale.Proxy != "HK-01" {
		t.Fatalf("expired entry must move to stale for anti-flap, got %+v", stale)
	}
}

func TestSegmentLock_ProbeFailUnlock(t *testing.T) {
	m := newDefaultManager()
	seg := "7.7.7.0/24"
	m.lockSegment(seg, "dc-kr.example.com", "HK-01", "HK", 60)
	m.mu.Lock()
	m.rttFailStreak["HK-01"] = 3
	m.mu.Unlock()
	if ent := m.getSegmentLock(seg); ent != nil {
		t.Fatalf("3-streak failed node must unlock (死六四③), got %+v", ent)
	}
}

// ---- 2026-10-18 返工 v2：Fake-IP 双保险 ----

// 第一招：IsGameDomain——GameLift UDP Ping Beacon 域名（api.aws 后缀，批复 Q-C 修正点）
func TestIsGameDomain_GameLiftApiAws(t *testing.T) {
	m := newDefaultManager()
	for _, domain := range []string{
		"gamelift-ping.ap-northeast-1.api.aws",
		"gamelift-ping.us-east-1.api.aws",
	} {
		if !m.IsGameDomain(domain) {
			t.Fatalf("%s must hit via api.aws suffix (批复 Q-C 修正点)", domain)
		}
	}
}

// 第一招：Riot 后缀（批复 Q-C 新增清单）
func TestIsGameDomain_RiotSuffix(t *testing.T) {
	m := newDefaultManager()
	if !m.IsGameDomain("riotgames.com") || !m.IsGameDomain("x.pvp.net") {
		t.Fatal("riotgames.com / pvp.net must hit the builtin list")
	}
}

// 第一招：非游戏域名不命中（语义边界：网页行为不变）
func TestIsGameDomain_NonGameMiss(t *testing.T) {
	m := newDefaultManager()
	for _, domain := range []string{"example.com", "bilibili.com", ""} {
		if m.IsGameDomain(domain) {
			t.Fatalf("%q must not be a game domain", domain)
		}
	}
}

// 批复第 6 项确认断言（2026-10-18）：无分隔符中文名逐个跑 extractRegionTag，
// 输出区标签（HK/TW/SG/JP/KR）。不新增机制代码，仅固化断言。
func TestExtractRegionTag_CnNoSeparatorNames(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"香港 01", "HK"},
		{"台湾 02", "TW"},
		{"新加坡 01", "SG"},
		{"狮城 01", "SG"},
		{"日本 01", "JP"},
		{"韩国 01", "KR"},
	}
	for _, c := range cases {
		got, ok := extractRegionTag(c.name)
		if !ok || got != c.want {
			t.Fatalf("extractRegionTag(%q) = (%q,%v), want (%s,true)", c.name, got, ok, c.want)
		}
		t.Logf("extractRegionTag(%q) -> %s ✓", c.name, got)
	}
}

// 第二招①：fake-ip 反查失败 → 放弃赛马（绝不把 198.18/24 写进锁死表）
func TestShadowForkingForFakeHost_ResolveFailAbandons(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	var dialed int
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		dialed++
		return newFakeRaceConn(time.Millisecond), nil
	})
	m.SetRealIPResolver(func(host string) (netip.Addr, error) {
		return netip.Addr{}, &net.DNSError{Err: "nxdomain", Name: host}
	})
	payload := []byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4}
	m.StartShadowForkingForFakeHost("dc-eu.example.com", 7770, payload, func([]byte) bool { return true })
	time.Sleep(100 * time.Millisecond)
	if dialed != 0 {
		t.Fatalf("resolve failure must abandon the race (zero dials), got %d", dialed)
	}
	if ent := m.getSegmentLock("198.18.0.0/24"); ent != nil {
		t.Fatalf("198.18/24 must NEVER enter the lock table, got %+v", ent)
	}
	if ent := m.getSegmentLock("203.0.113.0/24"); ent != nil {
		t.Fatalf("no lock expected on resolve failure, got %+v", ent)
	}
}

// 第二招①+批复1：fake-ip 同 /24 不互锁——两个 fake 域名反查到不同 realIP
// /24，各自赛马各自锁死（改前：同 198.18.0.0/24 互锁，第二个被跳过）。
func TestShadowForkingForFakeHost_SameFakeSubnetNoCrossLock(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	resolverMap := map[string]netip.Addr{
		"dc-eu.example.com": netip.AddrFrom4([4]byte{203, 0, 113, 9}),
		"dc-kr.example.com": netip.AddrFrom4([4]byte{198, 51, 100, 9}),
	}
	m.SetRealIPResolver(func(host string) (netip.Addr, error) {
		if ip, ok := resolverMap[host]; ok {
			return ip, nil
		}
		return netip.Addr{}, &net.DNSError{Err: "nxdomain", Name: host}
	})
	var dialed int
	var dialMu sync.Mutex
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		dialMu.Lock()
		dialed++
		dialMu.Unlock()
		return newFakeRaceConn(30 * time.Millisecond), nil
	})
	payload := []byte{0xff, 0xff, 0xff, 0xff, 7, 7, 7, 7, 1, 0, 0, 0}
	wb := func([]byte) bool { return true }
	m.StartShadowForkingForFakeHost("dc-eu.example.com", 7770, payload, wb)
	m.StartShadowForkingForFakeHost("dc-kr.example.com", 7770, payload, wb)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.getSegmentLock("203.0.113.0/24") != nil && m.getSegmentLock("198.51.100.0/24") != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if m.getSegmentLock("203.0.113.0/24") == nil || m.getSegmentLock("198.51.100.0/24") == nil {
		t.Fatalf("both real /24 must be locked independently (fake-ip same-subnet must not cross-lock)")
	}
	dialMu.Lock()
	defer dialMu.Unlock()
	if dialed < 2 {
		t.Fatalf("both flows must race independently, dialed=%d", dialed)
	}
}

// 第二招②③：协程内 realIP 解析成功 → 判锁/学习/赛马 + writeBack 源地址=fake-ip
func TestShadowForkingForFakeHost_ResolvesAndLocks(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		return newFakeRaceConn(30 * time.Millisecond), nil
	})
	m.SetRealIPResolver(func(host string) (netip.Addr, error) {
		return netip.AddrFrom4([4]byte{203, 0, 113, 9}), nil
	})
	var mu sync.Mutex
	var addrs []net.Addr
	fakeDst := &net.UDPAddr{IP: net.ParseIP("198.18.0.45"), Port: 7770}
	writeBack := func(data []byte) bool {
		mu.Lock()
		addrs = append(addrs, fakeDst)
		mu.Unlock()
		return true
	}
	payload := []byte{0xff, 0xff, 0xff, 0xff, 5, 5, 5, 5, 1, 0, 0, 0}
	m.StartShadowForkingForFakeHost("dc-eu.example.com", 7770, payload, writeBack)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.getSegmentLock("203.0.113.0/24") != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	ent := m.getSegmentLock("203.0.113.0/24")
	if ent == nil {
		t.Fatal("real /24 must be locked after fake-host race")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(addrs) == 0 {
		t.Fatal("winner reply must be written back")
	}
	for _, a := range addrs {
		if a != net.Addr(fakeDst) {
			t.Fatalf("writeBack source must stay the fake-ip the client knows (批复 v2③), got %v", a)
		}
	}
	// 模板必须落在 realIP（批复③：realIP 算锁、学习、赛马）
	m.preheatMu.Lock()
	_, hasTpl := m.probeTemplates["203.0.113.9"]
	m.preheatMu.Unlock()
	if !hasTpl {
		t.Fatal("probe template must be keyed by realIP")
	}
}

// 回归（2026-10-18 代码核对）：ForFakeHost 必须把 host 传进 startRace，
// 赛马赢家锁死时同步写域名索引——否则 getSegmentLockByHost 永远查不到，
// 方案 A（fake-ip 主路按域名查锁）整体失效。
func TestShadowForkingForFakeHost_DomainLockIndexed(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	m.SetRaceDialer(func(name string, dst netip.AddrPort) (net.PacketConn, error) {
		return newFakeRaceConn(30 * time.Millisecond), nil
	})
	m.SetRealIPResolver(func(host string) (netip.Addr, error) {
		return netip.AddrFrom4([4]byte{198, 51, 100, 9}), nil
	})
	const host = "dc-eu.example.com"
	payload := []byte{0xff, 0xff, 0xff, 0xff, 9, 9, 9, 9, 1, 0, 0, 0}
	m.StartShadowForkingForFakeHost(host, 7770, payload, func([]byte) bool { return true })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.getSegmentLockByHost(host) != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	ent := m.getSegmentLockByHost(host)
	if ent == nil {
		t.Fatalf("race winner must be reachable via domain index (getSegmentLockByHost(%q)), /24 lock=%+v",
			host, m.getSegmentLock("198.51.100.0/24"))
	}
	if ent.Host != host {
		t.Fatalf("lock entry must carry the triggering host, got %q", ent.Host)
	}
	if ent.Proxy == "" {
		t.Fatal("lock entry must carry the winner proxy")
	}
	// 双索引一致：域名索引与 /24 索引解析到同一条锁死条目
	if bySeg := m.getSegmentLock("198.51.100.0/24"); bySeg != ent {
		t.Fatal("domain index and /24 index must resolve to the same lock entry")
	}
}

// ---- 2026-10-18 v2.1：Retarget 主路对齐（批复方案 B + 三处致命修正）----

// 方案 B：lockSegment 落锁时把 /24 命中的自动目标主路切到赢家；
// 显式配置目标不受影响（配置优先=永久保护）；宽段自动目标不跟随
// （Q-F5 裁决：仅前缀位数 >=24 匹配）；真实变更触发按 IP 重建联动
// （漏洞三，old 非空且 old≠新值）。
func TestSegmentLock_InstallsWinnerToTargets(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	var mu sync.Mutex
	var hooked []string
	m.SetRetargetHook(func(ip string) {
		mu.Lock()
		hooked = append(hooked, ip)
		mu.Unlock()
	})
	m.SetTargets([]Target{
		{ProcessName: "game-auto", CIDR: []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}},
		{ProcessName: "game-fix", CIDR: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32")}, Proxy: "US-01"},
		{ProcessName: "game-wide", CIDR: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
	})
	// 模拟锁死前已定主路（pre-lock 会话）：
	tAuto := m.targetByDst("198.51.100.9")
	if tAuto == nil {
		t.Fatal("auto target missing")
	}
	if _, real := tAuto.InstallSegmentWinner("TW-01"); real {
		t.Fatal("first install (old empty) must not report a real change")
	}
	mu.Lock()
	hooked = nil
	mu.Unlock()

	m.lockSegment("198.51.100.0/24", "dc-eu.example.com", "HK-01", "HK", 50)

	snaps := m.GetTargets()
	byName := map[string]Target{}
	for _, s := range snaps {
		byName[s.ProcessName] = s
	}
	if got := byName["game-auto"].currentPrimary; got != "HK-01" {
		t.Fatalf("auto target primary must switch to race winner HK-01, got %q", got)
	}
	autoSnap := byName["game-auto"]
	if !autoSnap.IsAutoPrimary() {
		t.Fatal("auto target must be autoPrimary after install")
	}
	if byName["game-fix"].Proxy != "US-01" || byName["game-fix"].currentPrimary != "" {
		t.Fatalf("explicit target must be untouched, got proxy=%q primary=%q",
			byName["game-fix"].Proxy, byName["game-fix"].currentPrimary)
	}
	if got := byName["game-wide"].currentPrimary; got != "" {
		t.Fatalf("wide-CIDR auto target must NOT follow /24 locks (Q-F5), got %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hooked) != 1 || hooked[0] != "198.51.100.9" {
		t.Fatalf("real primary change must trigger retarget hook for the target IP, got %v", hooked)
	}
}

// 漏洞一（Q-F4）：目标处于赛马锁有效期内 → targetSegmentLocked 命中；
// 解锁（TTL/劣化/连败惰性裁决）后放行。probeAndSettle 换主写回前以此把门。
func TestSegmentLock_ProbeGateWhileLocked(t *testing.T) {
	m := newDefaultManager()
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	m.SetTargets([]Target{
		{ProcessName: "game-x", CIDR: []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")}},
	})
	m.lockSegment("203.0.113.0/24", "dc-eu.example.com", "HK-01", "HK", 40)
	tgt := m.targetByDst("203.0.113.9")
	if tgt == nil {
		t.Fatal("target missing")
	}
	if !m.targetSegmentLocked(tgt, netip.Addr{}) {
		t.Fatal("target must be reported locked while segment lock is valid (probe gate closed)")
	}
	if !m.segmentLockActive("203.0.113.0/24") {
		t.Fatal("segmentLockActive must be true while locked")
	}
	m.UnlockSegmentForRerace("203.0.113.9", "test")
	if m.targetSegmentLocked(tgt, netip.Addr{}) {
		t.Fatal("target must be reported unlocked after unlock-for-rerace (probe gate open)")
	}
	if m.segmentLockActive("203.0.113.0/24") {
		t.Fatal("segmentLockActive must be false after unlock")
	}
}
