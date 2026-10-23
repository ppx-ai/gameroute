package gamelane

import (
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func testMeta(ip string, port uint16) *C.Metadata {
	addr, _ := netip.ParseAddr(ip)
	return &C.Metadata{
		DstIP:   addr,
		DstPort: port,
	}
}

// feed 以固定间隔向观察器喂 n 个同特征出站包，返回是否注册成功。
func feed(t *testing.T, m *Manager, meta *C.Metadata, n int, payloadLen int, gap time.Duration) bool {
	t.Helper()
	for i := 0; i < n; i++ {
		if m.ObserveUDPFlow(meta, payloadLen) {
			return true
		}
		if gap > 0 {
			time.Sleep(gap)
		}
	}
	return false
}

// feedReply 向观察器喂 n 个服务器→客户端回复包（对称性计数）。
func feedReply(t *testing.T, m *Manager, addrPort netip.AddrPort, n int, payloadLen int) {
	t.Helper()
	for i := 0; i < n; i++ {
		m.ObserveUDPReply(addrPort, payloadLen)
	}
}

func TestFlowObserverRegisterGameTarget(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)

	// 27015 命中 PUBG 端口段（27000-27200）→ 已知游戏端口快速注册路径
	meta := testMeta("45.56.120.1", 27015)
	// 30 包 × 200ms = 6s，满足观察期(≥5s)/包数(≥20)/小包占比(≥0.6)
	ok := feed(t, m, meta, 30, 80, 200*time.Millisecond)
	if !ok {
		t.Fatalf("期望持续高频小包流触发自动注册")
	}
	// 已注册后重复喂入不应再次注册（幂等：RegisterTargetIP 覆盖检查）
	if feed(t, m, meta, 30, 80, 200*time.Millisecond) {
		t.Fatalf("已注册目标不应重复注册")
	}
	// 目标应已进入注册表
	ip := meta.DstIP.String()
	found := false
	for _, tg := range m.targets {
		for _, c := range tg.CIDR {
			if c.String() == ip+"/32" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("目标 %s/32 未出现在注册表", ip)
	}
}

// TestFlowObserverSymmetricRegistered 普通端口（非已知游戏端口段）必须
// 同时满足双向对称性：出站 30 包 + 回复 15 包（比例 2:1 ∈ [0.3,3]）才注册。
func TestFlowObserverSymmetricRegistered(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)

	meta := testMeta("45.56.120.7", 9000)
	ok := feed(t, m, meta, 30, 80, 200*time.Millisecond)
	if ok {
		t.Fatalf("未满足对称性（无回复包）不应注册")
	}
	// 观察条目应仍存在（对称性不达标不删条目，等待回复包积累）
	m.flowsMu.Lock()
	_, exist := m.flows["45.56.120.7:9000"]
	m.flowsMu.Unlock()
	if !exist {
		t.Fatalf("对称性不达标时观察条目不应被删除")
	}
	// 补 15 个回复包（2:1），再喂一个出站包触发判定
	feedReply(t, m, netip.AddrPortFrom(netip.MustParseAddr("45.56.120.7"), 9000), 15, 80)
	if !m.ObserveUDPFlow(meta, 80) {
		t.Fatalf("满足双向对称性(2:1)后应注册")
	}
}

// TestFlowObserverAsymmetricRejected 下载类单向流量：出站多、回复极少
// （比例远超 3）不得注册；回复补足至对称区间后才允许注册。
func TestFlowObserverAsymmetricRejected(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)

	meta := testMeta("45.56.120.8", 9001)
	// 出站 30 包 × 200ms = 6s，无任何回复 → 严重不对称，不注册
	if feed(t, m, meta, 30, 80, 200*time.Millisecond) {
		t.Fatalf("无回复包的纯出站流不应注册")
	}
	// 仅 3 个回复包（比例 10:1 > 3），仍不对称，不注册
	feedReply(t, m, netip.AddrPortFrom(netip.MustParseAddr("45.56.120.8"), 9001), 3, 80)
	if m.ObserveUDPFlow(meta, 80) {
		t.Fatalf("比例 10:1 严重不对称不应注册")
	}
	// 回复补足到 15（比例 2:1），应注册
	feedReply(t, m, netip.AddrPortFrom(netip.MustParseAddr("45.56.120.8"), 9001), 12, 80)
	if !m.ObserveUDPFlow(meta, 80) {
		t.Fatalf("回复补足至对称区间后应注册")
	}
}

// TestFlowObserverKnownPortFastRegister 命中已知游戏端口段时免对称性
// 快速注册：APEX/PUBG 端口段纯出站高频小包（无回复）观察期≥5s 即注册。
func TestFlowObserverKnownPortFastRegister(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)

	// APEX 主同步 1024-1124 / 备用 9960-9969 / 对局 37000-37015
	for _, port := range []uint16{1024, 1124, 9960, 9969, 37000, 37015, 27000, 27200} {
		m2 := newDefaultManager()
		m2.SetEnabled(true)
		meta := testMeta("45.56.120.9", port)
		if !feed(t, m2, meta, 30, 80, 200*time.Millisecond) {
			t.Fatalf("已知游戏端口 %d 应快速注册", port)
		}
	}
}

func TestFlowObserverTooFewPackets(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	meta := testMeta("45.56.120.2", 27015)
	// 3s 内仅 5 包，包数不足不应注册
	if feed(t, m, meta, 5, 80, 100*time.Millisecond) {
		t.Fatalf("包数不足不应注册")
	}
}

func TestFlowObserverLargePayloadRejected(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	meta := testMeta("45.56.120.3", 27015)
	// 全是 1500B 大包（视频/下载特征），小包占比 0 < 0.6 不应注册
	if feed(t, m, meta, 30, 1500, 110*time.Millisecond) {
		t.Fatalf("大包占比过高不应注册")
	}
}

func TestFlowObserverSkipPorts(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	// 前置排除：已知非游戏 UDP 服务端口喂单包即应返回 false
	for port, name := range map[uint16]string{53: "DNS", 123: "NTP", 443: "QUIC", 3478: "STUN", 5353: "mDNS", 1900: "UPnP", 8081: "CDN", 27022: "Steam探测"} {
		meta := testMeta("45.56.120.4", port)
		if m.ObserveUDPFlow(meta, 80) {
			t.Fatalf("%s 端口不应触发注册", name)
		}
	}
}

func TestFlowObserverPrivateIPRejected(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	// 前置排除：私网/保留地址喂单包即应返回 false
	for _, ip := range []string{"192.168.1.10", "10.0.0.5", "172.16.0.8"} {
		meta := testMeta(ip, 27015)
		if m.ObserveUDPFlow(meta, 80) {
			t.Fatalf("私网 %s 不应注册", ip)
		}
	}
}

// TestFlowObserverExcludedCIDR 排除层：Discord/Steam/TUN 虚拟网段/组播/
// 环回/CGNAT/链路本地等命中任一排除段喂单包即应返回 false。
func TestFlowObserverExcludedCIDR(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	cases := map[string]string{
		// v2.5 第一刀批复：155.133.224.0/19（Valve SDR）与 162.254.192.0/18
		//（Valve 核心）洗白入白名单，其排除断言撤销——见 retarget_v25_test.go。
		"198.18.0.1":      "TUN 198.18.0.0/15",
		"198.19.255.254":  "TUN 198.18.0.0/15",
		"224.0.0.1":       "组播 224.0.0.0/4",
		"239.255.255.254": "组播 224.0.0.0/4",
		"127.0.0.1":       "环回 127.0.0.0/8",
		"100.64.0.1":      "CGNAT 100.64.0.0/10",
		"169.254.0.1":     "链路本地 169.254.0.0/16",
	}
	for ip, name := range cases {
		meta := testMeta(ip, 37000) // 即使命中已知游戏端口段也必须被排除层拦截
		if m.ObserveUDPFlow(meta, 80) {
			t.Fatalf("排除段 %s（%s）不应注册", ip, name)
		}
	}
	// RegisterTargetIP 注册前终检：即使直接调用也应拒绝排除段 IP
	for ip := range cases {
		if m.RegisterTargetIP(ip) {
			t.Fatalf("注册前终检应拒绝排除段 %s", ip)
		}
	}
}

// TestFlowObserverReplyExcludedCIDR 回复方向同样拒绝排除段：Discord/
// Steam 等段即使出现在回复源地址也不建立观察计数。
func TestFlowObserverReplyExcludedCIDR(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	meta := testMeta("45.56.120.10", 9002)
	// 先建立观察条目
	if m.ObserveUDPFlow(meta, 80) {
		t.Fatalf("单包不应注册")
	}
	// 回复源命中排除段（如服务器实际为 Discord CDN 段）→ 不计数
	feedReply(t, m, netip.AddrPortFrom(netip.MustParseAddr("155.133.224.1"), 9002), 30, 80)
	m.flowsMu.Lock()
	st, ok := m.flows["45.56.120.10:9002"]
	m.flowsMu.Unlock()
	if !ok || st.s2c != 0 {
		t.Fatalf("排除段回复源不应增加 s2c 计数")
	}
}

func TestFlowObserverDisabled(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(false)
	meta := testMeta("45.56.120.5", 27015)
	if m.ObserveUDPFlow(meta, 80) {
		t.Fatalf("game-lane 未启用时不应注册")
	}
}

func TestFlowObserverEntryCleanup(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	meta := testMeta("45.56.120.6", 27015)
	// 喂入少量包（不触发注册）后条目存在
	if m.ObserveUDPFlow(meta, 80) {
		t.Fatalf("不应提前注册")
	}
	m.flowsMu.Lock()
	if len(m.flows) == 0 {
		m.flowsMu.Unlock()
		t.Fatalf("期望存在观察条目")
	}
	// 人为老化已有条目，再塞满到上限之上，触发懒清理
	for k, s := range m.flows {
		s.lastTS = time.Now().Add(-2 * time.Minute).UnixMilli()
		m.flows[k] = s
	}
	m.flowsMu.Unlock()
	for i := 0; i < flowMaxEntries+1; i++ {
		meta2 := testMeta("45.56.120.6", uint16(10000+i))
		_ = m.ObserveUDPFlow(meta2, 80)
	}
	m.flowsMu.Lock()
	n := len(m.flows)
	m.flowsMu.Unlock()
	if n > flowMaxEntries {
		t.Fatalf("清理后条目数 %d 仍超过上限 %d", n, flowMaxEntries)
	}
}
