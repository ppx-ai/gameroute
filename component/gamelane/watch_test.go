package gamelane

import (
	"net/netip"
	"testing"
	"time"
)

// TestWatchKeepsGameTarget 注册后持续具备对局特征（高频、双向、小包）
// 的目标应被确认保留：observeWatch 返回 true 且目标仍在注册表。
func TestWatchKeepsGameTarget(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	ip := "45.56.120.20"
	if !m.RegisterTargetIP(ip) {
		t.Fatalf("注册失败")
	}
	meta := testMeta(ip, 9000)
	meta.SrcPort = 40001
	for i := 0; i < 30; i++ {
		if !m.observeWatch(meta, 80) {
			t.Fatalf("对局特征目标不应被淘汰 (iter %d)", i)
		}
		if i%2 == 0 {
			m.observeWatchReply(netip.MustParseAddr(ip), 9000, 80)
		}
	}
	if found := m.hasTarget(ip); !found {
		t.Fatalf("对局特征目标应保留在注册表")
	}
}

// hasTarget 检查注册表是否包含指定 /32 目标。
func (m *Manager) hasTarget(ip string) bool {
	for _, tg := range m.GetTargets() {
		for _, c := range tg.CIDR {
			if c.String() == ip+"/32" {
				return true
			}
		}
	}
	return false
}

// TestWatchEvictLargeDownload 注册目标出现大包下载特征（大包占比过半且
// 数量达标）应自动淘汰：observeWatch 返回 false 且目标被移出注册表。
func TestWatchEvictLargeDownload(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	ip := "45.56.120.21"
	if !m.RegisterTargetIP(ip) {
		t.Fatalf("注册失败")
	}
	meta := testMeta(ip, 9000)
	meta.SrcPort = 40001
	// 先建立少量双向小包，再转入大包下载
	for i := 0; i < 3; i++ {
		if !m.observeWatch(meta, 80) {
			t.Fatalf("初期不应淘汰")
		}
		m.observeWatchReply(netip.MustParseAddr(ip), 9000, 80)
	}
	// 大包下载：c2s 大包 10 个（占比 10/13 > 0.5 且 ≥5 个）
	for i := 0; i < 10; i++ {
		m.observeWatch(meta, 1400)
	}
	if m.observeWatch(meta, 1400) {
		t.Fatalf("大包下载特征应触发自动淘汰")
	}
	found := false
	for _, tg := range m.GetTargets() {
		for _, c := range tg.CIDR {
			if c.String() == ip+"/32" {
				found = true
			}
		}
	}
	if found {
		t.Fatalf("大包下载目标应已被淘汰出注册表")
	}
}

// TestWatchEvictSrcPortFlap 本地端口跳变（非固定对局会话）应自动淘汰。
func TestWatchEvictSrcPortFlap(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	ip := "45.56.120.22"
	if !m.RegisterTargetIP(ip) {
		t.Fatalf("注册失败")
	}
	meta1 := testMeta(ip, 9000)
	meta1.SrcPort = 40001
	if !m.observeWatch(meta1, 80) {
		t.Fatalf("首端口不应淘汰")
	}
	meta2 := testMeta(ip, 9000)
	meta2.SrcPort = 40002
	if m.observeWatch(meta2, 80) {
		t.Fatalf("本地端口跳变应触发自动淘汰")
	}
}

// TestWatchEvictOneWayFlow 出站持续活跃但回复停止超过阈值（单向流）应淘汰。
func TestWatchEvictOneWayFlow(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	ip := "45.56.120.23"
	if !m.RegisterTargetIP(ip) {
		t.Fatalf("注册失败")
	}
	meta := testMeta(ip, 9000)
	meta.SrcPort = 40001
	// 建立双向会话：出站 ≥20 包、回复 >0
	for i := 0; i < 25; i++ {
		if !m.observeWatch(meta, 80) {
			t.Fatalf("初期不应淘汰")
		}
	}
	m.observeWatchReply(netip.MustParseAddr(ip), 9000, 80)
	// 回复停止：模拟 30s 后仍持续出站
	watchesMu := m.watchesMu
	watchesMu.Lock()
	m.watches[ip].lastReplyTS = time.Now().UnixMilli() - watchNoReplyMs - 1000
	watchesMu.Unlock()
	if m.observeWatch(meta, 80) {
		t.Fatalf("单向流（回复停止）应触发自动淘汰")
	}
}

// TestWatchSweepIdleCleanup 24h 无对局特征流量 → sweepWatches 自动清理。
func TestWatchSweepIdleCleanup(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	ip := "45.56.120.24"
	if !m.RegisterTargetIP(ip) {
		t.Fatalf("注册失败")
	}
	// 模拟 24h 无对局特征（lastMatchTS 置为 24h 前）
	m.watchesMu.Lock()
	m.watches[ip].lastMatchTS = time.Now().UnixMilli() - watchCleanAfterMs - 1000
	m.watchesMu.Unlock()
	m.sweepWatches()
	found := false
	for _, tg := range m.GetTargets() {
		for _, c := range tg.CIDR {
			if c.String() == ip+"/32" {
				found = true
			}
		}
	}
	if found {
		t.Fatalf("24h 无对局特征目标应被 sweep 清理")
	}
}

// TestFlowScoreSuspectPromote 疑似目标连续 3 个观察窗口分数上升才升级注册；
// 分数不持续上升（回落）则不注册。
func TestFlowScoreSuspectPromote(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	meta := testMeta("45.56.120.25", 9002)
	meta.SrcPort = 40001
	now := time.Now().UnixMilli()
	key := "45.56.120.25:9002"

	// 构造已满足观察期（≥5s / ≥20 包 / 小包占比≥0.6）且连续 3 窗口上升的疑似条目
	seedFlow := func(scores []int, s2c int) {
		t.Helper()
		m.flowsMu.Lock()
		m.flows[key] = &flowStat{
			firstTS:      now - 6000,
			lastTS:       now,
			prevTS:       now,
			packets:      25,
			s2c:          s2c,
			small:        25,
			lastScoreTS:  0,
			scores:       append([]int(nil), scores...),
		}
		m.flowsMu.Unlock()
	}

	// 连续上升 [60,65,70] → 应升级注册
	seedFlow([]int{60, 65, 70}, 12)
	if !m.ObserveUDPFlow(meta, 80) {
		t.Fatalf("连续 3 窗口分数上升的疑似目标应升级注册")
	}
	if !m.hasTarget("45.56.120.25") {
		t.Fatalf("升级注册后目标应出现在注册表")
	}
	// 观察条目应已清空
	m.flowsMu.Lock()
	_, exist := m.flows[key]
	m.flowsMu.Unlock()
	if exist {
		t.Fatalf("升级注册后观察条目应被清除")
	}

	// 分数回落 [70,65,60] → 不应注册
	m2 := newDefaultManager()
	m2.SetEnabled(true)
	meta2 := testMeta("45.56.120.26", 9003)
	key2 := "45.56.120.26:9003"
	m2.flowsMu.Lock()
	m2.flows[key2] = &flowStat{
		firstTS:      now - 6000,
		lastTS:       now,
		prevTS:       now,
		packets:      25,
		s2c:          12,
		small:        25,
		lastScoreTS:  0,
		scores:       []int{70, 65, 60},
	}
	m2.flowsMu.Unlock()
	if m2.ObserveUDPFlow(meta2, 80) {
		t.Fatalf("分数回落的疑似目标不应升级注册")
	}
	if m2.hasTarget("45.56.120.26") {
		t.Fatalf("分数回落目标不应出现在注册表")
	}
}
