package gamelane

// Shadow Forking 首包五路赛马（2026-10-17 改造需求 C，批复 Q3/Q4/死六一~四）：
// 游戏客户端第一个测速包命中扳机（需求 B）后，内核深拷贝 payload 经五区
// 冠军节点（需求 F）并发旁路发往同一目标；最先回包者写回 TUN（五元组不变，
// 唯一例外见红线 3）并锁死该 /24（Q3）；其余旁路回包记录 RTT 后静默 DROP。
// 原路回包永不拦截、不参与仲裁（批复修正一），客户端对同序号重复回包自有防重。

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	raceTimeoutMs = 3000 // 需求 C：旁路 3 秒超时
	raceTailMs    = 2000 // Q4：首包写回后的旁路迟到包窗口（min(2s, 全路关闭≤3s)）

	segmentLockTTLMs = 30 * 60 * 1000 // 死六四①：锁死 TTL 30 分钟
)

// raceLane 一路旁路通道。
type raceLane struct {
	name   string
	region string
	conn   net.PacketConn
	sentAt time.Time
}

// raceReply 一路旁路的回包。
type raceReply struct {
	proxy  string
	region string
	rttMs  int
	data   []byte
}

// raceDialer 旁路拨号抽象：生产实现从 SetProbeSource 注入的 proxyObjs 拨
// UDP（与 tunnel.handleUDPConn 的节点拨号同源）；测试注入 fake。
type raceDialer func(name string, dst netip.AddrPort) (net.PacketConn, error)

// raceSession 一次五路赛马会话。
type raceSession struct {
	dst       netip.AddrPort
	payload   []byte
	seg       string                 // 目标 /24（锁死键）
	host      string                 // 触发流反查域名（fake-ip 模式非空，域名锁索引键）
	writeBack func(data []byte) bool // 首包写回 TUN；nil=预热探针（红线 3：不进 TUN）
	lanes     []*raceLane
	replyCh   chan raceReply
	closed    atomic.Bool
}

// SetRaceDialer 注入赛马旁路拨号（测试用；生产留空走 proxyObjs 默认拨号）。
func (m *Manager) SetRaceDialer(fn raceDialer) {
	m.raceDialerMu.Lock()
	m.raceDialerFn = fn
	m.raceDialerMu.Unlock()
}

func (m *Manager) currentRaceDialer() raceDialer {
	m.raceDialerMu.Lock()
	fn := m.raceDialerFn
	m.raceDialerMu.Unlock()
	if fn != nil {
		return fn
	}
	return m.defaultRaceDialer
}

// defaultRaceDialer 生产拨号：按冠军节点名拨 UDP 到目标（dst IP:port），
// 与 tunnel.handleUDPConn 的节点拨号同源（proxyObjs 由 SetProbeSource 注入）。
func (m *Manager) defaultRaceDialer(name string, dst netip.AddrPort) (net.PacketConn, error) {
	m.probeMu.Lock()
	objs := m.proxyObjs
	m.probeMu.Unlock()
	p, ok := objs[name]
	if !ok || name == "" || name == "DIRECT" {
		return nil, fmt.Errorf("[GameRoute] race proxy %s not found", name)
	}
	meta := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.INNER,
		DstIP:   dst.Addr(),
		DstPort: dst.Port(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(raceTimeoutMs)*time.Millisecond)
	defer cancel()
	return p.ListenPacketContext(ctx, meta)
}

// IsSpeedtestProbePayload 测速包字节级扳机（需求 B）：payload 前 4 字节 =
// 0xffffffff 且整包 <64 字节。ns 级开销、零分配；对局包/其他流量一律
// false（红线 1）。长度下限 8B：4B magic + 4B 序号（已验证事实 1）。
func IsSpeedtestProbePayload(payload []byte) bool {
	return len(payload) >= 8 && len(payload) < 64 &&
		payload[0] == 0xff && payload[1] == 0xff && payload[2] == 0xff && payload[3] == 0xff
}

// raknetOfflineMagic RakNet Unconnected Ping 的离线消息 ID 魔数（16B）。
var raknetOfflineMagic = [16]byte{
	0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
}

// isProbeGuardPort STUN/WebRTC 与自动注册排除端口守卫（v2.9 裁决 2）。
// 3478/3479/5349 为 STUN/TURN，19302 为 Google 公共 STUN；其余复用
// IsExcludedAutoRegPort 单一来源（53/123/443/1900/3478/5353/8081/8125）。
func isProbeGuardPort(dport uint16) bool {
	switch dport {
	case 3478, 3479, 5349, 19302:
		return true
	}
	return IsExcludedAutoRegPort(dport)
}

// IsSpeedtestProbePayloadForPort v2.9 P3（2026-10-19 批复裁决 2）：
// 带目标端口守卫的测速扳机，供 UDP 热路径 tunnel/tunnel.go:168 使用。
//
//   - 0xffffffff 分支：完全沿用原口径，不查端口（GameLift 7770 等）；
//   - STUN Binding Request 与 RakNet Unconnected Ping 属通用协议，浏览器
//     WebRTC / 在线状态 / 后台信令日常即出现，必须同时排除 3478/3479/5349/
//     19302 与 IsExcludedAutoRegPort，否则单条 STUN 包就会触发五路克隆、
//     打爆节点 UDP 句柄。
//
// 开销：零分配；仅在不命中 0xffffffff 时多一次端口 switch。
func IsSpeedtestProbePayloadForPort(payload []byte, dport uint16) bool {
	kind := probeKind(payload, dport)
	// v2.10 埋点：按扳机类型分桶计数（atomic，热路径零分配）
	switch kind {
	case probeProtoMagic:
		metricsProbeMagicHit.Add(1)
	case probeProtoSTUN:
		metricsProbeStunHit.Add(1)
	case probeProtoRakNet:
		metricsProbeRaknetHit.Add(1)
	case probeKindGuard:
		metricsProbeGuardBlock.Add(1)
	}
	return kind == probeProtoMagic || kind == probeProtoSTUN || kind == probeProtoRakNet
}

// probeKind 是扳机判定的唯一实现（不计数），IsSpeedtestProbePayloadForPort
// 只在其上做计数分桶。返回值：
//   - probeProtoMagic / probeProtoSTUN / probeProtoRakNet：应起跑赛马；
//   - probeKindGuard：STUN/RakNet 形态但端口被守卫否决（计数口径用）；
//   - probeKindNone：不是测速探针。
func probeKind(payload []byte, dport uint16) string {
	if len(payload) < 8 || len(payload) >= 64 {
		return probeKindNone
	}
	if payload[0] == 0xff && payload[1] == 0xff && payload[2] == 0xff && payload[3] == 0xff {
		// 0xffffffff 分支：完全沿用原口径，不查端口（GameLift 7770 等）
		return probeProtoMagic
	}
	if isProbeGuardPort(dport) {
		return probeKindGuard
	}
	// STUN Binding Request：type=0x0001 + magic cookie 0x2112A442（RFC 5389）
	if len(payload) >= 20 && payload[0] == 0x00 && payload[1] == 0x01 &&
		payload[4] == 0x21 && payload[5] == 0x12 && payload[6] == 0xa4 && payload[7] == 0x42 {
		return probeProtoSTUN
	}
	// RakNet Unconnected Ping：0x01 + 8B 时间戳 + 16B 离线消息 ID（最小 25B）
	if len(payload) >= 25 && payload[0] == 0x01 {
		for i := 0; i < 16; i++ {
			if payload[9+i] != raknetOfflineMagic[i] {
				return probeKindNone
			}
		}
		return probeProtoRakNet
	}
	return probeKindNone
}

// isMatchServerPort 对局服务器端口判定（v2.9 批复修正二，强制口径变更）：
// 除 APEX 两个客户端本地源端口段外，gamePortRanges 其余全段一律算对局端口。
//
// 变更原因（原口径 r[0] >= 27000 的漏洞）：3724 / 6113 / 26503-36503（OW2）、
// 3074（COD）、5000-5500（Valorant）是实打实的对局服务端口，OW2/COD 语音
// 通道大量走 STUN/WebRTC；若这些段不算对局端口，撞上 D 项新魔数就会触发
// 五路克隆，违反红线 2（对局端口绝不克隆/预热）。
func isMatchServerPort(port uint16) bool {
	for _, r := range gamePortRanges {
		if r[0] == 1024 && r[1] == 1124 {
			continue // APEX 客户端本地源端口
		}
		if r[0] == 9960 && r[1] == 9969 {
			continue // APEX 客户端备用源端口
		}
		if port >= r[0] && port <= r[1] {
			// v2.10 埋点：v2.9 扩容段（3724/6113/3074/26503-36503/5000-5500）
			// 是否真的把流量认成对局端口——决定"绝不克隆"红线是否生效。
			metricsMatchServerPortHit.Add(1)
			return true
		}
	}
	return false
}

// IsStatelessProbePort 无状态测速端口判定（2026-10-18 v2.3 Q-H1 反转口径）：
// dport==7770（GameLift UDP Ping Beacon）或命中该目标已学习的测速模板端口
// 时为 true——无状态测速流允许抢回重建。前提 !isMatchServerPort(dport)：
// 真实对局端口（gamePortRanges 全集）永远不算无状态，绝不抢。
// 反转原因（批复铁证）：APEX 对局服务器 216.244.12.165:10200 不在
// gamePortRanges，任何"对局端口黑名单放行"口径都会把它掐断 → code:house
// 复发；故改为"仅显式无状态测速端口可豁免保护"的白名单口径。
func (m *Manager) IsStatelessProbePort(dstIP netip.Addr, dport uint16) bool {
	if isMatchServerPort(dport) {
		return false
	}
	if dport == 7770 {
		return true
	}
	if !dstIP.IsValid() {
		return false
	}
	m.preheatMu.Lock()
	tpl, hasTpl := m.probeTemplates[dstIP.String()]
	m.preheatMu.Unlock()
	return hasTpl && tpl != nil && tpl.DstPort != 0 && tpl.DstPort == dport
}

// tryBeginRace 赛马占位（死六一）：同 /24 已有赛马在途 → false（放行不
// 克隆，防并发风暴打爆节点 UDP 句柄）；/24 已锁死 → false（需求 B4，
// 原包走锁死节点）。占位在赛马结束（写锁死表或 3s 超时）时由
// clearRacingSeg 释放。
func (m *Manager) tryBeginRace(seg string) bool {
	if seg == "" {
		return false
	}
	if ent := m.getSegmentLock(seg); ent != nil {
		return false
	}
	m.racingMu.Lock()
	if m.racingSegs == nil {
		m.racingSegs = make(map[string]int64)
	}
	if _, racing := m.racingSegs[seg]; racing {
		m.racingMu.Unlock()
		return false
	}
	m.racingSegs[seg] = time.Now().UnixMilli()
	m.racingMu.Unlock()
	return true
}

func (m *Manager) clearRacingSeg(seg string) {
	m.racingMu.Lock()
	delete(m.racingSegs, seg)
	m.racingMu.Unlock()
}

// SegmentNeedsRace 该目标 /24 是否需要赛马（需求 B3/B4 + Q2 + 死六一）：
// 端口守卫（对局段 + 模板端口绑定）→ 锁死健康检查（死六四①③惰性裁决）
// → 赛马占位 CAS。返回 true 表示占位已持有，调用方随后必须 StartShadowForking。
func (m *Manager) SegmentNeedsRace(ip netip.Addr, dport uint16) bool {
	if !ip.IsValid() {
		return false
	}
	if isMatchServerPort(dport) {
		return false // 红线 2：对局服端口绝不克隆
	}
	seg := segmentKey24(ip.String())
	if seg == "" {
		return false
	}
	// Q2 模板端口绑定：该目标已学习模板时，扳机要求 dport 与模板一致。
	m.preheatMu.Lock()
	tpl, hasTpl := m.probeTemplates[ip.String()]
	m.preheatMu.Unlock()
	if hasTpl && tpl != nil && tpl.DstPort != 0 && tpl.DstPort != dport {
		return false
	}
	return m.tryBeginRace(seg)
}

// getSegmentLock 查询 /24 锁死（域名索引路径见 getSegmentLockByHost）。
// 惰性执行解锁重赛条件（死六四①③）：①锁死超 TTL 30 分钟；③锁死节点
// 连续探测失败（rttFailStreak>=3）。解锁 = 旧条目移入 segmentStale（重赛
// 防抖动裁决用，域名索引同步摘除）并返回 nil。
func (m *Manager) getSegmentLock(seg string) *segmentLockEntry {
	return m.checkSegmentLock(seg)
}

// getSegmentLockByHost 按触发流域名查锁（2026-10-18 主路对齐 A：fake-ip
// 模式主路 DstIP 被 preHandleMetadata 清空，host 是唯一可用键）。
func (m *Manager) getSegmentLockByHost(host string) *segmentLockEntry {
	m.segmentLockMu.RLock()
	seg := m.segmentLockHostIdx[host]
	m.segmentLockMu.RUnlock()
	if seg == "" {
		return nil
	}
	return m.checkSegmentLock(seg)
}

// checkSegmentLock 锁死健康惰性裁决（segmentLockMu 持锁调用）。
func (m *Manager) checkSegmentLock(seg string) *segmentLockEntry {
	m.segmentLockMu.Lock()
	defer m.segmentLockMu.Unlock()
	ent, ok := m.segmentLock[seg]
	if !ok {
		return nil
	}
	now := time.Now().UnixMilli()
	drop := func(reason string) {
		m.segmentStale[seg] = ent
		delete(m.segmentLock, seg)
		if ent.Host != "" && m.segmentLockHostIdx[ent.Host] == seg {
			delete(m.segmentLockHostIdx, ent.Host)
		}
		log.Infoln("[GameRoute] segment lock %s unlocked (%s, node=%s), rerace armed", seg, reason, ent.Proxy)
	}
	if now-ent.LockedAt >= segmentLockTTLMs {
		drop("ttl-30min")
		return nil
	}
	// 连败计数读专用 failStreakMu（禁用 m.mu）：MatchTarget 全程持有
	// m.mu.RLock，v2.1 让重建会话重新查锁后必然经 ensureAutoPrimary
	// 进入本函数——同 goroutine RLock 升级 Lock 会自死锁（连带必要修复）。
	m.failStreakMu.RLock()
	streak := m.rttFailStreak[ent.Proxy]
	m.failStreakMu.RUnlock()
	if streak >= 3 {
		drop("probe-fail-streak")
		return nil
	}
	return ent
}

// UnlockSegmentForRerace 对局劣化/M3 切换触发的解锁重赛（死六四②）：
// 移除该 /24 锁死（旧条目移入 stale 供重赛防抖动裁决），后续重赛由
// 静态预热或下一轮测速流触发。
func (m *Manager) UnlockSegmentForRerace(dstIP string, reason string) {
	seg := segmentKey24(dstIP)
	if seg == "" {
		return
	}
	m.UnlockSegmentForReraceSeg(seg, reason)
}

// UnlockSegmentForReraceByHost 按域名解锁（fake-ip 模式主路 DstIP 被清空，
// M3 回调处只有 Host 可用——2026-10-18 主路对齐 A 配套）。
func (m *Manager) UnlockSegmentForReraceByHost(host string, reason string) {
	if host == "" {
		return
	}
	m.segmentLockMu.RLock()
	seg := m.segmentLockHostIdx[host]
	m.segmentLockMu.RUnlock()
	if seg != "" {
		m.UnlockSegmentForReraceSeg(seg, reason)
	}
}

// UnlockSegmentForReraceSeg 按 /24 键解锁（含域名索引同步摘除）。
func (m *Manager) UnlockSegmentForReraceSeg(seg string, reason string) {
	m.segmentLockMu.Lock()
	ent, ok := m.segmentLock[seg]
	if ok {
		m.segmentStale[seg] = ent
		delete(m.segmentLock, seg)
		if ent.Host != "" && m.segmentLockHostIdx[ent.Host] == seg {
			delete(m.segmentLockHostIdx, ent.Host)
		}
	}
	m.segmentLockMu.Unlock()
	if ok {
		log.Infoln("[GameRoute] segment lock %s unlocked for rerace (%s, node=%s)", seg, reason, ent.Proxy)
	}
}

// segmentLockActive 纯读判定 /24 锁死是否有效（TTL 内且存在）——与
// checkSegmentLock（带 TTL/连败惰性解锁副作用）不同，本函数无副作用，
// 供 probeAndSettle 门卫在 primaryMu 内调用（批复 Q-F4/漏洞一）。
// 连败③不计入（保守视为锁有效，等待下一次惰性裁决自然放行）。
func (m *Manager) segmentLockActive(seg string) bool {
	m.segmentLockMu.RLock()
	defer m.segmentLockMu.RUnlock()
	ent, ok := m.segmentLock[seg]
	if !ok {
		return false
	}
	return time.Now().UnixMilli()-ent.LockedAt < segmentLockTTLMs
}

// targetSegmentLocked 判定目标是否处于赛马锁有效期内：优先用流量目标 IP
// （probeAndSettle 的 dstIP，可能为零值），退化为目标首个 IPv4 CIDR。
func (m *Manager) targetSegmentLocked(t *Target, dstIP netip.Addr) bool {
	ip := dstIP
	if !ip.IsValid() && t != nil {
		for _, p := range t.CIDR {
			if p.Addr().Is4() {
				ip = p.Addr()
				break
			}
		}
	}
	if !ip.IsValid() || !ip.Is4() {
		return false
	}
	seg := segmentKey24(ip.String())
	if seg == "" {
		return false
	}
	return m.segmentLockActive(seg)
}

// switchTargetsToSegmentWinner 把 /24 段内命中的自动目标主路切到赛马赢家
// （2026-10-18 v2.1 批复方案 B）：锁出现的瞬间对齐全部既有目标，修复
// "锁死前已建会话的目标重建时 currentPrimary 非空跳过锁查询"的边界缺陷。
// 匹配口径（Q-F5 裁决）：仅前缀位数 >=24（/24 与 /32）且与锁死段重叠的
// 目标——0.0.0.0/0 等宽段自动目标不跟随任一 /24 锁，防全局目标被测速流
// 反复拽走。锁序（批复漏洞二）：在 m.mu.RLock 内直接完成安装——与
// MatchTarget 全程读锁下走 ensureAutoPicked 的既有锁序一致（m.mu→
// primaryMu），绝不跨锁持有切片元素裸指针（append 扩容悬垂）。
// 真实变更（old 非空且 old≠新值）时按目标 IP 触发会话重建（漏洞三，
// 经 F4 400ms 去抖）。
func (m *Manager) switchTargetsToSegmentWinner(seg, proxy string) {
	segPrefix, err := netip.ParsePrefix(seg)
	if err != nil || !segPrefix.Addr().Is4() {
		return
	}
	m.mu.RLock()
	var changed []string
	for i := range m.targets {
		t := &m.targets[i]
		hit := false
		for _, p := range t.CIDR {
			if p.Addr().Is4() && p.Bits() >= 24 && p.Overlaps(segPrefix) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if ip, real := t.InstallSegmentWinner(proxy); real {
			changed = append(changed, ip)
		}
	}
	m.mu.RUnlock()
	for _, ip := range changed {
		log.Infoln("[GameRoute] segment winner %s installed to target %s, retarget sessions", proxy, ip)
		m.notifyRetarget(ip)
	}
}

// SetRetargetHook 注册"按目标 IP 重建会话"回调（tunnel 层在 initUDP 注册
// scheduleRetarget，继承 F4 400ms 去抖；批复 v2.1 漏洞三联动通道）。
func (m *Manager) SetRetargetHook(fn func(ip string)) {
	m.retargetMu.Lock()
	m.retargetFn = fn
	m.retargetMu.Unlock()
}

// notifyRetarget 触发按 IP 重建（钩子未注册时静默——纯 gamelane 使用无隧道层）。
func (m *Manager) notifyRetarget(ip string) {
	if ip == "" {
		return
	}
	m.retargetMu.Lock()
	fn := m.retargetFn
	m.retargetMu.Unlock()
	if fn != nil {
		fn(ip)
	}
}

// lockSegment 赛马胜者锁死 /24（需求 C3 + 死六四）：内存锁死表写入（含
// rttMs）；重赛防抖动——若存在 stale 旧锁死且新胜者 RTT >= 旧 RTT/2，
// 恢复旧锁死不覆盖；game_memory.json 网段级条目按 Q10 单样本即写。
// 2026-10-18 主路对齐（批复 Q-E 方案 A）：host 非空时同步写域名索引——
// fake-ip 模式主路 DstIP 被 preHandleMetadata 清空，只能按 host 查锁。
func (m *Manager) lockSegment(seg, host, proxy, region string, rttMs int) {
	m.segmentLockMu.Lock()
	if m.segmentLock == nil {
		m.segmentLock = make(map[string]*segmentLockEntry)
	}
	if m.segmentStale == nil {
		m.segmentStale = make(map[string]*segmentLockEntry)
	}
	ent := &segmentLockEntry{Proxy: proxy, Region: region, RTTMs: rttMs, LockedAt: time.Now().UnixMilli()}
	if old, ok := m.segmentStale[seg]; ok {
		delete(m.segmentStale, seg)
		if old.RTTMs > 0 && rttMs >= old.RTTMs/2 {
			log.Infoln("[GameRoute] segment %s rerace winner %s rtt=%dms not better than old %s rtt=%dms (>=1/2), keep old lock",
				seg, proxy, rttMs, old.Proxy, old.RTTMs)
			ent = old
			ent.LockedAt = time.Now().UnixMilli()
		}
	}
	m.segmentLock[seg] = ent
	if host != "" {
		ent.Host = host
		m.segmentLockHostIdx[host] = seg
	}
	finalProxy, finalRegion := ent.Proxy, ent.Region
	m.segmentLockMu.Unlock()
	m.rememberSegmentWinner(seg, finalProxy, finalRegion) // Q10：网段级记忆单样本即写
	log.Infoln("[GameRoute] segment %s locked -> %s (%s, rtt=%dms, host=%s)", seg, finalProxy, finalRegion, ent.RTTMs, host)
	m.switchTargetsToSegmentWinner(seg, finalProxy) // v2.1 方案 B：赢家进场（含 keep-old 恢复路径）
}

// StartShadowForking 触发五路赛马（需求 C，真实 IP 路径）。前置条件：
// SegmentNeedsRace 已返回 true（占位已持有）；赛马结束（锁死或 3s 超时）
// 释放占位（死六一）。原路回包永不拦截（批复修正一）：原包与原路回包走
// 既有路径，本函数只管旁路的仲裁与写回。
func (m *Manager) StartShadowForking(dst netip.AddrPort, payload []byte, writeBack func(data []byte) bool) {
	m.MarkGameActive() // v2.4 漏洞三①：捕获 7770 测速包即入临战活跃态
	m.startRace(dst, "", payload, writeBack, nil)
}

// StartShadowForkingForFakeHost 第二招兜底（2026-10-18 批复 v2 防爆三原则
// ②③）：fake-ip 流反查得到的 host 由协程调用——内层 ResolveIP（1.5s）拿
// realIP → 判锁/学习/赛马全部以 realIP 为口径（批复①：绝不让 198.18/24
// 进锁死表）；host 为空（反查失败）直接放弃（批复②：外层已拦截，此处
// 兜底防御）。DNS 慢只卡本旁路协程，原包照发、主链路不阻塞。
func (m *Manager) StartShadowForkingForFakeHost(host string, dport uint16, payload []byte, writeBack func(data []byte) bool) {
	if host == "" {
		return // 反查失败兜底：放弃赛马（外层同样拦截，双保险）
	}
	resolve := m.currentRealIPResolver()
	if resolve == nil {
		return
	}
	rip, err := resolve(host)
	if err != nil || !rip.IsValid() {
		log.Warnln("[GameRoute] fake-ip resolve %s failed, race abandoned: %v", host, err)
		return
	}
	if resolver.IsFakeIP(rip) {
		// 防御：解析结果仍是 fake-ip（DNS 劫持环）——绝不让 198.18/24 进锁死表
		log.Warnln("[GameRoute] resolve %s still fake-ip (%s), race abandoned (anti-pollution)", host, rip)
		return
	}
	if !m.SegmentNeedsRace(rip, dport) {
		return
	}
	m.LearnProbeTemplate(rip.String(), dport, payload)
	// v2.6 联动 C（2026-10-19 终批复）：赛马旁路注册真实 IP/32——替代被删
	// 的 tunnel 衔接1（第二刀后主路不再回填 realIP）。仅 SegmentNeedsRace
	// 确认"该段需要赛马"（= 真实游戏服务器段）才走到这里；trusted=true
	// 顺带豁免黑名单（批复 1.3）。幂等。非 fake-ip 形态会话（游戏进程真实
	// IP 直发）由此可被 Match 命中；retarget 键/记忆链/预热模板键对齐 realIP。
	m.RegisterTargetIPTrusted(rip.String(), true)
	// 2026-10-18 代码核对修复：必须直调 startRace 传入 host——原经
	// StartShadowForking（host 恒 ""），赛马赢家 lockSegment 写域名索引
	// segmentLockHostIdx 永远落空，getSegmentLockByHost 永远查不到，
	// 方案 A（fake-ip 主路按域名查锁）整体失效。
	m.startRace(netip.AddrPortFrom(rip, dport), host, payload, writeBack, nil)
}

// startRace 赛马主体：返回实际起跑的旁路数。budget 非 nil 时每个旁路
// 扣 1（需求 D：单次预热总探针上限），耗尽即停止加路。
func (m *Manager) startRace(dst netip.AddrPort, host string, payload []byte, writeBack func(data []byte) bool, budget *int32) int {
	if !dst.IsValid() || len(payload) == 0 {
		m.clearRacingSeg(segmentKey24(dst.Addr().String()))
		return 0
	}
	champions := m.LaneChampions()
	dial := m.currentRaceDialer()
	if len(champions) == 0 || dial == nil {
		m.clearRacingSeg(segmentKey24(dst.Addr().String()))
		return 0
	}
	seg := segmentKey24(dst.Addr().String())
	s := &raceSession{
		dst:       dst,
		payload:   append([]byte(nil), payload...),
		seg:       seg,
		host:      host,
		writeBack: writeBack,
		replyCh:   make(chan raceReply, 8),
	}
	// 死六三：五区全部参赛——显式包含主路当前节点所在区的冠军（主路区
	// 旁路与主路同节点时允许重复发一份，服务器不去重，见已验证事实 3），
	// 保证五区公平抢答、不漏主路所在区。champions 为 区→节点名。
	for region, name := range champions {
		if name == "" || name == "DIRECT" {
			continue
		}
		if budget != nil && atomic.AddInt32(budget, -1) < 0 {
			break // 需求 D：单次预热总探针（旁路）上限 20
		}
		conn, err := dial(name, dst)
		if err != nil {
			log.Debugln("[GameRoute] race lane %s dial failed: %v", name, err)
			continue
		}
		s.lanes = append(s.lanes, &raceLane{name: name, region: region, conn: conn})
	}
	if len(s.lanes) == 0 {
		m.clearRacingSeg(seg)
		return 0
	}
	log.Infoln("[GameRoute] shadow forking start dst=%s lanes=%d (five-region race, tun-write=%v)",
		dst.String(), len(s.lanes), writeBack != nil)
	go s.run(m)
	return len(s.lanes)
}

// startRaceNodes 定向节点赛马（2026-10-18 v2.4 第二刀 2.2，谷歌强制修正
// 一①）：把指定节点列表全部拉上 7770 跑道——绕过 LaneChampions 五区各 1
// 代表的限制（HK 02 这类非代表节点必须能参赛）。占位由调用方持有；回包
// 只进 rttTable（Source="race"）/bestRaceWinner/段锁，绝不写 TUN（红线 3）。
func (m *Manager) startRaceNodes(dst netip.AddrPort, nodes []string, payload []byte, budget *int32) int {
	if !dst.IsValid() || len(payload) == 0 || len(nodes) == 0 {
		return 0
	}
	dial := m.currentRaceDialer()
	if dial == nil {
		return 0
	}
	seg := segmentKey24(dst.Addr().String())
	s := &raceSession{
		dst:     dst,
		payload: append([]byte(nil), payload...),
		seg:     seg,
		replyCh: make(chan raceReply, 8),
	}
	for _, name := range nodes {
		if name == "" || name == "DIRECT" {
			continue
		}
		if budget != nil && atomic.AddInt32(budget, -1) < 0 {
			break
		}
		conn, err := dial(name, dst)
		if err != nil {
			log.Debugln("[GameRoute] fanout lane %s dial failed: %v", name, err)
			continue
		}
		region, _ := extractRegionTag(name)
		s.lanes = append(s.lanes, &raceLane{name: name, region: region, conn: conn})
	}
	if len(s.lanes) == 0 {
		return 0
	}
	log.Infoln("[GameRoute] preheat fanout start dst=%s lanes=%d (region squad race)", dst.String(), len(s.lanes))
	go s.run(m)
	return len(s.lanes)
}

// run 赛马仲裁循环：首个旁路回包写 TUN（writeBack 非 nil 时）并锁死 /24；
// 窗口内（Q4：min(首包写回后 2s, 全路关闭≤3s)）其余回包记录 RTT 后 DROP。
func (s *raceSession) run(m *Manager) {
	defer m.clearRacingSeg(s.seg)
	deadline := time.Now().Add(time.Duration(raceTimeoutMs) * time.Millisecond)
	// 发包 + 各路读 goroutine（每路只取首个回包参与仲裁）
	for _, lane := range s.lanes {
		l := lane
		if _, err := l.conn.WriteTo(s.payload, udpAddrOf(s.dst)); err != nil {
			_ = l.conn.Close()
			continue
		}
		l.sentAt = time.Now()
		go func() {
			buf := make([]byte, 2048)
			for {
				if s.closed.Load() {
					return
				}
				_ = l.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, _, err := l.conn.ReadFrom(buf)
				if err != nil {
					if s.closed.Load() {
						return
					}
					continue // 读超时轮询，直到会话关闭
				}
				rttMs := int(time.Since(l.sentAt).Milliseconds())
				select {
				case s.replyCh <- raceReply{proxy: l.name, region: l.region, rttMs: rttMs, data: append([]byte(nil), buf[:n]...)}:
				default:
				}
				return
			}
		}()
	}
	var winner *raceReply
	var winnerAt time.Time
	for {
		remain := time.Until(deadline)
		if !winnerAt.IsZero() {
			tail := time.Until(winnerAt.Add(time.Duration(raceTailMs) * time.Millisecond))
			if tail < remain {
				remain = tail
			}
		}
		if remain <= 0 {
			break
		}
		select {
		case r := <-s.replyCh:
			// RTT 留档（需求 C4：备用参考）——复用既有探测入库口径
			// （EMA 平滑 + 失败连击判死），赛马实测为真值无需校正。
			// v2.4 第二刀：入库带 Source="race" 标签（进场裁决仅认 race）。
			m.MergeProbeResults(map[string]probeSample{r.proxy: {RttMs: r.rttMs, Samples: 1, OK: true, Source: "race"}})
			if winner == nil {
				winner = &r
				winnerAt = time.Now()
				// v2.4 第二刀（2.1）：全局赛马实测最优择优更新（防晚回包篡位）
				m.updateBestRaceWinner(r.proxy, r.region, r.rttMs)
				if s.writeBack != nil {
					if ok := s.writeBack(r.data); ok {
						log.Infoln("[GameRoute] race winner %s (%s, rtt=%dms), reply written to tun", r.proxy, r.region, r.rttMs)
					} else {
						log.Warnln("[GameRoute] race winner %s rtt=%dms write-back failed (session gone)", r.proxy, r.rttMs)
					}
					m.lockSegment(s.seg, s.host, r.proxy, r.region, r.rttMs) // C-5：抢答锁死（host 入域名索引）
				} else {
					log.Infoln("[GameRoute] preheat best %s (%s, rtt=%dms) (no tun write, red line 3)", r.proxy, r.region, r.rttMs)
				}
			} else {
				// 其余慢包：RTT 已留档，静默 DROP（需求 C4）
				log.Debugln("[GameRoute] race loser %s rtt=%dms dropped", r.proxy, r.rttMs)
			}
		case <-time.After(minDuration(remain, 200*time.Millisecond)):
		}
	}
	s.closeLanes()
	if winner == nil {
		log.Infoln("[GameRoute] shadow forking timeout dst=%s (original path untouched)", s.dst.String())
	}
}

func (s *raceSession) closeLanes() {
	s.closed.Store(true)
	for _, l := range s.lanes {
		_ = l.conn.Close() // 需求 C4：句柄全部关闭，防内存泄漏
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// udpAddrOf 手工构造 UDPAddr（本仓库工具链下 netip.AddrPort 无 UDPAddr 方法）。
func udpAddrOf(ap netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(ap.Addr().AsSlice()), Port: int(ap.Port())}
}

// PendingHostsAdd 在途 fake-ip 解析去重占位（Q-D：防测速包风暴造成 DNS
// 解析放大）。返回 false=同 host 已有在途解析，本次放行不克隆。
func (m *Manager) PendingHostsAdd(host string) bool {
	m.pendingHostsMu.Lock()
	if m.pendingHosts == nil {
		m.pendingHosts = make(map[string]struct{})
	}
	if _, ok := m.pendingHosts[host]; ok {
		m.pendingHostsMu.Unlock()
		return false
	}
	m.pendingHosts[host] = struct{}{}
	m.pendingHostsMu.Unlock()
	return true
}

// PendingHostsDelete 释放在途解析占位（调用协程 defer 首行执行，死六二铁律）。
func (m *Manager) PendingHostsDelete(host string) {
	m.pendingHostsMu.Lock()
	delete(m.pendingHosts, host)
	m.pendingHostsMu.Unlock()
}

// SetRealIPResolver 注入 fake-ip host → realIP 解析器（测试用；生产留空
// 走 defaultRealIPResolver = resolver.ResolveIP，1.5s 超时）。
func (m *Manager) SetRealIPResolver(fn func(host string) (netip.Addr, error)) {
	m.realIPMu.Lock()
	m.realIPResolverFn = fn
	m.realIPMu.Unlock()
}

func (m *Manager) currentRealIPResolver() func(host string) (netip.Addr, error) {
	m.realIPMu.Lock()
	fn := m.realIPResolverFn
	m.realIPMu.Unlock()
	if fn != nil {
		return fn
	}
	return defaultRealIPResolver
}

var defaultRealIPResolver = func(host string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	return resolver.ResolveIP(ctx, host)
}

// udpPacketLike 出站 TUN 包的最小接口（C.UDPPacket 天然满足）。
type udpPacketLike interface {
	WriteBack(b []byte, addr net.Addr) (n int, err error)
	LocalAddr() net.Addr
}

// PacketWriteBackSink 将 TUN 出站包的 WriteBack 适配为赛马写回函数
// （需求 C3：旁路赢家回包写回客户端，五元组不变）。
// 2026-10-18 批复 Q-A 拍板方案 (ii)：addr 传**原包目的地址**的值拷贝
// （fake-ip 路径=客户端认识的 fake-ip；真实路径=真实服务器 IP）——
// 绝不传 nil（sing 实测报 "address is invalid"），也绝不引用会被
// preHandleMetadata 清空的 metadata.DstIP。
func PacketWriteBackSink(packet udpPacketLike, origDstAddr net.Addr) func(data []byte) bool {
	return func(data []byte) bool {
		_, err := packet.WriteBack(data, origDstAddr)
		return err == nil
	}
}
