package gamelane

// 静态探针主动预热（2026-10-17 改造需求 D，批复 Q6）：模板"捕获学习"
// （需求 B 命中时 LearnProbeTemplate），预热用原样 payload 从五区冠军
// 并发发出，统计真实 UDP RTT 预热选路——无需等待客户端发包。预热回包
// 绝不写 TUN（红线 3）；不硬编码任何游戏指纹（红线 5）。

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

// bahrainDeadZone 巴林死区（AWS me-south-1）：v2.5 第二刀 2.1 禁作测速模板。
var bahrainDeadZone = netip.MustParsePrefix("15.184.0.0/15")

const (
	preheatMinIntervalMs = 5000 // 节流红线：同一目标 5s 最多 1 个主动探针
	preheatMaxPerRound   = 20   // 单次预热总探针数（旁路）上限
	preheatMaxPayload    = 64   // 与扳机口径一致
)

// probeTemplate 单个目标的学习模板（Q6：独立文件 runtime/game_probe_templates.json）。
type probeTemplate struct {
	PayloadHex string `json:"payload_hex"`
	DstPort    uint16 `json:"dport"`
	LearnedAt  int64  `json:"learned_at"`
}

// probeTemplateFile 模板落盘结构（独立于 game_memory.json，Q6）。
type probeTemplateFile struct {
	Version   string                    `json:"version"`
	Updated   string                    `json:"updated"`
	Templates map[string]*probeTemplate `json:"templates"` // dstIP → 模板
}

// SetProbeTemplatePath 注入模板落盘路径并加载既有模板（Q6）。
func (m *Manager) SetProbeTemplatePath(path string) {
	if path == "" {
		return
	}
	m.preheatMu.Lock()
	m.probeTplPath = path
	m.preheatMu.Unlock()
	m.loadProbeTemplates(path)
}

// LearnProbeTemplate 模板学习（需求 D1）：首次捕获某目标合法测速包时缓存
// payload（按目标 IP 存储），主动预热用原样 payload 构造探针（红线 4：
// 任何自定义字段都会破坏服务器原样回显）。重复捕获仅刷新时间，不覆盖。
func (m *Manager) LearnProbeTemplate(dstIP string, dport uint16, payload []byte) {
	if dstIP == "" || len(payload) == 0 || len(payload) >= preheatMaxPayload {
		return
	}
	m.MarkGameActive() // v2.4 漏洞三①：捕获 7770 测速包即入临战活跃态
	cp := append([]byte(nil), payload...)
	m.preheatMu.Lock()
	if m.probeTemplates == nil {
		m.probeTemplates = make(map[string]*probeTemplate)
	}
	_, existed := m.probeTemplates[dstIP]
	m.probeTemplates[dstIP] = &probeTemplate{PayloadHex: hex.EncodeToString(cp), DstPort: dport, LearnedAt: time.Now().UnixMilli()}
	path := m.probeTplPath
	m.preheatMu.Unlock()
	if !existed {
		log.Infoln("[GameLane] probe template learned dst=%s port=%d len=%d", dstIP, dport, len(cp))
	}
	m.saveProbeTemplates(path)
	// v2.4 漏洞一③（冷启动首轮，谷歌强制）：首个 7770 模板学习且
	// bestRaceWinner 从未产生、尚未跑过扇出时，延迟 3.2s（等捕获中的
	// 赛马释放 /24 占位）异步触发一次 PreheatRegionFanout——全新安装
	// 首秒即可把 HK 01~08 全测完，25ms 的 HK 02 当场夺冠。
	if m.bestRaceEmpty() && m.fanoutOnce.CompareAndSwap(false, true) {
		go func() {
			time.Sleep(3200 * time.Millisecond)
			m.PreheatRegionFanout(m.probeTemplateKeys())
		}()
	}
}

// PreheatRegionFanout 主战场全量上跑道（2026-10-18 v2.4 第二刀 2.2，谷歌
// 强制修正一）：HK 前 8 + TW 前 8 + SG/JP/KR 前 3 节点对 1~2 个亚洲近距
// 7770 模板目标并发真 UDP 测速——绕过 LaneChampions 单代表限制与 5s 节流
// 门卫，独立预算 32。回包只进 rttTable（Source="race"）/bestRaceWinner/
// 段锁，绝不写 TUN（红线 3）。返回实际起跑旁路数。
func (m *Manager) PreheatRegionFanout(keys []string) int {
	// v2.5 第二刀 2：无模板时不再早退——asianTemplateTargets 对空 keys 返回
	// 空 → 7770 跳过 → 直接走 STUN 保底探针（bestRaceWinner 永不空）。
	// v2.5：无亚洲靶时 targets 为空——7770 循环自然跳过，直接走 STUN 保底
	// （原 `len(targets)==0 → return 0` 早退会让 bestRaceWinner 永不产出）。
	targets := m.asianTemplateTargets(keys, 2)
	nodes := m.fanoutNodes(8, 8, 3)
	if len(nodes) == 0 {
		return 0
	}
	budget := int32(32)
	total := 0
	for _, ap := range targets {
		m.preheatMu.Lock()
		tpl := m.probeTemplates[ap.Addr().String()]
		m.preheatMu.Unlock()
		if tpl == nil {
			continue
		}
		payload, err := hex.DecodeString(tpl.PayloadHex)
		if err != nil || len(payload) == 0 {
			continue
		}
		dport := tpl.DstPort
		if dport == 0 {
			dport = ap.Port()
		}
		if isMatchServerPort(dport) {
			continue // 红线 2：对局服端口绝不主动发包
		}
		total += m.startRaceNodes(netip.AddrPortFrom(ap.Addr(), dport), nodes, payload, &budget)
	}
	// v2.5 第二刀 2 + 强制修正二：STUN UDP 保底探针——7770 无亚洲靶/全部
	// 超时（赛马在途 ≤3s，结束后复检 bestRaceWinner 仍空）时立即触发。
	// STUN 是全球 Anycast 就近响应：SG 01 连新加坡本地仅 22ms，跨区比大小
	// 会把它误选为全局最优、进香港对局时绕路——故 STUN 只允许 HK/TW 近距
	// 核心枢纽区节点竞争 bestRaceWinner（fanoutNodes(8,8,0)），五区跨区
	// 竞争仅限真实 7770 游戏测速赛马（谷歌强制修正二/铁律 F）。
	if m.bestRaceEmpty() {
		stunNodes := m.fanoutNodes(8, 8, 0)
		if len(stunNodes) > 0 {
			if total > 0 {
				go func() {
					time.Sleep(3200 * time.Millisecond)
					if m.bestRaceEmpty() {
						m.stunProbeFallback(stunNodes)
					}
				}()
			} else {
				total += m.stunProbeFallback(stunNodes)
			}
		}
	}
	if total > 0 {
		log.Infoln("[GameLane] preheat region-fanout started lanes=%d targets=%d nodes=%d", total, len(targets), len(nodes))
	}
	return total
}

// stunProbeServers STUN 服务器域名表（v2.5 第二刀 2 保底探针；域名经内核
// DNS 解析真 IP，解析失败/返回 Fake-IP 由 stunStaticTargets 兜底）。
var stunProbeServers = []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}

// stunStaticTargets 硬编码内置免 DNS 解析的保底 Anycast STUN 靶点（v2.5
// 强制修正一：SetAllProxies 后 +1s 触发时内核 DNS 可能未就绪，且 STUN
// 域名不在免 Fake-IP 名单时解析会返回 198.18.x.x——静态 Anycast IP 保证
// STUN 探针永不空转）。Google STUN / Cloudflare Anycast 公网 IP。
var stunStaticTargets = []netip.AddrPort{
	netip.MustParseAddrPort("74.125.250.129:19302"),
	netip.MustParseAddrPort("142.250.82.127:19302"),
	netip.MustParseAddrPort("104.16.123.96:3478"),
}

// stunBindingRequestHex 标准 20 字节 STUN Binding Request：
// 0001(Binding Request) 0000(长度) 2112a442(magic cookie) + 12 字节事务 ID。
var stunBindingRequestHex = "000100002112a442000102030405060708090a0b"

// stunProbeTargets STUN 靶点解析（v2.5 强制修正一）：域名形态经内核 DNS
// 解析——解析失败或返回 Fake-IP（198.18.0.0/15）时跳过，由硬编码静态
// Anycast 靶点兜底（静态靶点恒在、与域名靶点去重并入）。
func stunProbeTargets() []netip.AddrPort {
	seen := make(map[netip.AddrPort]bool)
	out := make([]netip.AddrPort, 0, len(stunProbeServers)+len(stunStaticTargets))
	for _, s := range stunProbeServers {
		host, portStr, err := net.SplitHostPort(s)
		if err != nil {
			continue
		}
		port, perr := strconv.Atoi(portStr)
		if perr != nil || port <= 0 || port > 65535 {
			continue
		}
		addr, aerr := netip.ParseAddr(host)
		if aerr != nil {
			// DefaultResolver 为 nil（内核 DNS 组件未就绪/单测环境）→ 跳过
			// 域名靶点，由静态 Anycast 靶点兜底（强制修正一同语义）。
			if resolver.DefaultResolver == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			resolved, rerr := resolver.ResolveIP(ctx, host)
			cancel()
			if rerr != nil || !resolved.IsValid() || resolver.IsFakeIP(resolved) {
				continue // Fake-IP/解析失败 → 静态 Anycast 靶点兜底（修正一）
			}
			addr = resolved
		}
		if !addr.IsValid() {
			continue
		}
		ap := netip.AddrPortFrom(addr.Unmap(), uint16(port))
		if !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	}
	for _, ap := range stunStaticTargets {
		if !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	}
	return out
}

// stunProbeFallback STUN 保底探针（v2.5 第二刀 2）：标准 20 字节 Binding
// Request 经各节点 UDP 通道发往 STUN 服务器，首回包 RTT 即该节点真实
// UDP 延迟——run() 复用既有入库（Source="race"）与 bestRaceWinner 更新
// （race.go:617 位于 writeBack!=nil 判断之前，writeBack==nil 照样生效，
// race.go 零改动维持）；不锁段不写 TUN（红线 3）。nodes 仅 HK/TW
// （强制修正二）。返回实际起跑旁路数。
func (m *Manager) stunProbeFallback(nodes []string) int {
	targets := stunProbeTargets()
	if len(targets) == 0 || len(nodes) == 0 {
		return 0
	}
	payload, err := hex.DecodeString(stunBindingRequestHex)
	if err != nil || len(payload) == 0 {
		return 0
	}
	budget := int32(32)
	total := 0
	for _, ap := range targets {
		total += m.startRaceNodes(ap, nodes, payload, &budget)
	}
	if total > 0 {
		log.Infoln("[GameLane] stun fallback probe started servers=%d nodes=%d lanes=%d", len(targets), len(nodes), total)
	}
	return total
}

// ---- v2.13 第一刀（1.1 / 1.2）：STUN 保底扇出周期化 + 过期软降级刷新 ----

const (
	// stunRefreshInterval STUN 保底扇出周期（5min）：保证 bestRaceWinner 全天
	// 候保有新鲜实测值。虚幻引擎类游戏（Fortnite）没有 7770 模板，race 源
	// 只能靠 STUN 保底产出——周期化后即使长时间不触发赛马，冠军也不会
	// 因 10min TTL 过期而掉进盲选分支。
	stunRefreshInterval = 5 * time.Minute
	// stunRefreshMinGap 异步刷新最小间隔：过期软降级路径由进场首包触发，
	// 高频新目标场景下用"最小间隔 + in-flight CAS"双重去重，绝不并发
	// 重复扇出抢预算。
	stunRefreshMinGap = 10 * time.Second
	// stunRefreshStartDelay 周期协程首轮延迟：避开 SetAllProxies 已排定的
	// 1s 启动扇出（同一时刻两轮 STUN 扇出会互相抢 32 路独立预算）。
	stunRefreshStartDelay = 90 * time.Second
)

// startSTUNRefreshLoop 启动 STUN 保底扇出的周期刷新协程（v2.13 第一刀 1.1）。
// 一次性启动（stunRefreshOnce），池就绪后调用；每 stunRefreshInterval 检查
// bestRaceWinner 是否陈旧，陈旧才重跑 stunProbeFallback——复用既有
// fanoutNodes(8,8,0) 与 32 路独立预算语义，不碰 TUN、不锁段（红线 3）。
func (m *Manager) startSTUNRefreshLoop() {
	if !m.stunRefreshOnce.CompareAndSwap(false, true) {
		return
	}
	go func() {
		time.Sleep(stunRefreshStartDelay)
		ticker := time.NewTicker(stunRefreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			if !m.bestRaceStale(stunRefreshInterval) {
				continue
			}
			m.triggerSTUNRefreshAsync("periodic")
		}
	}()
}

// bestRaceStale 全局最优是否陈旧（为空，或距上次更新已满 d）。
func (m *Manager) bestRaceStale(d time.Duration) bool {
	m.bestRaceMu.Lock()
	defer m.bestRaceMu.Unlock()
	if m.bestRace == nil {
		return true
	}
	return time.Since(time.UnixMilli(m.bestRace.At)) >= d
}

// triggerSTUNRefreshAsync 异步重跑一轮 STUN 保底扇出（v2.13 第一刀 1.2 的
// 刷新侧）：去重策略为最小间隔 stunRefreshMinGap + in-flight CAS，重复触发
// 只返回 false 不排队。任何失败只记诊断，绝不影响选路。
func (m *Manager) triggerSTUNRefreshAsync(reason string) bool {
	now := time.Now().UnixMilli()
	if last := m.stunRefreshLastAt.Load(); last != 0 && now-last < int64(stunRefreshMinGap/time.Millisecond) {
		return false
	}
	if !m.stunRefreshInFlight.CompareAndSwap(false, true) {
		return false
	}
	m.stunRefreshLastAt.Store(now)
	go func() {
		defer m.stunRefreshInFlight.Store(false)
		nodes := m.fanoutNodes(8, 8, 0)
		if len(nodes) == 0 {
			recordDiag("stun_refresh", "reason=%s nodes=0 skipped", reason)
			return
		}
		lanes := m.stunProbeFallback(nodes)
		recordDiag("stun_refresh", "reason=%s nodes=%d lanes=%d", reason, len(nodes), lanes)
		log.Infoln("[GameLane] stun refresh (%s): nodes=%d lanes=%d", reason, len(nodes), lanes)
	}()
	return true
}

// asianTemplateTargets 挑前 n 个亚洲近距模板目标：优先已锁死 HK/TW/SG 段、
// 可信亚太段（RegionTrustedFor）、GeoIP 亚太；绝不拿巴林/欧美模板测香港
// 节点（批复漏洞一②）。
func (m *Manager) asianTemplateTargets(keys []string, n int) []netip.AddrPort {
	type cand struct {
		ap  netip.AddrPort
		pri int
	}
	var cands []cand
	for _, k := range keys {
		addr, err := netip.ParseAddr(k)
		if err != nil || !addr.IsValid() {
			continue
		}
		// v2.5 第二刀 2.1：巴林死区（AWS me-south-1，15.184.0.0/15 覆盖
		// 15.184.x 与 15.185.x）严禁当测速模板——远且不通，19 路探针全
		// timeout 会让 race 源 rttTable/bestRaceWinner 全空（00:40 实测）。
		if bahrainDeadZone.Contains(addr) {
			continue
		}
		m.preheatMu.Lock()
		tpl := m.probeTemplates[k]
		m.preheatMu.Unlock()
		if tpl == nil || tpl.DstPort == 0 {
			continue
		}
		pri := 0
		if seg := segmentKey24(k); seg != "" {
			if ent := m.getSegmentLock(seg); ent != nil {
				switch ent.Region {
				case "HK", "TW", "SG":
					pri = 3
				case "JP", "KR":
					pri = 2
				}
			}
		}
		if pri == 0 && SegmentTable().RegionTrustedFor(addr) {
			pri = 2
		}
		if pri == 0 {
			if region := geoipCountryFor(addr); region == "HK" || region == "TW" || region == "SG" || region == "JP" || region == "KR" || region == "MO" {
				pri = 1
			}
		}
		if pri > 0 {
			cands = append(cands, cand{ap: netip.AddrPortFrom(addr, tpl.DstPort), pri: pri})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].pri > cands[j].pri })
	out := make([]netip.AddrPort, 0, n)
	for i, c := range cands {
		if i >= n {
			break
		}
		out = append(out, c.ap)
	}
	return out
}

// fanoutNodes 扇出节点列表：HK 前 hkN + TW 前 twN + SG/JP/KR 各前 n3
// （池序；v2.4 漏洞一①：HK 02 这类非代表节点必须上跑道）。
func (m *Manager) fanoutNodes(hkN, twN, n3 int) []string {
	m.mu.RLock()
	pool := append([]string(nil), m.allProxies...)
	m.mu.RUnlock()
	var out []string
	for _, spec := range []struct {
		region string
		n      int
	}{{"HK", hkN}, {"TW", twN}, {"SG", n3}, {"JP", n3}, {"KR", n3}} {
		members := FilterByRegion(pool, "", spec.region)
		for i, name := range members {
			if i >= spec.n {
				break
			}
			out = append(out, name)
		}
	}
	return out
}

// PreheatTarget 对已知目标做一轮五区主动探针（需求 D2）：节流 5s/1、
// 失败指数退避 1/2/4/8s 封顶、预算扣减（单轮总探针上限 20）。回包只进
// rttTable，绝不写 TUN（startRace 的 writeBack=nil 路径，红线 3）。
// 返回实际发出的旁路数（0=未发出）。
func (m *Manager) PreheatTarget(dst netip.AddrPort, budget *int32) int {
	if !dst.IsValid() || budget == nil {
		return 0
	}
	dstKey := dst.Addr().String()
	m.preheatMu.Lock()
	tpl, ok := m.probeTemplates[dstKey]
	if !ok || tpl == nil {
		m.preheatMu.Unlock()
		return 0 // 无模板不强造（需求 D5：模板捕获学习，非硬编码）
	}
	now := time.Now().UnixMilli()
	if now-m.preheatLastAt[dstKey] < preheatMinIntervalMs {
		m.preheatMu.Unlock()
		return 0
	}
	if fails := m.preheatFailN[dstKey]; fails > 0 {
		backoff := int64(1000 << minInt(fails-1, 3)) // 1/2/4/8s 封顶
		if now-m.preheatFailAt[dstKey] < backoff {
			m.preheatMu.Unlock()
			return 0
		}
	}
	payload, err := hex.DecodeString(tpl.PayloadHex)
	if err != nil || len(payload) == 0 {
		m.preheatMu.Unlock()
		return 0
	}
	dport := tpl.DstPort
	if dport == 0 {
		dport = dst.Port()
	}
	if isMatchServerPort(dport) {
		m.preheatMu.Unlock()
		return 0 // 红线 2：对局服端口绝不主动发包
	}
	m.preheatLastAt[dstKey] = now
	m.preheatMu.Unlock()

	lanes := m.startProbeRace(dst, payload, budget)
	if lanes == 0 {
		// 全部旁路拨号失败：计入失败退避
		m.preheatMu.Lock()
		m.preheatFailAt[dstKey] = time.Now().UnixMilli()
		m.preheatFailN[dstKey]++
		m.preheatMu.Unlock()
	}
	return lanes
}

// startProbeRace 预热探针入口：占位 CAS + 无写回赛马（回包死在内核）。
func (m *Manager) startProbeRace(dst netip.AddrPort, payload []byte, budget *int32) int {
	if !m.tryBeginRace(segmentKey24(dst.Addr().String())) {
		return 0
	}
	return m.startRace(dst, "", payload, nil, budget)
}

// probeTemplateKeys 当前已学习模板的目标键（触发时刻快照）。
func (m *Manager) probeTemplateKeys() []string {
	m.preheatMu.Lock()
	keys := make([]string, 0, len(m.probeTemplates))
	for k := range m.probeTemplates {
		keys = append(keys, k)
	}
	m.preheatMu.Unlock()
	return keys
}

// PreheatKnownTargets 候选池刷新时的批量预热（需求 D3）：对传入的已学习
// 模板目标逐一发起主动探针，单轮总探针（旁路）上限 preheatMaxPerRound。
// keys 由调用方在触发时刻快照（SetAllProxies），避免与后续模板学习竞争。
func (m *Manager) PreheatKnownTargets(keys []string) {
	if len(keys) == 0 {
		return
	}
	budget := int32(preheatMaxPerRound)
	started := 0
	for _, k := range keys {
		if atomic.LoadInt32(&budget) <= 0 {
			break
		}
		addr, err := netip.ParseAddr(k)
		if err != nil {
			continue
		}
		m.preheatMu.Lock()
		port := m.probeTemplates[k].DstPort
		m.preheatMu.Unlock()
		if port == 0 {
			continue
		}
		started += m.PreheatTarget(netip.AddrPortFrom(addr.Unmap(), port), &budget)
	}
	if started > 0 {
		log.Infoln("[GameLane] preheat round done: probes=%d (budget=%d)", started, atomic.LoadInt32(&budget))
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// loadProbeTemplates 启动加载模板（文件缺失/损坏以空表启动，不影响链路）。
func (m *Manager) loadProbeTemplates(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var pf probeTemplateFile
	if err := json.Unmarshal(data, &pf); err != nil {
		log.Warnln("[GameLane] probe templates load failed: %v", err)
		return
	}
	m.preheatMu.Lock()
	if m.probeTemplates == nil {
		m.probeTemplates = make(map[string]*probeTemplate)
	}
	for k, v := range pf.Templates {
		if v != nil && v.PayloadHex != "" {
			m.probeTemplates[k] = v
		}
	}
	n := len(pf.Templates)
	m.preheatMu.Unlock()
	log.Infoln("[GameLane] probe templates loaded %d from %s", n, path)
}

// saveProbeTemplates 模板落盘（Q6：runtime/game_probe_templates.json）。
func (m *Manager) saveProbeTemplates(path string) {
	if path == "" {
		return
	}
	m.preheatMu.Lock()
	pf := probeTemplateFile{Version: "1", Updated: time.Now().UTC().Format(time.RFC3339), Templates: m.probeTemplates}
	m.preheatMu.Unlock()
	if pf.Templates == nil {
		return
	}
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Warnln("[GameLane] probe templates save failed: %v", err)
	}
}
