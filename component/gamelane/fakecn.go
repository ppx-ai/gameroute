package gamelane

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

// fakeCN 反悔接管机制（v2.12 清单5，2026-10-22）。
//
// 背景：大陆路由表（china_ip.go）判定"国内目标 → 直连"是**宁可直连**的
// 保守方向，但它一定存在两类漏判：
//  1. 假大陆 IP：CDN/Anycast/回国中转或表数据陈旧，IP 落在大陆段里但服务
//     实际在海外，直连根本到不了；
//  2. 劣化链路：能到但直连 RTT/丢包明显劣于走加速。
//
// 若只有"直连"没有反悔，这两类对局会直接死锁在"不接管"状态且无法自愈。
// 因此对**已确认为游戏进程**的直连目标开观察窗，满足任一条即反悔接管：
//   - 零回包：观察窗 ≥3s 且出站包 ≥5，全程零回包（≥2s 静默判据内嵌）；
//   - 高延迟：实测直连最小 RTT > 70ms，样本 ≥3 —— 最小 RTT 已排除排队
//     抖动干扰，属链路本身劣化；
//
// 且两种情况都要求"多端口"（≥2 个目的端口）或包量足够大，避免把单个
// 探测包/心跳当成一局游戏。
//
// 反悔结果写入 runtime/fakecn_override.json（持久，跨重启有效）：下次同 IP
// 直接按海外服接管，不再重走"直连 → 观察 → 反悔"的损失过程。原始直连
// 判定语义不变，本机制只做**收紧后的补充接管**，误伤面为 0（接管对象本身
// 就是游戏进程流量）。
const (
	fakeCNWindowMs           = 3000 // 观察窗最短时长（覆盖 2s 静默判据）
	fakeCNMaxDirectRTTMs     = 70   // 直连最小 RTT 上限，超过即链路劣化
	fakeCNMinRTTSamples      = 3    // RTT 样本下限，防单次抖动误判
	fakeCNMinPackets         = 5    // 零回包判据的出站包下限
	fakeCNMinPacketsOnePort  = 20   // 单端口场景的出站包下限（多端口只要求 5）
	fakeCNWatchMaxEntries    = 512  // 观察表上限，内存有界
	fakeCNWatchMaxIdleMs     = int64(30000)
	fakeCNDefaultOverrideRel = "fakecn_override.json"
)

// fakeCNWatchState 单个 IP 的反悔接管观察窗状态。
type fakeCNWatchState struct {
	IP        string          `json:"ip"`
	Proc      string          `json:"proc,omitempty"`
	Ports     map[uint16]bool `json:"-"`
	FirstAt   int64           `json:"first_at"`
	LastOutAt int64           `json:"last_out_at"`
	LastInAt  int64           `json:"last_in_at"`
	Packets   int64           `json:"packets"`
	Replies   int64           `json:"replies"`
	RTTMin    int64           `json:"rtt_min"`
	RTTSample int             `json:"rtt_samples"`
	Done      bool            `json:"-"`
}

// fakeCNOverrideEntry 持久化的"假大陆 IP 已反悔接管"记录。
type fakeCNOverrideEntry struct {
	IP      string `json:"ip"`
	Proc    string `json:"proc,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Reason  string `json:"reason"`  // no_reply / high_rtt
	RTTMs   int64  `json:"rtt_ms"`  // 反悔时的直连最小 RTT（0=零回包）
	Packets int64  `json:"packets"` // 反悔时累计出站包
	At      int64  `json:"at"`      // 反悔时间 UnixMilli
}

type fakeCNOverrideFile struct {
	Version string                         `json:"version"`
	Updated string                         `json:"updated"`
	Note    string                         `json:"note"`
	Entries map[string]fakeCNOverrideEntry `json:"entries"`
}

var fakeCNOverrideStore struct {
	sync.RWMutex
	path    string
	entries map[string]fakeCNOverrideEntry
	loaded  bool
}

// fakeCNAutoOverrideEnabled 单测/演练开关：关闭后仅观察不写持久记录。
// 生产恒为 true；测试用它隔离全局状态。
var fakeCNAutoOverrideEnabled = true

// fakeCNNow 时间源（测试可替换，避免真实 sleep）。
var fakeCNNow = func() int64 { return time.Now().UnixMilli() }

// fakeCNWatchActive 观察窗计数：非 0 时热路径才需加锁查表，
// 常态（无国内直连待验证目标）为零开销短路。
var fakeCNWatchActive atomic.Int32

// noteDomesticDirect 目标若因大陆路由表被判直连（且无 override 记忆），
// 为已确认为游戏进程的流量登记反悔观察窗。非国内目标为 no-op。
//
// 红线（第 6 条）：假 CN 反悔只服务游戏——aux 进程（浏览器 / IM / 下载器）
// 与未知进程一律不进观察窗，绝不为非游戏流量开加速。
func (m *Manager) noteDomesticDirect(ip string, port uint16, proc string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	addr = addr.Unmap()
	if !addr.Is4() || !isChinaMainlandIP(addr) {
		return
	}
	if SegmentTable().MatchIP(addr) {
		return
	}
	if !isConfirmedGameProcessForFakeCN(proc) {
		return
	}
	m.startFakeCNWatch(ip, proc, port)
}

// isConfirmedGameProcessForFakeCN 判定观察窗候选进程是否"已确认游戏进程"。
// 与注册链路同一把尺子：完整路径走 isGameProcess（aux → 关键词 → 目录特征 →
// 引擎 DLL 嗅探）；只有裸进程名时退化为纯内存关键词判定
// （isGameProcessNameQuiet，不写任何计数器，避免污染 proc_keyword_hit）。
func isConfirmedGameProcessForFakeCN(proc string) bool {
	p := strings.TrimSpace(proc)
	if p == "" {
		return false
	}
	if strings.ContainsAny(p, `\/`) {
		if ok, _ := isGameProcess(p); ok {
			return true
		}
	}
	return isGameProcessNameQuiet(processBaseName(strings.ToLower(p)))
}

// fakeCNOverridePath 反悔记录文件路径：与 game_memory.json 同目录
// （部署形态一致：runtime/），记忆路径未知时退回 HomeDir 默认。
func (m *Manager) fakeCNOverridePath() string {
	if m.memPath != "" {
		return filepath.Join(filepath.Dir(m.memPath), fakeCNDefaultOverrideRel)
	}
	return ""
}

// loadFakeCNOverride 从磁盘加载反悔记录（幂等；同路径只加载一次）。
func (m *Manager) loadFakeCNOverride() {
	path := m.fakeCNOverridePath()
	if path == "" {
		return
	}
	fakeCNOverrideStore.Lock()
	defer fakeCNOverrideStore.Unlock()
	if fakeCNOverrideStore.loaded && fakeCNOverrideStore.path == path {
		return
	}
	fakeCNOverrideStore.path = path
	fakeCNOverrideStore.entries = make(map[string]fakeCNOverrideEntry)
	fakeCNOverrideStore.loaded = true
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var f fakeCNOverrideFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Warnln("[GameLane] fakecn override parse failed: %v", err)
		return
	}
	for k, v := range f.Entries {
		if k == "" || v.IP == "" {
			continue
		}
		fakeCNOverrideStore.entries[k] = v
	}
	if n := len(fakeCNOverrideStore.entries); n > 0 {
		log.Infoln("[GameLane] fakecn override loaded: %d entries", n)
	}
}

// hasFakeCNOverride 该 IP 是否已有"假大陆 IP 已反悔接管"记录。
// 供注册路径与命中路径共用，判定为纯内存查表（常量级，热路径安全）。
func (m *Manager) hasFakeCNOverride(ip string) bool {
	if ip == "" {
		return false
	}
	m.loadFakeCNOverride()
	fakeCNOverrideStore.RLock()
	_, ok := fakeCNOverrideStore.entries[ip]
	fakeCNOverrideStore.RUnlock()
	return ok
}

// rememberFakeCNOverride 写入并落盘反悔记录（同一 IP 只写一次）。
func (m *Manager) rememberFakeCNOverride(ip, proc string, port uint16, reason string, rttMs, packets int64) {
	if !fakeCNAutoOverrideEnabled || ip == "" {
		return
	}
	m.loadFakeCNOverride()
	fakeCNOverrideStore.Lock()
	if fakeCNOverrideStore.entries == nil {
		fakeCNOverrideStore.entries = make(map[string]fakeCNOverrideEntry)
	}
	if _, exists := fakeCNOverrideStore.entries[ip]; exists {
		fakeCNOverrideStore.Unlock()
		return
	}
	fakeCNOverrideStore.entries[ip] = fakeCNOverrideEntry{
		IP: ip, Proc: proc, Port: port, Reason: reason,
		RTTMs: rttMs, Packets: packets, At: fakeCNNow(),
	}
	snapshot := make(map[string]fakeCNOverrideEntry, len(fakeCNOverrideStore.entries))
	for k, v := range fakeCNOverrideStore.entries {
		snapshot[k] = v
	}
	path := fakeCNOverrideStore.path
	fakeCNOverrideStore.Unlock()
	writeFakeCNOverrideFile(path, snapshot)
}

// writeFakeCNOverrideFile 原子写盘（tmp + rename），失败仅告警不影响加速。
func writeFakeCNOverrideFile(path string, entries map[string]fakeCNOverrideEntry) {
	if path == "" {
		return
	}
	f := fakeCNOverrideFile{
		Version: "1",
		Updated: time.Now().Format(time.RFC3339),
		Note:    "GameLane fakeCN auto-override: china route IP that failed direct connect / high RTT, taken over as overseas",
		Entries: entries,
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Warnln("[GameLane] fakecn override mkdir failed: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Warnln("[GameLane] fakecn override write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Warnln("[GameLane] fakecn override rename failed: %v", err)
		_ = os.Remove(tmp)
		return
	}
	log.Infoln("[GameLane] fakecn override saved: entries=%d", len(entries))
}

// FakeCNOverrideSnapshot 返回全部反悔记录（诊断/面板展示用，按时间倒序）。
func FakeCNOverrideSnapshot() []fakeCNOverrideEntry {
	fakeCNOverrideStore.RLock()
	out := make([]fakeCNOverrideEntry, 0, len(fakeCNOverrideStore.entries))
	for _, v := range fakeCNOverrideStore.entries {
		out = append(out, v)
	}
	fakeCNOverrideStore.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out
}

// ClearFakeCNOverride 清空指定 IP（ip=="" 时清空全部）的反悔记录并落盘。
// 供面板"这条直连其实没问题"的人工纠正入口；返回清除条数。
func ClearFakeCNOverride(ip string) int {
	fakeCNOverrideStore.Lock()
	defer fakeCNOverrideStore.Unlock()
	if !fakeCNOverrideStore.loaded {
		return 0
	}
	if ip == "" {
		n := len(fakeCNOverrideStore.entries)
		fakeCNOverrideStore.entries = make(map[string]fakeCNOverrideEntry)
		writeFakeCNOverrideFile(fakeCNOverrideStore.path, fakeCNOverrideStore.entries)
		return n
	}
	if _, ok := fakeCNOverrideStore.entries[ip]; !ok {
		return 0
	}
	delete(fakeCNOverrideStore.entries, ip)
	snapshot := make(map[string]fakeCNOverrideEntry, len(fakeCNOverrideStore.entries))
	for k, v := range fakeCNOverrideStore.entries {
		snapshot[k] = v
	}
	writeFakeCNOverrideFile(fakeCNOverrideStore.path, snapshot)
	return 1
}

// startFakeCNWatch 登记一个反悔观察窗（幂等：已有未完成窗口则复用并补全进程名）。
// 只在"目标已判为国内直连 + 已确认为游戏进程"时调用。
func (m *Manager) startFakeCNWatch(ip, proc string, port uint16) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return
	}
	if m.hasFakeCNOverride(ip) {
		return // 已反悔接管过，无需再观察
	}
	now := fakeCNNow()
	m.fakeCNMu.Lock()
	defer m.fakeCNMu.Unlock()
	if m.fakeCNWatch == nil {
		m.fakeCNWatch = make(map[string]*fakeCNWatchState, 32)
	}
	if st, ok := m.fakeCNWatch[ip]; ok {
		if proc != "" && st.Proc == "" {
			st.Proc = proc
		}
		if port != 0 && st.Ports != nil {
			st.Ports[port] = true
		}
		return
	}
	// 懒清理：超限时先删已完成/超时空闲条目，仍超限则淘汰最老条目。
	if len(m.fakeCNWatch) >= fakeCNWatchMaxEntries {
		for k, s := range m.fakeCNWatch {
			if s.Done || now-s.LastOutAt > fakeCNWatchMaxIdleMs {
				delete(m.fakeCNWatch, k)
				fakeCNWatchActive.Add(-1)
			}
		}
		for len(m.fakeCNWatch) >= fakeCNWatchMaxEntries {
			var oldKey string
			var oldTS int64 = 1<<63 - 1
			for k, s := range m.fakeCNWatch {
				if s.FirstAt < oldTS {
					oldTS = s.FirstAt
					oldKey = k
				}
			}
			delete(m.fakeCNWatch, oldKey)
			fakeCNWatchActive.Add(-1)
		}
	}
	ports := make(map[uint16]bool, 2)
	if port != 0 {
		ports[port] = true
	}
	m.fakeCNWatch[ip] = &fakeCNWatchState{IP: ip, Proc: proc, Ports: ports, FirstAt: now, LastOutAt: now}
	fakeCNWatchActive.Add(1)
	recordDiag("fakecn_observe", "start watch ip=%s proc=%s port=%d", ip, proc, port)
}

// fakeCNAccountOutbound 出站包记账（热路径，仅观察窗内 IP 命中，一次 map 查找）。
// 达判据时反悔接管并返回 true（调用方应重评估会话）。调用方须已确认该 IP
// 的目标属游戏流量语义（flow 观察窗/进程目标），此处不再做进程白名单判定。
func (m *Manager) fakeCNAccountOutbound(ip string, port uint16) bool {
	if ip == "" || fakeCNWatchActive.Load() == 0 {
		return false
	}
	m.fakeCNMu.Lock()
	st, ok := m.fakeCNWatch[ip]
	if !ok || st.Done {
		m.fakeCNMu.Unlock()
		return false
	}
	now := fakeCNNow()
	st.LastOutAt = now
	st.Packets++
	if st.Ports == nil {
		st.Ports = make(map[uint16]bool, 2)
	}
	if port != 0 {
		st.Ports[port] = true
	}
	elapsed := now - st.FirstAt
	multiPort := len(st.Ports) >= 2
	minPkts := int64(fakeCNMinPacketsOnePort)
	if multiPort {
		minPkts = fakeCNMinPackets
	}
	reason := ""
	rttMs := int64(0)
	switch {
	case st.Replies == 0 && elapsed >= fakeCNWindowMs && st.Packets >= minPkts:
		reason = "no_reply"
	case st.RTTSample >= fakeCNMinRTTSamples && st.RTTMin > fakeCNMaxDirectRTTMs && multiPort:
		reason = "high_rtt"
		rttMs = st.RTTMin
	}
	if reason == "" {
		m.fakeCNMu.Unlock()
		return false
	}
	st.Done = true
	if n := fakeCNWatchActive.Load(); n > 0 {
		fakeCNWatchActive.Add(-1)
	}
	proc := st.Proc
	packets := st.Packets
	victim := st.IP
	m.fakeCNMu.Unlock()

	// 反悔接管：forceOverseas=true 跳过大陆直连判定，直接注册为游戏目标。
	if !m.registerTargetIPTrusted(victim, true, true) {
		// 已注册/被黑名单拒绝：仍要落盘 override，避免重启后又回落到直连。
		recordDiag("fakecn_override", "re-takeover skipped (register refused) ip=%s reason=%s", victim, reason)
		m.rememberFakeCNOverride(victim, proc, port, reason, rttMs, packets)
		return false
	}
	m.remember(victim, port)
	if proc != "" {
		m.rememberProcessName(victim, proc)
	}
	m.rememberFakeCNOverrideMark(victim, reason) // 记忆条目审计标记（fakecn_override）
	m.rememberFakeCNOverride(victim, proc, port, reason, rttMs, packets)
	log.Infoln("[GameLane] fakecn re-takeover %s (proc=%s reason=%s rtt=%dms pkts=%d)",
		victim, proc, reason, rttMs, packets)
	recordDiag("fakecn_override", "re-takeover ip=%s proc=%s reason=%s rtt=%dms pkts=%d",
		victim, proc, reason, rttMs, packets)
	m.MarkGameActive()
	return true
}

// fakeCNAccountReply 入站回复记账：记录最小 RTT 与回包存在性。
// 仅观察窗内 IP 生效；与出站记账共用 fakeCNMu。
func (m *Manager) fakeCNAccountReply(ip string) {
	if ip == "" || fakeCNWatchActive.Load() == 0 {
		return
	}
	m.fakeCNMu.Lock()
	defer m.fakeCNMu.Unlock()
	st, ok := m.fakeCNWatch[ip]
	if !ok || st.Done {
		return
	}
	now := fakeCNNow()
	rtt := now - st.LastOutAt
	st.LastInAt = now
	st.Replies++
	if rtt > 0 && rtt <= 5000 {
		if st.RTTSample == 0 || rtt < st.RTTMin {
			st.RTTMin = rtt
		}
		st.RTTSample++
	}
}

// fakeCNWatchSnapshot 观察窗快照（诊断用，按首包时间倒序）。
func (m *Manager) fakeCNWatchSnapshot() []fakeCNWatchState {
	m.fakeCNMu.Lock()
	defer m.fakeCNMu.Unlock()
	out := make([]fakeCNWatchState, 0, len(m.fakeCNWatch))
	for _, st := range m.fakeCNWatch {
		cp := *st
		cp.Ports = nil
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstAt > out[j].FirstAt })
	return out
}
