package gamelane

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// 自学习记忆模块：服务"未知游戏"的持久化记忆。
// 目标一经确认注册（进程反查 / 流特征注册）即写入记忆文件，重启后
// 首个数据包命中记忆则直接注册，跳过观察期，实现"第二次秒识别"。
//
// 记忆 Key 格式：
//   - 普通 IP：  "3.66.92.28/32"
//   - 端口段：   "3.66.92.28:1024-1124"（目的端口落入已知游戏端口段时）
//
// 状态机：active（可秒识别）→ 24h 未命中降权 decay（不参与识别）→
// 72h 未命中淘汰 evicted（删除）。超 500 条时优先淘汰最旧 decay 条目。

// 记忆常量
const (
	memVersion           = "1"
	memDefaultPath       = "game_memory.json"      // 相对 HomeDir（面板以 -d runtime 启动）
	memEntryLimit        = 500                     // 超限淘汰最旧 decay
	memActiveTTLMs       = int64(24 * 3600 * 1000) // active 24h 未命中 → decay
	memDecayTTLMs        = int64(72 * 3600 * 1000) // decay 72h 未命中 → 删除
	memFlushDebounceMs   = 500 * time.Millisecond  // 去抖落盘窗口
	memFlushConfirmN     = 3                       // 连续确认 3 次立即落盘
	memForceFlushAfterMs = int64(2 * 1000)         // 单次变更兜底强制落盘（2s）
	memFlowHitsUpgradeN  = 3                       // B 类连续 3 次不同会话 → 升级 A 类
	memFlowSessionMs     = int64(5 * 60 * 1000)    // 判定不同会话的最小间隔（5 分钟）
)

// gamePortRanges 已知游戏端口段（与 flow.go isKnownGamePort 同步维护）：
// 命中这些端口段的目标，记忆 Key 使用 "ip:lo-hi" 端口段形式，重启后
// 端口落回段内任意值均可命中（APEX/PUBG 客户端端口在段内随机变化）。
var gamePortRanges = [][2]uint16{
	{1024, 1124},   // APEX
	{9960, 9969},   // APEX 备用
	{37000, 37015}, // APEX 备用
	{27000, 27200}, // PUBG / Steam 游戏
	// ---- v2.9 P2（2026-10-19 批复）：非亚太引擎系对局/大厅端口 ----
	// 顺序有意为之：窄段在前、26503-36503 宽段垫底，保证 memoryKeyFor 遍历时
	// 27000-27200 / 37000-37015 仍优先命中旧 Key（老记忆不漂移）。
	{3724, 3724},   // 暴雪 Battle.net 对局（WoW/D2R/SC2）
	{6113, 6113},   // 育碧/Uplay 对局
	{3074, 3074},   // COD / Xbox Live 对局（Xbox 端口复用）
	{5000, 5500},   // Valorant 对局（仅入本表，不入 isKnownGamePort——批复裁决 3）
	{26503, 36503}, // OW2/COD 宽动态对局段（与 27000-27200 重叠无冲突）
}

// GameMemory 单条自学习记忆。
type GameMemory struct {
	Key               string `json:"key"`                             // "ip/32" 或 "ip:lo-hi"
	Hits              int64  `json:"hits"`                            // 累计命中次数
	LastHitAt         int64  `json:"last_hit_at"`                     // 最后命中时间 UnixMilli
	Status            string `json:"status"`                          // active / decay / evicted
	ProcessName       string `json:"process_name,omitempty"`          // 进程反查确认的进程名（零名单）
	PreferredProxy    string `json:"preferred_proxy,omitempty"`       // 该 IP 上次实际使用的出口（重启后最高优先复用）
	RegionActual      string `json:"region_actual,omitempty"`         // 实际表现最佳的服务器区（如 "SG"/"HK"），记忆优先时直接取该区
	Source            string `json:"source"`                          // "process"（进程背书 A 类，高信任）/ "flow"（流量背书 B 类，低信任）
	FlowHits          int64  `json:"flow_hits,omitempty"`             // B 类会话计数，连续 3 次不同会话被确认 → 升级 A 类
	LastFlowHitsIncAt int64  `json:"last_flow_hits_inc_at,omitempty"` // B 类 FlowHits 最后递增时间 UnixMilli
	TimeBucket        string `json:"time_bucket,omitempty"`           // 时段维度：day(08-18) / night(18-24) / late(00-08)

	// ---- 网段级记忆（Shadow Forking 改造 2026-10-17 需求 E4/Q10）----
	// Key 为 "a.b.c.0/24"（/16 兜底）形式；普通被动路径 ≥2 个不同 IP 样本
	// 才可信，赛马胜者 SegmentSource="race" 单样本即写。
	SegmentLevel   string   `json:"segment_level,omitempty"`   // "/24" / "/16"（空=单 IP 条目）
	SegmentSamples int      `json:"segment_samples,omitempty"` // 已确认的不同 IP 样本数
	SegmentIPs     []string `json:"segment_ips,omitempty"`     // 已确认 IP 列表
	SegmentSource  string   `json:"segment_source,omitempty"`  // "race"（赛马实测）/ "passive"（被动累计）

	// FakeCNOverride 反悔接管审计标记（v2.12 清单5，2026-10-22）：
	// 该 IP 曾被大陆路由表误判为国内直连，后经"出站有包 + 入站零回包（或
	// RTT>70ms）"验尸判定为假 CN 并接管注册。置 true 即来源标记
	// "fakecn_override"，可审计；ClearFakeCNOverride(ip) 或手工删除
	// runtime/fakecn_override.json 后可恢复直连。
	FakeCNOverride   bool   `json:"fakecn_override,omitempty"`
	FakeCNOverrideAt int64  `json:"fakecn_override_at,omitempty"` // 接管时刻 UnixMilli
	FakeCNReason     string `json:"fakecn_reason,omitempty"`      // "no_reply" / "high_rtt"
}

// MemoryFile 记忆文件结构（runtime/game_memory.json）。
type MemoryFile struct {
	Version string                `json:"version"`
	Updated string                `json:"updated"` // RFC3339
	Entries map[string]GameMemory `json:"entries"`
}

// memoryKeyFor 计算记忆 Key：port==0 或目的端口不在已知游戏端口段内时
// 用普通 IP key；落入段内时用端口段 key。
func memoryKeyFor(ip string, port uint16) string {
	if port == 0 {
		return ip + "/32"
	}
	for _, r := range gamePortRanges {
		if port >= r[0] && port <= r[1] {
			return fmt.Sprintf("%s:%d-%d", ip, r[0], r[1])
		}
	}
	return ip + "/32"
}

// segmentKey24/segmentKey16 计算网段级记忆 Key（需求 E4，2026-10-17）：
// /24 起步（≥2 个不同 IP 样本确认），/16 兜底（仅当 /24 无样本）。
// 非 IPv4 返回 ""（网段级记忆仅覆盖 IPv4 游戏目标）。
func segmentKey24(ip string) string {
	return segmentPrefixKey(ip, 24)
}

func segmentKey16(ip string) string {
	return segmentPrefixKey(ip, 16)
}

func segmentPrefixKey(ip string, bits int) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return ""
	}
	return netip.PrefixFrom(addr, bits).Masked().String()
}

// memorySnap 保存"上一次加载/落盘后的记忆表"（v2.10.2）。
//
// 背景：配置重载（parseGameLane）会新建 Manager 并再次 LoadMemory，若仍从
// 文件重新解析，就要把全表重新遍历、进程条目重跑一次污染校验——既浪费一次
// 全表扫描，也会让"校验过的条数"混进运行期计数器。这里用包级快照继承上一
// 实例的内存表：既跳过重复解析，又保留尚未落盘的新学习条目（内存表不比文件旧）。
//
// 锁序：memMu → memorySnap.mu（写快照）；takeMemorySnapshot 不持有 memMu，
// 不存在反向嵌套。
var memorySnap struct {
	sync.Mutex
	path    string
	entries map[string]*GameMemory
}

func cloneMemoryEntry(src *GameMemory) *GameMemory {
	if src == nil {
		return nil
	}
	cp := *src // 结构体拷贝（SegmentIPs 另做深拷贝）
	if src.SegmentIPs != nil {
		cp.SegmentIPs = append([]string(nil), src.SegmentIPs...)
	}
	return &cp
}

// storeMemorySnapshot 用当前记忆表覆盖快照（调用方通常持 memMu）。
func storeMemorySnapshot(path string, src map[string]*GameMemory) {
	cp := make(map[string]*GameMemory, len(src))
	for k, v := range src {
		cp[k] = cloneMemoryEntry(v)
	}
	memorySnap.Lock()
	memorySnap.path = path
	memorySnap.entries = cp
	memorySnap.Unlock()
}

// takeMemorySnapshot 取出同路径快照的深拷贝；无快照或路径不符返回 false。
func takeMemorySnapshot(path string) (map[string]*GameMemory, bool) {
	memorySnap.Lock()
	defer memorySnap.Unlock()
	if memorySnap.path != path || memorySnap.entries == nil {
		return nil, false
	}
	cp := make(map[string]*GameMemory, len(memorySnap.entries))
	for k, v := range memorySnap.entries {
		cp[k] = cloneMemoryEntry(v)
	}
	return cp, true
}

// LoadMemory 启动加载记忆文件（零名单自学习：文件缺失/解析失败时以空表
// 启动，不影响正常链路）。调用方：parseGameLane 创建 Manager 后调用。
//
// v2.10.2 幂等：同一实例只加载一次；配置重载（新 Manager 实例）优先继承
// 运行期快照，不再重复读盘/解析/污染校验。
func (m *Manager) LoadMemory(path string) {
	if path == "" {
		path = memDefaultPath
	}
	// 幂等一：同实例重复调用直接跳过。
	m.memMu.Lock()
	if m.memLoaded {
		m.memMu.Unlock()
		metricsMemoryReloadSkipped.Add(1)
		log.Infoln("[GameRoute] memory already loaded, skip: %s", path)
		return
	}
	m.memMu.Unlock()

	// 假大陆 IP 反悔接管记录（fakecn_override.json，同目录）随记忆一起加载：
	// 让重启后首个包就走"已反悔 → 直接接管"路径，不重复损失直连观察窗。
	m.loadFakeCNOverride()

	// 幂等二：配置重载是新 Manager 实例，继承上一实例的内存表。
	if snap, ok := takeMemorySnapshot(path); ok {
		m.memMu.Lock()
		m.memPath = path
		m.memories = snap
		m.memLoaded = true
		m.memMu.Unlock()
		metricsMemoryReloadSkipped.Add(1)
		log.Infoln("[GameRoute] memory inherited %d entries from runtime snapshot: %s", len(snap), path)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Infoln("[GameRoute] memory load skip: %v", err)
		m.memMu.Lock()
		m.memPath = path
		m.memLoaded = true // 空表也是有效状态，避免重载时反复重试读盘
		if m.memories == nil {
			m.memories = make(map[string]*GameMemory)
		}
		storeMemorySnapshot(path, m.memories)
		m.memMu.Unlock()
		return
	}
	var mf MemoryFile
	if err := json.Unmarshal(data, &mf); err != nil {
		log.Warnln("[GameRoute] memory load parse failed: %v", err)
		m.memMu.Lock()
		m.memPath = path
		m.memLoaded = true
		m.memMu.Unlock()
		return
	}
	now := time.Now().UnixMilli()
	m.memMu.Lock()
	m.memPath = path
	loaded := 0
	for k, mem := range mf.Entries {
		// 过期条目不载入：active 超过 24h 未命中 → decay；decay 超过
		// 72h 未命中 → 直接丢弃（等价于已在维护期被淘汰）。
		switch mem.Status {
		case "active":
			if now-mem.LastHitAt >= memActiveTTLMs {
				mem.Status = "decay"
			}
		case "decay":
			if now-mem.LastHitAt >= memDecayTTLMs {
				continue
			}
		default:
			continue // 未知状态（含 evicted）一律不载入
		}
		// 进程门禁记忆清理：source=process 且进程名不在游戏进程名单的
		// 条目是历史污染（msedge/QQMusic 等非游戏进程流量误注册），
		// 启动加载时直接剔除，不再参与秒识别（A 类记忆 24h 污染的根除）。
		//
		// v2.10.2：这里用纯判定内核 + 独立计数器。原实现调 isGameProcessName
		// 会把"校验了几条历史记忆"计进 proc_keyword_hit（实测 93 条 × 两次
		// 加载 = 186 的假信号），使该指标丧失"运行期检测到几次游戏进程"语义。
		if mem.Source == "process" && mem.ProcessName != "" {
			metricsMemoryProcValidated.Add(1)
			// 2026-10-21 无词表通用识别：改用 isGameProcess（aux 排除 →
			// 关键词/目录特征 → 引擎 DLL 嗅探），与注册链路判定一致。
			// 否则无词条的第三方游戏（父目录/Tools 下带引擎 DLL）在重启加载
			// 时会被当作污染条目剔除，丢失第二次秒识别能力。
			// isGameProcess 不写任何计数器（proc_keyword_hit 语义不变）。
			if ok, _ := isGameProcess(mem.ProcessName); !ok {
				log.Warnln("[GameRoute] memory purge polluted entry %s (proc=%s)", k, mem.ProcessName)
				continue
			}
		}
		// 排除层过滤：记忆条目命中排除段（Discord/Steam/TUN/私网/组播/
		// 保留段等）一律剔除，与 RegisterTargetIP 注册前检查一致，
		// 避免重启后恢复被排除段目标（如 8125 遥测端口误注册的段内条目）。
		ipPart := k
		if i := strings.IndexAny(ipPart, "/:"); i > 0 {
			ipPart = ipPart[:i]
		}
		if addr, err := netip.ParseAddr(ipPart); err == nil && isExcludedIP(addr) {
			log.Warnln("[GameRoute] memory purge excluded entry %s", k)
			continue
		}
		entry := mem // range 变量拷贝，避免指针共享
		// 2026-10-17（需求 E3/Q5）：原"污染 region_actual 清洗"逻辑删除——
		// 五区锁死后 RegionActual 写入侧已限定 HK/TW/SG/JP/KR，且启动清洗
		// （reconcileMemoryForLanePool，死六二）统一处理旧数据残留。
		m.memories[k] = &entry
		loaded++
	}
	m.memLoaded = true
	metricsMemoryLoaded.Add(uint64(loaded))
	// 写快照：配置重载时直接继承，免掉一次文件解析与污染校验（v2.10.2）。
	storeMemorySnapshot(path, m.memories)
	log.Infoln("[GameRoute] memory loaded %d entries from %s", loaded, path)
	m.memMu.Unlock()
}

// remember 写入/刷新一条记忆（目标确认注册后调用）：命中次数递增、
// 状态置 active、最后命中时间更新，并标记待落盘。
// 落盘策略：500ms 去抖合并；连续确认 3 次立即落盘；单次变更 2s 兜底
// 强制落盘——保证"疑似/单次识别"最终也会持久化，但高频确认更快落盘。
// 时段维度：写入时带上当前时段 bucket，同 IP 不同时段可独立记忆。
func (m *Manager) remember(ip string, port uint16) {
	key := memoryKeyFor(ip, port)
	now := time.Now().UnixMilli()
	bucket := timeBucket(now)
	m.memMu.Lock()
	if m.memories == nil {
		m.memories = make(map[string]*GameMemory)
	}
	mem, ok := m.memories[key]
	if !ok {
		mem = &GameMemory{Key: key}
		m.memories[key] = mem
	}
	mem.Hits++
	mem.LastHitAt = now
	mem.Status = "active"
	mem.TimeBucket = bucket
	m.touchMemoryLocked()
	m.memMu.Unlock()
}

// rememberProcessName 进程名自学习：注册成功后把反查到的进程名写进记忆，
// Source="process"（A 类，高信任，进程背书），长期保留不降权。
// 进程门禁：非游戏进程名一律不写入（防 msedge/QQMusic 等再次污染记忆）。
func (m *Manager) rememberProcessName(ip string, procName string) {
	procName = strings.TrimSpace(procName)
	if procName == "" {
		return
	}
	// 2026-10-21 无词表通用识别：与注册链路统一走 isGameProcess（aux 排除 →
	// 关键词/目录特征 → 引擎 DLL 嗅探），避免无词条游戏注册成功却写不进
	// A 类进程背书记忆。
	if ok, _ := isGameProcess(procName); !ok {
		return
	}
	m.MarkGameActive() // v2.4 漏洞三④：识别游戏进程即入临战活跃态
	m.memMu.Lock()
	changed := false
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem.ProcessName == procName {
			continue
		}
		mem.ProcessName = procName
		mem.Source = "process" // A 类：进程背书，长期保留
		m.memories[k] = mem
		changed = true
	}
	if changed {
		m.touchMemoryLocked()
	}
	m.memMu.Unlock()
}

// rememberFakeCNOverrideMark 给反悔接管目标的记忆条目打审计标记
// （FakeCNOverride=true + 时间 + 原因），来源标记语义等价
// "source=fakecn_override"，但保留原有 Source（process/flow）的信任等级语义，
// 避免 A 类进程背书条目被降权后在启动清洗中被误剔除。
// 与 remember / rememberProcessName 相同遍历规则：匹配 ip/32 与 ip: 前缀。
func (m *Manager) rememberFakeCNOverrideMark(ip, reason string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	now := time.Now().UnixMilli()
	m.memMu.Lock()
	changed := false
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem == nil || mem.FakeCNOverride {
			continue
		}
		mem.FakeCNOverride = true
		mem.FakeCNOverrideAt = now
		mem.FakeCNReason = reason
		changed = true
	}
	if changed {
		m.touchMemoryLocked()
	}
	m.memMu.Unlock()
}

// rememberPreferredProxy 记录某 IP 实际选中的出口到记忆条目
// （PreferredProxy 字段，重启后 Auto-Pick Primary 最高优先复用，
// 避免重启后 RTT 表为空时随机选到劣化节点）。
// 与 rememberProcessName 相同遍历规则：匹配 ip/32 与 ip: 前缀的全部条目。
func (m *Manager) rememberPreferredProxy(ip string, proxy string) {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return
	}
	m.memMu.Lock()
	changed := false
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem.PreferredProxy == proxy {
			continue
		}
		mem.PreferredProxy = proxy
		m.memories[k] = mem
		changed = true
	}
	if changed {
		m.touchMemoryLocked()
	}
	// 需求 E4（2026-10-17）：同步累计 /24 与 /16 网段级条目（普通被动
	// 路径：≥2 个不同 IP 样本才可信，见 lookUpSegmentPreferred）。
	m.bumpSegmentMemoryLocked(ip, proxy, "", "passive")
	m.memMu.Unlock()
}

// lookUpPreferredProxy 读取某 IP 记忆条目中记录的优选出口：
// 命中任一携带 PreferredProxy 的 active 条目即返回（active 判定与
// lookupMemory 一致），无记录返回空串。供 Auto-Pick Primary 初选最高优先。
func (m *Manager) lookUpPreferredProxy(ip string) string {
	m.memMu.Lock()
	defer m.memMu.Unlock()
	now := time.Now().UnixMilli()
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem == nil || !m.memUsableLocked(mem, now) {
			continue
		}
		if p := strings.TrimSpace(mem.PreferredProxy); p != "" {
			return p
		}
	}
	return ""
}

// rememberRegionActual 记录某 IP 实际表现最佳的服务器区到记忆条目（RegionActual 字段），
// 与 rememberPreferredProxy 相同遍历规则：匹配 ip/32 与 ip: 前缀的全部条目。
// 写入侧治理污染：欧美/大洋洲/中东等易污染区标签仅当目标 IP 命中段表
// （已知游戏服务器确在该区）才允许写入，否则丢弃——防止探测把欧美节点
// 选为 best 后把地区误写进记忆（DE/US/NL/GB 污染根因）。
func (m *Manager) rememberRegionActual(ip string, region string) {
	region = strings.TrimSpace(region)
	if region == "" {
		return
	}
	// 五区锁死（Shadow Forking 改造 2026-10-17 需求 E/Q5）：RegionActual
	// 取值空间仅 HK/TW/SG/JP/KR，非五区值一律拒绝落盘。原"污染区拒绝"
	// 与"横跳冻结"机制随五区锁死一并移除（Q5 裁决①③④）。
	if !IsLaneRegion(region) {
		log.Warnln("[GameRoute] refuse non-lane region_actual %s for %s (five-region lock)", region, ip)
		return
	}

	m.memMu.Lock()
	changed := false
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem.RegionActual == region {
			continue
		}
		mem.RegionActual = region
		m.memories[k] = mem
		changed = true
	}
	if changed {
		m.touchMemoryLocked()
	}
	// 需求 E4（2026-10-17）：同步累计网段级条目（值已五区锁死）。
	m.bumpSegmentMemoryLocked(ip, "", region, "passive")
	m.memMu.Unlock()
}

// lookUpRegionActual 读取某 IP 记忆条目中实际表现最佳的地区（如 SG/HK）：
// 命中任一携带 RegionActual 的 active 条目即返回，无记录返回空串。
// 供 Auto-Pick Primary 记忆优先路径使用（记忆优先级 > GeoIP）。
func (m *Manager) lookUpRegionActual(ip string) string {
	m.memMu.Lock()
	defer m.memMu.Unlock()
	now := time.Now().UnixMilli()
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem == nil || !m.memUsableLocked(mem, now) {
			continue
		}
		if r := strings.TrimSpace(mem.RegionActual); r != "" {
			return r
		}
	}
	return ""
}

// LookUpAnyRegionActual 返回记忆中任一 active 且携带 RegionActual 的条目
// 对应的实际最优区（取最后写入的，供 GET /gameroute/status 的
// region_actual 字段输出；无记录返回空串）。锁内只读遍历，无副作用。
func (m *Manager) LookUpAnyRegionActual() string {
	m.memMu.Lock()
	defer m.memMu.Unlock()
	now := time.Now().UnixMilli()
	var last string
	var lastAt int64
	for _, mem := range m.memories {
		if mem == nil || !m.memUsableLocked(mem, now) {
			continue
		}
		if r := strings.TrimSpace(mem.RegionActual); r != "" && mem.LastHitAt >= lastAt {
			lastAt = mem.LastHitAt
			last = r
		}
	}
	return last
}

// lookUpProcessName 查询该 IP 记忆条目中的进程名（进程级保活用）：
// 任一 key（ip/32 或 ip:lo-hi）携带进程名即返回；全部无进程名返回 ""。
func (m *Manager) lookUpProcessName(ip string) string {
	m.memMu.Lock()
	defer m.memMu.Unlock()
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem != nil && strings.TrimSpace(mem.ProcessName) != "" {
			return mem.ProcessName
		}
	}
	return ""
}

// ---- 网段级记忆与启动清洗（Shadow Forking 改造 2026-10-17 需求 E）----

// bumpSegmentMemoryLocked 累计一个 IP 样本到 /24（及 /16 兜底）网段级记忆
// 条目（memMu 持锁调用）。普通被动路径：≥2 个不同 IP 样本才可信（需求
// E4：单样本防污染）；赛马胜者走 rememberSegmentWinner（Q10 单样本即写）。
// /16 仅当 /24 尚未可信时累计（/24 有样本后不再喂 /16）。
func (m *Manager) bumpSegmentMemoryLocked(ip, proxy, region, source string) {
	key24 := segmentKey24(ip)
	if key24 == "" {
		return
	}
	now := time.Now().UnixMilli()
	mem := m.ensureSegmentEntryLocked(key24)
	seen := false
	for _, s := range mem.SegmentIPs {
		if s == ip {
			seen = true
			break
		}
	}
	if !seen {
		mem.SegmentIPs = append(mem.SegmentIPs, ip)
		mem.SegmentSamples = len(mem.SegmentIPs)
	}
	mem.SegmentLevel = "/24"
	if mem.SegmentSource != "race" {
		mem.SegmentSource = source
	}
	if proxy != "" {
		mem.PreferredProxy = proxy
	}
	if region != "" {
		mem.RegionActual = region
	}
	mem.Hits++
	mem.LastHitAt = now
	mem.Status = "active"
	if mem.SegmentSource != "race" && mem.SegmentSamples < 2 {
		if key16 := segmentKey16(ip); key16 != "" {
			mem16 := m.ensureSegmentEntryLocked(key16)
			seen16 := false
			for _, s := range mem16.SegmentIPs {
				if s == ip {
					seen16 = true
					break
				}
			}
			if !seen16 {
				mem16.SegmentIPs = append(mem16.SegmentIPs, ip)
				mem16.SegmentSamples = len(mem16.SegmentIPs)
			}
			mem16.SegmentLevel = "/16"
			if mem16.SegmentSource != "race" {
				mem16.SegmentSource = source
			}
			if proxy != "" {
				mem16.PreferredProxy = proxy
			}
			if region != "" {
				mem16.RegionActual = region
			}
			mem16.Hits++
			mem16.LastHitAt = now
			mem16.Status = "active"
		}
	}
	m.touchMemoryLocked()
}

// ensureSegmentEntryLocked 取/建一条记忆条目（memMu 持锁调用）。
func (m *Manager) ensureSegmentEntryLocked(key string) *GameMemory {
	if m.memories == nil {
		m.memories = make(map[string]*GameMemory)
	}
	mem, ok := m.memories[key]
	if !ok || mem == nil {
		mem = &GameMemory{Key: key}
		m.memories[key] = mem
	}
	return mem
}

// segmentEntryUsable 网段级条目可信判定：赛马锁死（race）或 ≥2 个不同
// IP 样本（需求 E4 / Q10）。
func segmentEntryUsable(mem *GameMemory) bool {
	if mem == nil {
		return false
	}
	return mem.SegmentSource == "race" || mem.SegmentSamples >= 2
}

// lookUpSegmentPreferred 网段级记忆查询：/24 → /16 顺序；/16 仅当 /24
// 无条目时兜底（需求 E4）。/24 条目存在但未可信 → 不再查 /16。
// 返回 (proxy, region, level)。ip/32 精确记忆由 lookUpPreferredProxy 覆盖。
func (m *Manager) lookUpSegmentPreferred(ip string) (string, string, string) {
	key24 := segmentKey24(ip)
	if key24 == "" {
		return "", "", ""
	}
	m.memMu.Lock()
	defer m.memMu.Unlock()
	if mem, ok := m.memories[key24]; ok {
		if segmentEntryUsable(mem) {
			return mem.PreferredProxy, mem.RegionActual, "/24"
		}
		return "", "", ""
	}
	if key16 := segmentKey16(ip); key16 != "" {
		if mem, ok := m.memories[key16]; ok && segmentEntryUsable(mem) {
			return mem.PreferredProxy, mem.RegionActual, "/16"
		}
	}
	return "", "", ""
}

// rememberSegmentWinner 赛马胜者网段记忆（Q10：单样本即写，SegmentSource
// =race，可信度等同实测仲裁）。segKey 为 "a.b.c.0/24" 形式。
func (m *Manager) rememberSegmentWinner(segKey, proxy, region string) {
	if segKey == "" {
		return
	}
	m.memMu.Lock()
	mem := m.ensureSegmentEntryLocked(segKey)
	mem.SegmentLevel = segKey[strings.LastIndex(segKey, "/"):]
	mem.SegmentSource = "race"
	if mem.SegmentSamples < 1 {
		mem.SegmentSamples = 1
	}
	if mem.SegmentIPs == nil {
		mem.SegmentIPs = []string{}
	}
	mem.PreferredProxy = proxy
	if region != "" {
		mem.RegionActual = region
	}
	mem.Hits++
	mem.LastHitAt = time.Now().UnixMilli()
	mem.Status = "active"
	m.touchMemoryLocked()
	m.memMu.Unlock()
}

// reconcileMemoryForLanePool 启动清洗（批复补充/死六二）：五区池就绪后
// 一次性执行——RegionActual 非五区、PreferredProxy 不在五区池的字段值
// 清空；绝不删整条记忆（保留 source=process 识别能力）。仅清字段值。
// 池未就绪（len==0）时不置位，留待下次 SetAllProxies。
func (m *Manager) reconcileMemoryForLanePool(pool []string) {
	if !m.memReconciled.CompareAndSwap(false, true) {
		return
	}
	if len(pool) == 0 {
		m.memReconciled.Store(false)
		return
	}
	inPool := make(map[string]bool, len(pool))
	for _, n := range pool {
		inPool[n] = true
	}
	m.memMu.Lock()
	cleaned := 0
	for _, mem := range m.memories {
		if mem == nil {
			continue
		}
		changed := false
		if mem.RegionActual != "" && !IsLaneRegion(mem.RegionActual) {
			mem.RegionActual = ""
			changed = true
		}
		if mem.PreferredProxy != "" && !inPool[mem.PreferredProxy] {
			mem.PreferredProxy = ""
			changed = true
		}
		if changed {
			cleaned++
		}
	}
	if cleaned > 0 {
		m.touchMemoryLocked()
	}
	m.memMu.Unlock()
	if cleaned > 0 {
		log.Infoln("[GameRoute] memory startup reconcile: cleaned %d entries (five-region lock)", cleaned)
	}
	// Q6：模板独立落盘路径随记忆路径派生（runtime/game_probe_templates.json）。
	m.memMu.Lock()
	memPath := m.memPath
	m.memMu.Unlock()
	if memPath != "" {
		m.SetProbeTemplatePath(filepath.Join(filepath.Dir(memPath), "game_probe_templates.json"))
	}
}

// forget 将指定 IP 相关记忆全部降权 active → decay（UnregisterTargetIP
// 调用）：目标被移除说明不可靠，降权后不再参与秒识别；decay 条目由
// 维护器 72h 后淘汰。降权状态本身会落盘，防止重启后又秒识别。
func (m *Manager) forget(ip string) {
	now := time.Now().UnixMilli()
	m.memMu.Lock()
	changed := false
	for k, mem := range m.memories {
		if k != ip+"/32" && !strings.HasPrefix(k, ip+":") {
			continue
		}
		if mem.Status == "active" {
			mem.Status = "decay"
			mem.LastHitAt = now
			m.memories[k] = mem
			changed = true
		}
	}
	if changed {
		m.touchMemoryLocked()
	}
	m.memMu.Unlock()
}

// lookupMemory 查询记忆：命中（IP 或端口段 key）且状态 active 且
// 距最后命中 <24h → 返回命中 key 与 true。decay/evicted 一律不命中，
// 即"疑似/降权状态不参与秒识别"。
// 时段匹配：优先当前时段记录 → 回退最近时段记录 → 最后回退全局记录。
// 同 IP 允许不同时段不同节点（白天香港、晚上新加坡，各自独立记忆）。
// v4 A/B 类规则：A 类（Source=process）无条件可命中；
// B 类（Source=flow）需 LastHitAt < 15min 才命中（短 TTL 防污染）。
func (m *Manager) lookupMemory(ip string, port uint16) (string, bool) {
	// v4：临时黑名单检查。黑名单命中时拒绝记忆命中。
	if bl, until := m.isBlacklisted(ip); bl {
		log.Warnln("[GameRoute] blacklist hit %s (until %s)", ip, until)
		return "", false
	}
	now := time.Now().UnixMilli()
	bucket := timeBucket(now)
	m.memMu.Lock()
	defer m.memMu.Unlock()
	key := memoryKeyFor(ip, port)

	// 1) 精确匹配当前时段
	if mem, ok := m.memories[key]; ok && m.memUsableLocked(mem, now) && mem.TimeBucket == bucket {
		return m.processMemoryHitLocked(mem, now, key)
	}

	// 2) 精确匹配无当前时段 → 回退最近时段记录
	// 时段优先级：night(18-24) > day(08-18) > late(00-08)
	// 因为当前时段无记录时，最近时段（按时间倒序）最可能有效
	for _, fallbackBucket := range []string{bucket, timeBucket(now - 12*3600*1000), timeBucket(now - 6*3600*1000)} {
		if fallbackBucket == bucket {
			continue
		}
		if mem, ok := m.memories[key]; ok && m.memUsableLocked(mem, now) && mem.TimeBucket == fallbackBucket {
			return m.processMemoryHitLocked(mem, now, key)
		}
	}

	// 3) 回退全局记录（无时段限制）
	if mem, ok := m.memories[key]; ok && m.memUsableLocked(mem, now) {
		return m.processMemoryHitLocked(mem, now, key)
	}

	// 4) 端口段宽松命中：精确 key 未中时，按 IP 前缀扫全部端口段条目
	// （重启后客户端端口在段内变化，需段级命中）。
	prefix := ip + ":"
	for k, mem := range m.memories {
		if strings.HasPrefix(k, prefix) && m.memUsableLocked(mem, now) {
			if mem.TimeBucket == bucket {
				return m.processMemoryHitLocked(mem, now, k)
			}
		}
	}

	// 5) 普通 IP 匹配
	k := ip + "/32"
	if mem, ok := m.memories[k]; ok && m.memUsableLocked(mem, now) {
		return m.processMemoryHitLocked(mem, now, k)
	}

	return "", false
}

// processMemoryHitLocked 处理记忆命中：B 类升级逻辑 + 返回 key。
func (m *Manager) processMemoryHitLocked(mem *GameMemory, now int64, key string) (string, bool) {
	// B 类（Source 为空或 "flow"）：命中即确认，累加 FlowHits，
	// 连续 3 次不同会话（距上次递增 ≥5 分钟）升级为 A 类。
	isB := mem.Source == "" || mem.Source == "flow"
	if isB {
		if mem.FlowHits > 0 && now-mem.LastFlowHitsIncAt >= memFlowSessionMs {
			mem.FlowHits++
			mem.LastFlowHitsIncAt = now
			if mem.FlowHits >= memFlowHitsUpgradeN {
				mem.Source = "process"
				log.Warnln("[GameRoute] memory upgrade B->A %s (flowHits=%d)", key, mem.FlowHits)
				m.touchMemoryLocked()
			}
		} else if mem.FlowHits == 0 {
			// 首次命中：记录当前时间作为第一次递增点
			mem.FlowHits = 1
			mem.LastFlowHitsIncAt = now
			if mem.FlowHits >= memFlowHitsUpgradeN {
				mem.Source = "process"
				log.Warnln("[GameRoute] memory upgrade B->A %s (flowHits=%d)", key, mem.FlowHits)
				m.touchMemoryLocked()
			}
		}
	}
	return key, true
}

// memUsableLocked 记忆可用判定：active 且距最后命中 <24h。
// v4 A/B 类规则：A 类（Source=process）仅要求 active 且 <24h；
// B 类（Source=flow）额外要求 <15min，避免纯流量识别的误圈目标
// 长期滞留造成记忆污染。
func (m *Manager) memUsableLocked(mem *GameMemory, now int64) bool {
	if mem == nil || mem.Status != "active" {
		return false
	}
	if mem.Source == "process" {
		return now-mem.LastHitAt < memActiveTTLMs
	}
	// B 类：15 分钟短 TTL，纯流量识别的误圈目标不能长期污染记忆。
	return now-mem.LastHitAt < 15*60*1000
}

// touchMemoryLocked 标记记忆脏并安排去抖落盘（须持有 memMu）。
func (m *Manager) touchMemoryLocked() {
	if !m.memDirty {
		m.memDirty = true
		m.memFirstDirtyAt = time.Now().UnixMilli()
	}
	m.memConfirmCount++
	if m.memFlushScheduled {
		return
	}
	// 连续确认 3 次 → 500ms 后立即落盘；单次变更 → 2s 兜底强制落盘。
	delay := memFlushDebounceMs
	if m.memConfirmCount < memFlushConfirmN {
		remaining := memForceFlushAfterMs - (time.Now().UnixMilli() - m.memFirstDirtyAt)
		if remaining <= 0 {
			delay = 0
		} else if remaining < int64(delay/time.Millisecond) {
			delay = time.Duration(remaining) * time.Millisecond
		}
	}
	m.memFlushScheduled = true
	time.AfterFunc(delay, func() { m.flushMemoryOnce() })
}

// flushMemoryOnce 去抖落盘：快照当前记忆，原子写（临时文件 + Rename）。
func (m *Manager) flushMemoryOnce() {
	m.memMu.Lock()
	if !m.memDirty || m.memPath == "" {
		m.memFlushScheduled = false
		m.memMu.Unlock()
		return
	}
	baseConfirm := m.memConfirmCount
	mf := MemoryFile{
		Version: memVersion,
		Updated: time.Now().Format(time.RFC3339),
		Entries: make(map[string]GameMemory, len(m.memories)),
	}
	for k, v := range m.memories {
		mf.Entries[k] = *v
	}
	m.memMu.Unlock()

	if err := writeMemoryFileAtomic(m.memPath, mf); err != nil {
		log.Warnln("[GameRoute] memory flush failed: %v", err)
		m.memMu.Lock()
		m.memFlushScheduled = false
		m.memMu.Unlock()
		return
	}
	m.memMu.Lock()
	if m.memConfirmCount > baseConfirm {
		// 写盘期间又有新变更：保留 dirty，重新安排去抖。
		m.memFlushScheduled = false
		m.memMu.Unlock()
		return
	}
	m.memDirty = false
	m.memConfirmCount = 0
	m.memFlushScheduled = false
	// 落盘成功：同步运行期快照（配置重载继承内存表，必须是最新态）。
	storeMemorySnapshot(m.memPath, m.memories)
	m.memMu.Unlock()
	log.Debugln("[GameRoute] memory flushed %d entries", len(mf.Entries))
}

// memSweep 记忆维护（随 watch sweeper 周期调用，60s）：
//   - active 24h 未命中 → decay（降权）
//   - decay 72h 未命中 → 删除（evicted）
//   - 超 500 条 → 淘汰最旧 decay 条目
//   - 兜底强制落盘（2s 前有未落盘变更但去抖未触发时）
func (m *Manager) memSweep() {
	now := time.Now().UnixMilli()
	m.memMu.Lock()
	if m.memories == nil {
		m.memories = make(map[string]*GameMemory)
	}
	for k, mem := range m.memories {
		switch mem.Status {
		case "active":
			// v4 A/B 类规则：A 类（process 背书）不降权；
			// B 类（flow 背书）idle 超 15min 降权（decay）防污染。
			if mem.Source == "process" {
				continue // A 类：长期保留，idle 不降权
			}
			if now-mem.LastHitAt >= 15*60*1000 {
				mem.Status = "decay"
				mem.LastHitAt = now
				m.memories[k] = mem
			}
		case "decay":
			if now-mem.LastHitAt >= memDecayTTLMs {
				delete(m.memories, k)
			}
		}
	}
	if len(m.memories) > memEntryLimit {
		type evictItem struct {
			key  string
			last int64
		}
		// 两段式淘汰：先删最旧 decay（不可用记忆优先让位）；decays 不足时
		// 按 LastHitAt 从旧到新直接淘汰 active —— active 24h 未命中本就会转
		// decay，主动淘汰等价于提前降权，保证条目数一定收敛到上限以内。
		decays := make([]evictItem, 0, len(m.memories))
		actives := make([]evictItem, 0, len(m.memories))
		for k, mem := range m.memories {
			if mem.Status == "decay" {
				decays = append(decays, evictItem{k, mem.LastHitAt})
			} else {
				actives = append(actives, evictItem{k, mem.LastHitAt})
			}
		}
		sort.Slice(decays, func(i, j int) bool { return decays[i].last < decays[j].last })
		sort.Slice(actives, func(i, j int) bool { return actives[i].last < actives[j].last })
		for i := 0; i < len(decays) && len(m.memories) > memEntryLimit; i++ {
			delete(m.memories, decays[i].key)
		}
		for i := 0; i < len(actives) && len(m.memories) > memEntryLimit; i++ {
			delete(m.memories, actives[i].key)
		}
		m.memDirty = true
		m.memFirstDirtyAt = now
		if m.memConfirmCount < memFlushConfirmN {
			m.memConfirmCount = memFlushConfirmN
		}
	}
	if m.memDirty && !m.memFlushScheduled && now-m.memFirstDirtyAt >= memForceFlushAfterMs {
		m.memFlushScheduled = true
		time.AfterFunc(0, func() { m.flushMemoryOnce() })
	}
	// 维护期可能降权/淘汰过条目：同步运行期快照，避免配置重载继承已淘汰条目。
	if m.memPath != "" {
		storeMemorySnapshot(m.memPath, m.memories)
	}
	m.memMu.Unlock()
}

// MemorySnapshot 返回当前记忆快照（供 REST API 展示，按 key 排序）。
func (m *Manager) MemorySnapshot() []GameMemory {
	m.memMu.Lock()
	defer m.memMu.Unlock()
	out := make([]GameMemory, 0, len(m.memories))
	for _, mem := range m.memories {
		out = append(out, *mem)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ClearMemory 清空全部记忆并删除记忆文件（REST API：DELETE /gameroute/memory）。
func (m *Manager) ClearMemory() {
	m.memMu.Lock()
	m.memories = make(map[string]*GameMemory)
	m.memDirty = true
	m.memFirstDirtyAt = time.Now().UnixMilli()
	m.memConfirmCount = memFlushConfirmN // 清空立即落盘
	path := m.memPath
	// 快照同步清空：否则配置重载会从快照把已清空的记忆"复活"。
	storeMemorySnapshot(path, m.memories)
	m.memMu.Unlock()
	if path != "" {
		// 删除文件本身（而非只写空表）：清空语义 = 文件消失，下次启动零名单。
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Warnln("[GameRoute] memory clear remove failed: %v", err)
		}
	}
	log.Infoln("[GameRoute] memory cleared")
}

// ForgetMemoryIP 移除指定 IP 的全部记忆（REST API：DELETE /gameroute/memory/<ip>）。
func (m *Manager) ForgetMemoryIP(ip string) bool {
	m.memMu.Lock()
	changed := false
	for k := range m.memories {
		if k == ip+"/32" || strings.HasPrefix(k, ip+":") {
			delete(m.memories, k)
			changed = true
		}
	}
	if changed {
		m.memConfirmCount = memFlushConfirmN // 立即落盘
		m.memDirty = true
		m.memFirstDirtyAt = time.Now().UnixMilli()
		if m.memPath != "" {
			storeMemorySnapshot(m.memPath, m.memories) // 快照同步删除，避免重载复活
		}
	}
	m.memMu.Unlock()
	return changed
}

// writeMemoryFileAtomic 原子写：同目录临时文件写入后 Rename 覆盖，
// 避免写一半崩溃导致记忆文件损坏。
func writeMemoryFileAtomic(path string, mf MemoryFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "game_memory_*.tmp")
	if err != nil {
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(mf); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// timeBucket 计算当前时间所属时段 bucket：
//   - day:   08:00-18:00  (白天)
//   - night: 18:00-24:00  (晚上高峰)
//   - late:  00:00-08:00  (深夜)
func timeBucket(unixMs int64) string {
	h := time.UnixMilli(unixMs).Hour()
	switch {
	case h >= 8 && h < 18:
		return "day"
	case h >= 18 && h < 24:
		return "night"
	default:
		return "late"
	}
}
