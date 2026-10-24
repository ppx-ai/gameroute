package gamelane

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Target 是 gameroute 配置节中的一条快速通道目标：
// 命中后该会话的 UDP 流量直接使用 Proxy 出口，跳过常规 rules 匹配；
// Fallbacks 为质量恶化时预测式切换的备用出口候选池（可空，表示不启用切换；
// 单元素即旧版单 fallback 行为）。切换前会对候选池逐个探测评分，选最优出口。
type Target struct {
	ProcessName string
	CIDR        []netip.Prefix
	Proxy       string
	Fallbacks   []string

	// autoPicked 标记该 Target 的 Fallbacks 由内核自动圈选生成（区别于配置写入），
	// 供周期刷新重新圈选使用。仅包内可见，不参与配置序列化。
	autoPicked bool

	// v2 Auto-Pick Primary：autoPrimary 标记该 Target 处于自动主节点模式
	// （Proxy 为空或 "auto"）。首次命中立即用临时主节点进场（不等待探测），
	// 会话建立后后台对候选池探测评分，选最优自动切换主节点；
	// currentPrimary 为当前实际主节点名（临时节点或探测后最优，排队等待选路时为空串）。
	// 两者仅包内可见，不参与配置序列化；显式配置 Proxy 时该模式不生效。
	autoPrimary    bool
	currentPrimary string
	primaryMu      sync.Mutex // 保护 currentPrimary/autoPrimary 的跨层读写（tunnel 回报）

	// 扩展字段（状态查询 API 用）
	Region        string       // 目标归属区（如 "SG"）
	CurrentProxy  string       // 当前实际主节点
	CurrentRegion string       // 当前实际节点区
	RTT           int          // 当前节点到目标延迟（毫秒）
	Packets       int          // 该目标累计命中包数
	LastSeen      *time.Time   // 最近一次有流量时间
	extMu         sync.RWMutex // 保护 region/currentProxy/currentRegion/rtt/packets/lastSeen

	// F5：探测单飞标记——并发首包/周期刷新会重复触发 probeAndSettle，
	// 造成探测风暴与无谓的主节点跳变（诊断 RC13）。用 int32+atomic CAS
	// 而非 atomic.Bool，保持 Target 可整体拷贝（vet copylocks）。
	probeRunning int32
}

// IsAutoPrimary 返回该 Target 是否处于自动主节点模式（Proxy 为空或 "auto"）。
func (t *Target) IsAutoPrimary() bool {
	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()
	return t.autoPrimary
}

// EffectiveProxy 返回当前实际主节点名：autoPrimary 模式下为临时/探测选中的
// 节点（空串表示排队等待选路，上层不放行直连），显式配置模式返回配置
// Proxy（配置优先）。
func (t *Target) EffectiveProxy() string {
	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()
	if t.autoPrimary {
		return t.currentPrimary
	}
	return t.Proxy
}

// SetCurrentPrimary 更新 autoPrimary 模式下的当前实际主节点名
// （供会话探测切换后回报，GET /gameroute/targets 输出即取该值）。
// 显式配置模式（非 autoPrimary）一律忽略，保证配置优先。
func (t *Target) SetCurrentPrimary(name string) {
	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()
	if t.autoPrimary && name != "" {
		t.currentPrimary = name
		// 探测后选中/换优主节点时同步全局 current_proxy（不算切换次数）
		RecordM3Active(name)
	}
}

// InstallSegmentWinner 锁死赢家进场（2026-10-18 v2.1 批复方案 B）：
// lockSegment 落锁时对 /24 命中的目标同步安装赢家主路——修复"锁死前
// 已建会话的目标重建时 currentPrimary≠空 跳过锁查询"的边界缺陷
// （ensureAutoPrimary 仅在主路为空时查锁）。显式配置目标直接拒绝
// （配置优先=永久保护，Q-F2 附带确认）。未匹配过的注册目标同样进场
// （首次 Match 的锁查询结果与本安装一致）。返回（目标 IPv4, 是否
// 发生真实变更）：old≠空 且 old≠新值 时由调用方触发会话重建（批复
// 漏洞三；old==空 表示目标从未定主路，无已结算会话，不触发重建）。
func (t *Target) InstallSegmentWinner(proxy string) (string, bool) {
	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()
	if t.Proxy != "" && t.Proxy != "auto" {
		return "", false
	}
	t.autoPrimary = true
	ip := ""
	if len(t.CIDR) > 0 && t.CIDR[0].Addr().Is4() {
		ip = t.CIDR[0].Addr().String()
	}
	old := t.currentPrimary
	if old == proxy {
		return ip, false
	}
	t.currentPrimary = proxy
	RecordM3Active(proxy)
	return ip, old != ""
}

// SnapshotFallbacks 返回候选池快照（探测结算/会话读取用，避免与写回竞态）。
func (t *Target) SnapshotFallbacks() []string {
	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()
	out := make([]string, len(t.Fallbacks))
	copy(out, t.Fallbacks)
	return out
}

// SetFallbacks 按探测结果重排候选池（仅自动主节点模式生效；显式配置不动）。
func (t *Target) SetFallbacks(ordered []string) {
	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()
	if t.autoPrimary && len(ordered) > 0 {
		t.Fallbacks = ordered
	}
}

// Manager 维护 gameroute 的启用状态与目标注册表。
type Manager struct {
	mu      sync.RWMutex
	enabled bool
	targets []Target

	// 临时黑名单：硬性异常淘汰后写入，24h 内 RegisterTargetIP/ 记忆命中拒绝。
	blacklist map[string]blacklistEntry

	// 自动圈选：全局节点列表 + RTT 表 + 刷新控制
	allProxies         []string       // 全局代理名列表（从 mihomo 核心注入）
	rttTable           map[string]int // proxy 名 → RTT（毫秒）
	refreshMu          sync.Mutex
	lastRefreshAt      int64 // UnixMilli，控制周期刷新频率
	refreshMinInterval int   // 30s，懒测低频
	candidateTopN      int   // 自动圈选 top N，默认 5

	// v6.5 即时探测源：探测 URL + 全局节点对象映射（从 mihomo 核心注入）。
	// 命中目标后立即对候选池发起真实出站探测写回 RTT，供 auto-pick 裁决
	// （不再等流量被动积累 RTT，确保池内港台节点被测到并胜出）。
	probeMu   sync.Mutex
	probeURL  string
	proxyObjs map[string]C.Proxy

	// 默认出口：当前策略组实际选中节点（如 Final 当前节点），作为
	// 永远可用的兜底出口。GameLane 流量绝不直连，默认出口不可达时
	// 也保持上一次可用出口或排队等待选路。
	defaultProxyMu sync.Mutex
	defaultProxy   string

	// 最后一个实际可用出口（极端兜底：默认出口也不可达时保持此值）
	lastProxyMu sync.Mutex
	lastProxy   string

	// 每个目标上一次有效出口（目标 key → 出口名），重启后从
	// game_lane_state.json 恢复，作为退避链中"上一出口"的来源。
	lastProxyByTargetMu sync.Mutex
	lastProxyByTarget   map[string]string
	lastProxyPath       string // game_lane_state.json 绝对路径

	// UDP 流特征观察表：目标 "IP:Port" → 轻量统计，零名单自动识别游戏目标。
	flowsMu sync.Mutex
	flows   map[string]*flowStat

	// fakeCN 反悔接管观察窗（v2.12 清单5，2026-10-22）：大陆路由表命中的
	// 游戏 UDP 目标先按直连放行，同时登记观察窗；出站有包但 ≥2s 零回包
	// 或实测直连 RTT>70ms → 判为"假大陆 IP"（CDN/Anycast 或表数据陈旧），
	// 反悔注册并写 fakecn_override 持久记忆。锁独立于 flowsMu/m.mu。
	fakeCNMu    sync.Mutex
	fakeCNWatch map[string]*fakeCNWatchState

	// 已注册目标动态监视表：目标 IP → watchStat，用于注册后自我纠错
	// （对局特征确认保留 / 非对局特征自动淘汰 / 24h 无对局特征自动清理）。
	watchesMu sync.Mutex
	watches   map[string]*watchStat

	// 自学习记忆：服务未知游戏的持久化记忆（跨重启秒识别）。
	memMu             sync.Mutex
	memories          map[string]*GameMemory // key("ip/32"|"ip:port-range") → 记忆
	memPath           string                 // 记忆文件路径
	memLoaded         bool                   // 已完成一次加载（同实例重复 LoadMemory 幂等跳过）
	memDirty          bool                   // 有未落盘变更
	memFlushScheduled bool                   // 已有去抖落盘 goroutine 在途
	memConfirmCount   int                    // 连续确认次数（达到阈值才落盘）
	memFirstDirtyAt   int64                  // 首个未落盘变更时间（兜底强制写）

	// 状态快照：供 GET /gameroute/status 只读输出（替代 core.log 排查）。
	// 全部在现有选路/切换路径上顺带记录，读取端在 snapshotMu 内做快照拷贝，
	// 不新增全局锁、不引入并发热点。
	snapshotMu        sync.Mutex              // 保护 primarySnapshot/lastSwitch/candidateSnapshot/history
	primarySnapshot   primarySnapshot         // 最近一次选路/切换后的主出口快照
	lastSwitch        lastSwitchInfo          // 最近一次跨区/降级切换（仅保留最近一次）
	candidateSnapshot []candidateInfo         // 最近一次候选池快照（按生成排序原样输出）
	switchHistory     [10]*switchHistoryEntry // 最多保留 10 条切换历史（环形缓冲）
	switchHistoryIdx  int                     // 写入位置

	// 状态计数器
	switchCount atomic.Uint64

	// ---- F1 探测数据治理（2026-10-16 诊断 RC1/RC6）----
	// rttTable 是所有切换/选路决策的唯一数据源，历史实现只靠单发
	// URLTest（含 TLS 握手系统性虚高 + 无平滑 + 失败即判死）写入，
	// 实测港台节点被写成 245-251ms（真实 20-50ms）。治理字段：
	failStreakMu  sync.RWMutex     // 保护 rttFailStreak：checkSegmentLock 在 segmentLockMu 内只读本锁，禁用 m.mu（防 MatchTarget 持 RLock 时升级自死锁）
	rttFailStreak map[string]int   // 节点 → 连续失败轮数（≥3 才判死写 0）
	rttLastOK     map[string]int64 // 节点 → 最近一次成功/实测时间（UnixMilli）
	lastURLTest   map[string]int   // 节点 → 最近一次原始 URLTest 值（开销校准用）
	probeOffset   map[string]int   // 节点 → 已学习的 URLTest−游戏实测 开销估计
	lastProbeOKAt atomic.Int64     // 最近一次探测/实测成功时间（UnixMilli，0=从未）

	// F2 切换冷却：目标 dst → 冷却截止（UnixMilli）。Manager 级切换是
	// 绕过 SessionConn 保护期的唯一入口，必须自身限频（30s，与会话
	// 保护期一致），否则 rttTable 抖动会把换优放大成秒级切换风暴。
	switchCooldownMu sync.Mutex
	switchCooldown   map[string]int64

	// 第一刀（v2.7）：活跃对局会话注册表——dst(目标 IP) → 最近回包时间
	// （UnixMilli）。由 tunnel 层 markRecv 路径上报（connection.go），
	// SessionConn 包装会话亦走同一下行路径；SwitchToBestFallback /
	// probeAndSettle 据此判断"目标是否承载活跃会话（recv>=1 且 10s 内
	// 有回包）"，命中即禁止换主/换区（局中跨区切出口被 EA 拒收根因）。
	sessionActiveMu     sync.Mutex
	sessionActiveRecvAt map[string]int64

	// v2.8 铁律一：会话出生注册表——dst(目标 IP) → 出生时刻（UnixMilli）。
	// laneEntry 创建第 0 毫秒由 tunnel 层 RegisterBirth 写入，出生后
	// 30s（birthGraceMs）内严禁任何入口调用 SwitchToBestFallback 换节点
	// （握手/地图加载期 0 回包是正常现象，不是死链；香港02 进场即锁死）。
	sessionBirthAt map[string]int64

	// 第二刀（v2.7）：劣迹节点熔断表——curRtt>150ms 或 degraded 触发的
	// 节点记入熔断 30 分钟；熔断期内读取侧（SnapshotRTT）叠加 +200ms
	// 惩罚权重，并废黜 bestRaceWinner，下一局/下一个新目标立即换健康
	// 节点上位，杜绝劣迹节点继续当冠军害人。
	badNodeMu    sync.Mutex
	badNodeUntil map[string]int64 // proxy → 熔断截止（UnixMilli）

	// F4 新注册目标队列：RegisterTargetIP 成功即入队，tunnel 层去抖后
	// 按 IP 精确重建会话（不再全表重建，诊断 RC4）。
	newRegMu    sync.Mutex
	newRegQueue []string

	// ---- Shadow Forking（2026-10-17 改造需求 A/C/D，批复 Q3/死六一~四）----
	segmentLockMu      sync.RWMutex
	segmentLock        map[string]*segmentLockEntry // /24 → 赛马胜者锁死（Q3①）
	segmentLockHostIdx map[string]string            // host → /24 锁键（域名索引，2026-10-18 主路对齐 A）
	segmentStale       map[string]*segmentLockEntry // 解锁待重赛的旧锁死（死六四防抖动）
	racingMu           sync.Mutex
	racingSegs         map[string]int64 // 赛马进行中占位 /24 → 起始时刻（死六一）
	preheatMu          sync.Mutex
	preheatLastAt      map[string]int64          // dst → 上次主动探针时间（5s 节流）
	preheatFailAt      map[string]int64          // dst → 上次失败时间（指数退避）
	preheatFailN       map[string]int            // dst → 连续失败次数
	probeTemplates     map[string]*probeTemplate // dstIP → 学习模板（需求 D1）
	probeTplPath       string                    // 模板落盘路径（Q6 独立文件）
	raceDialerMu       sync.Mutex
	raceDialerFn       raceDialer // 测试注入拨号；nil = 生产拨号（proxyObjs）
	realIPMu           sync.Mutex
	realIPResolverFn   func(host string) (netip.Addr, error) // fake-ip host→realIP（测试注入；nil=resolver.ResolveIP）
	pendingHostsMu     sync.Mutex
	pendingHosts       map[string]struct{} // 在途 fake-ip 解析去重（死六一前移/Q-D）
	retargetMu         sync.Mutex
	retargetFn         func(ip string) // 锁死赢家进场联动重建回调（tunnel 注册 scheduleRetarget，漏洞三）
	gameActiveUntil    atomic.Int64    // 游戏临战活跃态（v2.4 漏洞三：任一游戏特征事件刷新 now+60s）
	bestRaceMu         sync.Mutex
	bestRace           *bestRaceEntry    // 全局赛马实测最优（v2.4 第二刀 2.1：防晚回包篡位）
	fanoutOnce         atomic.Bool       // 冷启动扇出一次性触发（v2.4 漏洞一③）
	rttSource          map[string]string // 节点 → RTT 数据源（"race"=7770 赛马实测 / "urltest"=Cloudflare；进场裁决仅认 race）
	// v2.13 第一刀：STUN 保底扇出周期化——bestRaceWinner 全天候保鲜，
	// 过期软降级时的异步刷新按 in-flight + 最小间隔去重（防并发重复扇出）。
	stunRefreshOnce     atomic.Bool
	stunRefreshInFlight atomic.Bool
	stunRefreshLastAt   atomic.Int64

	// 死六二：启动清洗一次性标记（池就绪后执行一次）
	memReconciled atomic.Bool
}

// segmentLockEntry /24 网段锁死条目（需求 C / 死六四：含 rttMs 与锁定时刻）。
type segmentLockEntry struct {
	Proxy    string
	Region   string
	RTTMs    int
	LockedAt int64  // UnixMilli
	Host     string // 反查域名（2026-10-18 主路对齐 A：域名索引键，fake-ip 模式主路查锁用）
}

// primarySnapshot 记录最近一次选路/切换后的主出口快照。
// source 与 pickPrimaryTemp 优先级链一一对应：
// preferred-proxy / memory-region / player-side / geoip / fallback。
type primarySnapshot struct {
	Proxy  string `json:"proxy"`
	Region string `json:"region"`
	Source string `json:"source"`
	RTT    int    `json:"rtt"`
	At     int64  `json:"at"` // UnixMilli，记录时刻
}

// candidateInfo 候选池单项（proxy + region + rtt，按生成时排序原样输出）。
type candidateInfo struct {
	Proxy  string `json:"proxy"`
	Region string `json:"region"`
	RTT    int    `json:"rtt"`
}

// lastSwitchInfo 最近一次跨区/降级切换记录（SwitchToBestFallback 落地时写入）。
type lastSwitchInfo struct {
	Time      time.Time `json:"time"`
	FromProxy string    `json:"from_proxy"`
	ToProxy   string    `json:"to_proxy"`
	Reason    string    `json:"reason"` // region-changed / degraded
}

// PrimaryInfo 是 GET /gameroute/status 的 primary 对象。
type PrimaryInfo struct {
	Proxy  string `json:"proxy"`
	Region string `json:"region"`
	Source string `json:"source"`
	RTT    int    `json:"rtt"`
}

// CandidateInfo 是 GET /gameroute/status 的 candidate_pool 单项。
type CandidateInfo struct {
	Proxy  string `json:"proxy"`
	Region string `json:"region"`
	RTT    int    `json:"rtt"`
}

// LastSwitchInfo 是 GET /gameroute/status 的 last_switch 对象。
type LastSwitchInfo struct {
	Time      time.Time `json:"time"`
	FromProxy string    `json:"from_proxy"`
	ToProxy   string    `json:"to_proxy"`
	Reason    string    `json:"reason"`
}

// switchHistoryEntry 切换历史项（switch_history 数组中的单项）。
type switchHistoryEntry struct {
	Time       time.Time `json:"time"`
	FromProxy  string    `json:"from_proxy"`
	ToProxy    string    `json:"to_proxy"`
	FromRegion string    `json:"from_region"`
	ToRegion   string    `json:"to_region"`
	Reason     string    `json:"reason"` // region-changed / degraded
	RTT        int       `json:"rtt"`
}

// StatusStats 是 GET /gameroute/status 的 stats 对象。
type StatusStats struct {
	UDPPackets      uint64 `json:"udp_packets"`
	ManagedSessions int64  `json:"managed_sessions"`
	SwitchCount     uint64 `json:"switch_count"`
}

// StatusSnapshot 是 GET /gameroute/status 的扩展返回体（新字段，旧字段兼容）。
type StatusSnapshot struct {
	Enabled       bool               `json:"enabled"`
	M3            bool               `json:"m3"`
	Targets       int                `json:"targets"`
	Primary       *PrimaryInfo       `json:"primary"`
	RegionActual  *string            `json:"region_actual"`
	CandidatePool []CandidateInfo    `json:"candidate_pool"`
	LastSwitch    *LastSwitchInfo    `json:"last_switch"`
	SwitchHistory []switchHistoryDTO `json:"switch_history"`
	Stats         StatusStats        `json:"stats"`
	// F12：最近一次探测/会话实测成功时间（UnixMilli，0=从未），供面板
	// 判断探测数据新鲜度。
	ProbeLastOKAt int64 `json:"probe_last_ok_at"`
}

type switchHistoryDTO struct {
	Time       string `json:"time"`
	FromProxy  string `json:"from_proxy"`
	ToProxy    string `json:"to_proxy"`
	FromRegion string `json:"from_region"`
	ToRegion   string `json:"to_region"`
	Reason     string `json:"reason"`
	RTT        int    `json:"rtt"`
}

// recordPrimarySnapshot 在选路/切换命中后记录主出口快照（Source 由调用方
// 按优先级链填）；rttTable 可为 nil（此时 rtt 记 0）。
func (m *Manager) recordPrimarySnapshot(proxy, source string, rttTable map[string]int) {
	if proxy == "" {
		return
	}
	region, _ := extractRegionTag(proxy)
	rt := 0
	if rttTable != nil {
		rt = rttTable[proxy]
	}
	m.snapshotMu.Lock()
	m.primarySnapshot = primarySnapshot{Proxy: proxy, Region: region, Source: source, RTT: rt, At: time.Now().UnixMilli()}
	m.snapshotMu.Unlock()
}

// recordCandidateSnapshot 在候选池生成后记录快照（按当前排序原样输出）。
func (m *Manager) recordCandidateSnapshot(pool []string, rttTable map[string]int) {
	if len(pool) == 0 {
		return
	}
	out := make([]candidateInfo, 0, len(pool))
	for _, n := range pool {
		region, _ := extractRegionTag(n)
		rt := 0
		if rttTable != nil {
			rt = rttTable[n]
		}
		out = append(out, candidateInfo{Proxy: n, Region: region, RTT: rt})
	}
	m.snapshotMu.Lock()
	m.candidateSnapshot = out
	m.snapshotMu.Unlock()
}

// recordSwitchHistory 在 SwitchToBestFallback 切换落地处记录切换历史（环形缓冲最多10条），
// 同时保持 lastSwitch 兼容现有 last_switch 用法。
func (m *Manager) recordSwitchHistory(fromProxy, toProxy, fromRegion, toRegion, reason string, rtt int) {
	entry := &switchHistoryEntry{
		Time:       time.Now(),
		FromProxy:  fromProxy,
		ToProxy:    toProxy,
		FromRegion: fromRegion,
		ToRegion:   toRegion,
		Reason:     reason,
		RTT:        rtt,
	}
	m.snapshotMu.Lock()
	// 保持 lastSwitch 兼容（仅保留最近一次）
	m.lastSwitch = lastSwitchInfo{Time: entry.Time, FromProxy: fromProxy, ToProxy: toProxy, Reason: reason}
	// 环形缓冲写入
	m.switchHistory[m.switchHistoryIdx] = entry
	m.switchHistoryIdx = (m.switchHistoryIdx + 1) % 10
	m.snapshotMu.Unlock()
	m.switchCount.Add(1)
}

// Status 返回扩展状态快照（供 REST GET /gameroute/status）：
// 数据全部从现有内存结构读取并在现有锁内做快照拷贝，不新增全局锁。
// managedSessions / udpPackets 来自 tunnel 层统计（GameLane 快速通道）。
func (m *Manager) Status(managedSessions int64, udpPackets uint64) StatusSnapshot {
	st := StatusSnapshot{
		Enabled:       m.Enabled(),
		M3:            M3Enabled(),
		Targets:       len(m.GetTargets()),
		CandidatePool: []CandidateInfo{},
	}
	m3 := GetM3Snapshot()
	st.Stats = StatusStats{
		UDPPackets:      udpPackets,
		ManagedSessions: managedSessions,
		SwitchCount:     m3.SwitchCount + m.switchCount.Load(),
	}
	st.ProbeLastOKAt = m.lastProbeOKAt.Load()
	m.snapshotMu.Lock()
	if m.primarySnapshot.Proxy != "" {
		p := m.primarySnapshot
		st.Primary = &PrimaryInfo{Proxy: p.Proxy, Region: p.Region, Source: p.Source, RTT: p.RTT}
	}
	if len(m.candidateSnapshot) > 0 {
		for _, c := range m.candidateSnapshot {
			st.CandidatePool = append(st.CandidatePool, CandidateInfo{Proxy: c.Proxy, Region: c.Region, RTT: c.RTT})
		}
	}
	if m.lastSwitch.ToProxy != "" {
		ls := m.lastSwitch
		st.LastSwitch = &LastSwitchInfo{Time: ls.Time, FromProxy: ls.FromProxy, ToProxy: ls.ToProxy, Reason: ls.Reason}
	}
	// switch_history：环形缓冲按时间从旧到新输出。
	// 未写满时（idx 未绕回）物理下标 0..idx-1 即时间顺序；
	// 写满后从 idx（最旧）绕一圈。
	st.SwitchHistory = make([]switchHistoryDTO, 0, 10)
	n := 0
	for _, e := range m.switchHistory {
		if e != nil {
			n++
		}
	}
	start := 0
	if n == len(m.switchHistory) {
		start = m.switchHistoryIdx
	}
	for i := 0; i < len(m.switchHistory); i++ {
		e := m.switchHistory[(start+i)%len(m.switchHistory)]
		if e != nil {
			st.SwitchHistory = append(st.SwitchHistory, switchHistoryDTO{
				Time:       e.Time.Format(time.RFC3339),
				FromProxy:  e.FromProxy,
				ToProxy:    e.ToProxy,
				FromRegion: e.FromRegion,
				ToRegion:   e.ToRegion,
				Reason:     e.Reason,
				RTT:        e.RTT,
			})
		}
	}
	m.snapshotMu.Unlock()

	if ra := m.LookUpAnyRegionActual(); ra != "" {
		st.RegionActual = &ra
	}
	return st
}

// newDefaultManager 构造带默认值的 Manager。
func newDefaultManager() *Manager {
	return &Manager{
		refreshMinInterval: 25000, // 25s，懒测低频（F1：原 60s 太疏，决策数据陈旧）
		candidateTopN:      5,     // 自动圈选 top N，默认 5
		flows:              make(map[string]*flowStat),
		watches:            make(map[string]*watchStat),
		memories:           make(map[string]*GameMemory),
		blacklist:          make(map[string]blacklistEntry),
		lastProxyByTarget:  make(map[string]string),
		rttFailStreak:      make(map[string]int),
		lastURLTest:        make(map[string]int),
		probeOffset:        make(map[string]int),
		switchCooldown:     make(map[string]int64),
		segmentLock:        make(map[string]*segmentLockEntry),
		segmentLockHostIdx: make(map[string]string),
		segmentStale:       make(map[string]*segmentLockEntry),
		racingSegs:         make(map[string]int64),
		preheatLastAt:      make(map[string]int64),
		preheatFailAt:      make(map[string]int64),
		preheatFailN:       make(map[string]int),
		probeTemplates:     make(map[string]*probeTemplate),
	}
}

var defaultManager = newDefaultManager()

// Default 返回全局 Manager 单例。
func Default() *Manager {
	startWatchSweeper()
	return defaultManager
}

// SetEnabled 开关 gameroute 快速通道。
func (m *Manager) SetEnabled(b bool) {
	m.mu.Lock()
	m.enabled = b
	n := len(m.targets)
	m.mu.Unlock()
	log.Infoln("[GameRoute] enabled=%v targets=%d", b, n)
	recordDiag("config_update", "kind=enabled value=%v targets=%d", b, n)
}

// Enabled 返回当前是否启用。
func (m *Manager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// SetTargets 整体替换目标注册表（幂等，供配置重载与 REST API 使用）。
func (m *Manager) SetTargets(targets []Target) {
	// 排除层过滤：注入目标中命中排除段（Discord/Steam/TUN/私网/组播/
	// 保留段等）的 CIDR 一律剔除，与 RegisterTargetIP 注册前检查一致，
	// 防止面板手动/自动圈选把排除段目标推入快速通道。
	filtered := make([]Target, 0, len(targets))
	for _, t := range targets {
		cidrs := make([]netip.Prefix, 0, len(t.CIDR))
		for _, c := range t.CIDR {
			if isExcludedIP(c.Addr()) {
				log.Warnln("[GameRoute] target %s cidr %s excluded, drop", t.ProcessName, c)
				continue
			}
			cidrs = append(cidrs, c)
		}
		// 过滤后 CIDR 为空且原始注册了 CIDR → 整条剔除，避免空占位；
		// 纯进程名目标（未注册 CIDR，如 game.exe + Proxy 的进程级目标）
		// 不受影响，保持原样注册（CIDR 匹配由进程名 + 会话远端独立完成）。
		if len(cidrs) == 0 && len(t.CIDR) > 0 {
			log.Warnln("[GameRoute] target %s cidr all excluded, drop target", t.ProcessName)
			continue
		}
		// Q9（2026-10-17 需求 A）：显式配置的 fallbacks 同样过五区过滤——
		// "池子洗干净"不依赖配置来源；被滤除节点静默丢弃并汇总日志。
		if len(t.Fallbacks) > 0 {
			fb := m.filterLaneRegions(t.Fallbacks)
			if len(fb) != len(t.Fallbacks) {
				log.Infoln("[GameRoute] target %s fallbacks filtered: %d -> %d (five-region lock)",
					t.ProcessName, len(t.Fallbacks), len(fb))
			}
			t.Fallbacks = fb
		}
		t.CIDR = cidrs
		filtered = append(filtered, t)
	}
	targets = filtered
	m.mu.Lock()
	m.targets = append([]Target(nil), targets...)
	enabled := m.enabled
	m.mu.Unlock()
	// 整体清空（一键清空/配置移除）时同步清空自动注册的监视表，
	// 避免已淘汰目标残留 watch 继续占用。
	if len(targets) == 0 {
		m.watchesMu.Lock()
		m.watches = make(map[string]*watchStat)
		m.watchesMu.Unlock()
	}
	log.Infoln("[GameRoute] enabled=%v targets=%d", enabled, len(targets))
	recordDiag("config_update", "kind=targets enabled=%v targets=%d", enabled, len(targets))
}

// GetTargets 返回当前注册表副本（含扩展字段快照：
// region/current_proxy/current_region/rtt/packets/last_seen）。
// 扩展字段由命中路径 recordTargetHit 在各自 Target 的 extMu 下更新，
// 此处同样持 extMu 读锁快照，避免与命中写入竞态。
func (m *Manager) GetTargets() []Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Target, len(m.targets))
	for i := range m.targets {
		src := &m.targets[i]
		src.primaryMu.Lock()
		cp := src.currentPrimary
		src.primaryMu.Unlock()
		var lastSeen *time.Time
		src.extMu.RLock()
		if src.LastSeen != nil {
			v := *src.LastSeen
			lastSeen = &v
		}
		out[i] = Target{
			ProcessName:    src.ProcessName,
			CIDR:           append([]netip.Prefix(nil), src.CIDR...),
			Proxy:          src.Proxy,
			Fallbacks:      append([]string(nil), src.Fallbacks...),
			autoPicked:     src.autoPicked,
			autoPrimary:    src.autoPrimary,
			currentPrimary: cp,
			Region:         src.Region,
			CurrentProxy:   src.CurrentProxy,
			CurrentRegion:  src.CurrentRegion,
			RTT:            src.RTT,
			Packets:        src.Packets,
			LastSeen:       lastSeen,
		}
		src.extMu.RUnlock()
	}
	return out
}

// findProcess 用于按会话源地址反查进程（PID 优先来源）。
// 包级变量便于单测注入替换，生产环境使用 process.FindProcessName。
var findProcess = func(metadata *C.Metadata) (uint32, string) {
	pid, name, err := process.FindProcessName(
		metadata.NetWork.String(),
		metadata.SrcIP,
		int(metadata.SrcPort),
	)
	if err != nil {
		return 0, ""
	}
	return pid, name
}

// findProcessByPort 按源端口-only 反查进程（TUN 模式专用）：
// TUN 包源 IP 为虚拟网段（198.18.x.x），与 UDP 表真实绑定地址不匹配，
// 仅凭 SrcPort 在 UDP 表中匹配本地端口归属进程（客户端随机端口全局
// 基本唯一，误判概率可忽略）。修复 APEX 等在 TUN 下无法识别的根因。
// 包级变量便于单测注入替换，生产环境使用 process.FindProcessNameByPort。
var findProcessByPort = func(metadata *C.Metadata) (uint32, string) {
	pid, name, err := process.FindProcessNameByPort(
		metadata.NetWork.String(),
		int(metadata.SrcPort),
	)
	if err != nil {
		return 0, ""
	}
	return pid, name
}

// tunVirtualPrefix TUN 虚拟网段（与 excludelayer 同步）：源 IP 落入该段
// 即视为 TUN 模式流量，进程反查只能用 SrcPort-only。
var tunVirtualPrefix = netip.MustParsePrefix("198.18.0.0/15")

// procNameForMetadata 按元数据反查源端口归属进程名（进程名自学习用）：
// TUN 源 IP 为虚拟网段（198.18.0.0/15）时走 findProcessByPort（SrcPort-only），
// 非 TUN 走 findProcess（SrcIP+SrcPort）；反查失败返回 ""（留空=纯流特征
// 识别的无进程来源目标）。注册频率低（仅新目标确认时调用），开销可接受。
func procNameForMetadata(metadata *C.Metadata) string {
	src := metadata.SrcIP.Unmap()
	if src.Is4() && tunVirtualPrefix.Contains(src) {
		_, name := findProcessByPort(metadata)
		return name
	}
	_, name := findProcess(metadata)
	return name
}

// Match 判定 UDP 元数据是否命中 gameroute 快速通道。
// isTUN 为 true 时（TUN 虚拟网段源地址无法反查进程）降级为仅 CIDR 匹配；
// 命中返回当前实际主节点名称（autoPrimary 模式为临时/探测选中的节点，
// 空串表示排队等待选路，不放行直连；显式配置模式返回配置 Proxy），
// 未命中返回 ("", false)，对默认流程零影响。
// 首包完成进程反查后，会话级命中结果由上层 natTable 缓存，无需重复查询。
func (m *Manager) Match(metadata *C.Metadata, isTUN bool) (string, bool) {
	// 铁令 C（2026-10-18 v2.4 批复）：排除端口（8125 遥测/443 QUIC/53 DNS
	// 等）一票否决——严禁 onLane/SessionConn 包装观测（RC12 回归修复：
	// stats 单向流假丢包 85% 污染评分并触发 degraded switch blocked）。
	if IsExcludedAutoRegPort(metadata.DstPort) {
		return "", false
	}
	t, ok := m.MatchTarget(metadata, isTUN)
	if !ok {
		return "", false
	}
	return t.EffectiveProxy(), true
}

// MatchTarget 同 Match，但返回完整 Target（含备用出口 Fallback），
// 供上层在命中后创建预测式切换会话。
func (m *Manager) MatchTarget(metadata *C.Metadata, isTUN bool) (*Target, bool) {
	if !m.Enabled() {
		return nil, false
	}
	// 全程持有读锁：MatchTarget 含 findProcess（进程名填充）与
	// ensureAutoPicked（切片写回），并发 SetTargets / SetAllProxies /
	// SetRTTTable 替换切片会让写回落在即将被替换的旧数组上（写回丢失）。
	m.mu.RLock()
	defer m.mu.RUnlock()
	targets := m.targets
	allProxies := m.allProxies
	rttTable := m.rttTable
	// v2.6 联动 A（2026-10-19 终批复修正一/二）：Fake-IP + 游戏域名会话——
	// 第二刀后主路不回填 realIP，包以域名形态交出口、落地机本地解析。
	// 进场选路多级（保证 GameLane 开启时 100% 接管，绝不滑入普通规则）：
	//   ① 域名段锁 segmentLockHostIdx（赛马赢家 lockSegment 写入，锁定优先）；
	//   ② bestRaceWinner（真实 UDP 测速全局最优，7770 赛马/修正二 STUN 产生）；
	//   ③ laneChampionsLocked 的 HK 区冠军（开机初期赛马在途的保底）；
	//   ④ 五区池第 1 个可用节点（HK 无冠军时）；
	//   ⑤ 仅当整个五区池为空（Q8 极端）才弃权落规则。
	// 锁序（修正二）：本函数已持 m.mu.RLock——① getSegmentLockByHost 用独立
	// segmentLockMu、② bestRaceWinnerProxy 用独立 bestRaceMu、③④ 走锁内直读
	// 变体 laneChampionsLocked；严禁调 LaneChampions/SnapshotRTT（内部再取
	// m.mu.RLock，写者等待时构成死锁环）。会话级稳定性：Match 首包命中后由
	// 上层 natTable 缓存，后续包不重查（铁律二 recv≥1 不换节点语义不变）。
	if metadata.DNSMode == C.DNSFakeIP && metadata.Host != "" && m.IsGameDomain(metadata.Host) {
		pick := func(name string) (*Target, bool) {
			if name == "" {
				return nil, false
			}
			return &Target{Proxy: name, currentPrimary: name}, true
		}
		if e := m.getSegmentLockByHost(metadata.Host); e != nil {
			if t, ok := pick(e.Proxy); ok {
				return t, true
			}
		}
		if px, ok := m.bestRaceWinnerProxy(); ok {
			if t, ok2 := pick(px); ok2 {
				return t, true
			}
		}
		champs := m.laneChampionsLocked()
		if n := champs["HK"]; n != "" {
			if t, ok := pick(n); ok {
				return t, true
			}
		}
		// ④ HK 无冠军 → 五区池第 1 个可用节点（HK,TW,SG,JP,KR 顺序）
		for _, region := range []string{"HK", "TW", "SG", "JP", "KR"} {
			members := FilterByRegion(allProxies, "", region)
			if len(members) > 0 {
				if t, ok := pick(members[0]); ok {
					return t, true
				}
			}
		}
		return nil, false // ⑤ 五区池空（Q8 极端）
	}
	if len(targets) == 0 {
		return nil, false
	}

	processName := metadata.Process
	if !isTUN && processName == "" {
		// PID 优先：Process 未填充时按会话源地址反查一次进程
		if _, name := findProcess(metadata); name != "" {
			processName = name
		}
	}

	for i := range targets {
		t := &targets[i]
		if !isTUN && t.ProcessName != "" && t.ProcessName == processName {
			// 国内游戏 UDP 直连（domestic-direct，指令 2026-10-21）：目标 IP
			// 属大陆路由表（v2.12 清单4：GeoIP 换内置 chnroutes）且未命中已知
			// 游戏段表 → 不接管，视为未命中滑落普通规则（直连）。段表命中
			// 永不直连；海外行为零变化；fakecn_override 记忆条目按海外处理。
			if isChinaMainlandIP(metadata.DstIP) && !SegmentTable().MatchIP(metadata.DstIP) &&
				!m.hasFakeCNOverride(metadata.DstIP.String()) {
				recordDiag("domestic_direct", "target match skipped (china route direct): process=%s dst=%s", t.ProcessName, metadata.DstIP)
				// 进程目标明确即"已确认游戏进程"：登记反悔观察窗，直连 3s
				// 零回包或最小 RTT>70ms 即反悔接管并写持久 override（清单5）。
				m.startFakeCNWatch(metadata.DstIP.String(), t.ProcessName, metadata.DstPort)
				return nil, false
			}
			m.ensureAutoPicked(t, metadata.DstIP, metadata.Host, allProxies, rttTable)
			px := t.EffectiveProxy()
			if px == "" {
				// 游戏加速流量绝不直连：空出口回退默认出口，
				// 默认出口也缺失时保持上一个可用出口。
				px = m.safeProxy("")
				if px == "" {
					log.Errorln("[GameRoute] no proxy available, holding (%s)", t.ProcessName)
					recordDiag("holding", "no proxy available, target=%s", t.ProcessName)
				}
			}
			m.rememberProxy(px)
			m.rememberTargetProxy(t.ProcessName, px)
			m.recordTargetHit(t, metadata.DstIP, px, rttTable)
			log.Infoln("[GameRoute] matched target %s -> proxy %s (fallbacks=%d)",
				t.ProcessName, px, len(t.Fallbacks))
			recordDiag("target_match", "target=%s proxy=%s fallbacks=%d", t.ProcessName, px, len(t.Fallbacks))
			return t, true
		}
		if len(t.CIDR) > 0 && cidrContains(t.CIDR, metadata.DstIP) {
			m.ensureAutoPicked(t, metadata.DstIP, metadata.Host, allProxies, rttTable)
			hit := ""
			for _, c := range t.CIDR {
				if cidrContains([]netip.Prefix{c}, metadata.DstIP) {
					hit = c.String()
					break
				}
			}
			px := t.EffectiveProxy()
			if px == "" {
				// 游戏加速流量绝不直连：空出口回退默认出口，
				// 默认出口也缺失时保持上一个可用出口。
				px = m.safeProxy("")
				if px == "" {
					log.Errorln("[GameRoute] no proxy available, holding (%s)", hit)
				}
			}
			m.rememberProxy(px)
			m.rememberTargetProxy(hit, px)
			m.recordTargetHit(t, metadata.DstIP, px, rttTable)
			log.Infoln("[GameRoute] matched target %s -> proxy %s (fallbacks=%d)",
				hit, px, len(t.Fallbacks))
			recordDiag("target_match", "target=%s proxy=%s fallbacks=%d", hit, px, len(t.Fallbacks))
			return t, true
		}
	}
	return nil, false
}

// ensureAutoPicked 在命中时保证候选池可用：
//   - Proxy 为空或 "auto" → v2 Auto-Pick Primary：标记 autoPrimary，
//     立即选临时主节点进场，候选池自动生成（见 ensureAutoPrimary）；
//   - 配置未写 fallbacks（且非自动圈选标记）→ 自动圈选并标记；
//   - 已是自动圈选池且到达刷新间隔 → 按最新 RTT 重新圈选（淘汰劣化、补入优节点）；
//   - 配置写了 fallbacks（autoPicked=false）→ 一律不动，配置优先。
func (m *Manager) ensureAutoPicked(t *Target, dstIP netip.Addr, host string, allProxies []string, rttTable map[string]int) {
	if t.Proxy == "" || t.Proxy == "auto" {
		m.ensureAutoPrimary(t, dstIP, host, allProxies, rttTable)
		return
	}
	// F5：同 ensureAutoPrimary，写入纳入 primaryMu 并预占防并发重复圈选。
	t.primaryMu.Lock()
	needPool := !t.autoPicked && len(t.Fallbacks) == 0
	if needPool {
		t.autoPicked = true
	}
	doRefresh := !needPool && t.autoPicked && m.maybeRefresh(time.Now().UnixMilli())
	t.primaryMu.Unlock()
	if needPool {
		pool := m.autoPickFallbacks(t.Proxy, allProxies, rttTable)
		t.primaryMu.Lock()
		t.Fallbacks = pool
		t.primaryMu.Unlock()
		m.maybeRefresh(time.Now().UnixMilli()) // 记录刷新基准时间
		return
	}
	if doRefresh {
		pool := m.autoPickFallbacks(t.Proxy, allProxies, rttTable)
		log.Infoln("[GameRoute] refresh start candidates=%d", len(pool))
		t.primaryMu.Lock()
		t.Fallbacks = pool
		t.primaryMu.Unlock()
	}
}

// ensureAutoPrimary v2 Auto-Pick Primary：保证自动主节点模式可用。
// 首次命中瞬间立即选临时主节点进场，不等待任何探测：
//   - 记忆条目有 PreferredProxy → 直接用（最高优先）；
//   - 无记忆 → GeoIP 按目标 IP 查地区 → 筛同地区节点 → RTT 最低/随机该地区池；
//   - 该地区无节点 → 全局 RTT 最优 → 默认出口（绝不直连）；
//
// 候选池取同地区 RTT top N（无 RTT 数据时随机该地区池，地区缺失退化全局池），
// 随 60s 懒测周期刷新；同地区池全部劣化（>300ms）时回退全局 RTT 最优。
func (m *Manager) ensureAutoPrimary(t *Target, dstIP netip.Addr, host string, allProxies []string, rttTable map[string]int) {
	t.primaryMu.Lock()
	t.autoPrimary = true
	if t.currentPrimary == "" {
		// Q3③/需求 C + 2026-10-18 主路对齐（批复 Q-E 方案 A）：赛马锁死优先
		// ——查询顺序：域名索引（fake-ip 模式 DstIP 被 preHandleMetadata
		// 清空时的唯一可用键，纯内存零网络）→ realIP/24 索引（DstIP 有效
		// 时）→ 原记忆/GeoIP 链。锁死健康（TTL 30min/探测连败）由
		// getSegmentLock* 惰性裁决（死六四①③）。
		var ent *segmentLockEntry
		if host != "" {
			ent = m.getSegmentLockByHost(host)
		}
		if ent == nil && dstIP.IsValid() {
			if seg := segmentKey24(dstIP.String()); seg != "" {
				ent = m.getSegmentLock(seg)
			}
		}
		if ent != nil {
			t.currentPrimary = ent.Proxy
			cur := ent.Proxy
			t.primaryMu.Unlock()
			log.Infoln("[GameRoute] temp primary = %s (segment-lock rtt=%dms host=%s)", cur, ent.RTTMs, host)
			recordDiag("temp_primary", "reason=segment-lock proxy=%s rtt=%dms host=%s", cur, ent.RTTMs, host)
			RecordM3Active(cur)
			m.rememberProxy(cur)
			// 候选池照常生成（锁死节点劣化时的兜底链仍可用）
			t.primaryMu.Lock()
			needPool := !t.autoPicked && len(t.Fallbacks) == 0
			if needPool {
				t.autoPicked = true
			}
			t.primaryMu.Unlock()
			if needPool {
				pool := m.autoPickPrimaryPool(dstIP, allProxies, rttTable)
				t.primaryMu.Lock()
				t.Fallbacks = pool
				t.primaryMu.Unlock()
			}
			return
		}
	}
	if t.currentPrimary == "" {
		// v2.4 第二刀（2.3，Q-I2 优先级②）：进场选主第一优先 = 全局赛马
		// 实测最优（bestRaceWinner，10min 内新鲜）——段锁之后、记忆之前。
		if bw, ok := m.bestRaceWinnerProxy(); ok {
			t.currentPrimary = bw
			cur := bw
			t.primaryMu.Unlock()
			log.Infoln("[GameRoute] temp primary = %s (best-race-winner)", cur)
			recordDiag("temp_primary", "reason=best-race-winner proxy=%s", cur)
			RecordM3Active(cur)
			t.primaryMu.Lock()
			needPool := !t.autoPicked && len(t.Fallbacks) == 0
			if needPool {
				t.autoPicked = true
			}
			t.primaryMu.Unlock()
			if needPool {
				pool := m.autoPickPrimaryPool(dstIP, allProxies, rttTable)
				t.primaryMu.Lock()
				t.Fallbacks = pool
				t.primaryMu.Unlock()
			}
			return
		}
		// 2.5（谷歌强制）：rtt-lowest 仅当数据源为 7770 赛马实测时可用——
		// 只喂 race 源条目；race 源为空时 pickPrimaryTemp 的 rtt 分支自然
		// 回退 memory/pool-order，Cloudflare urltest 数据不参与进场裁决
		// （反向验收：recordPrimarySnapshot/日志可查 source）。
		// Locked 变体：本函数全部调用方（MatchTarget/RegisterTargetIPTrusted/
		// matchTargetTCP）均持有 m.mu ≥RLock（既定锁序 m.mu→primaryMu），锁内直读。
		rttTable = m.raceOnlyRTTTableLocked()
		// v2.13 第二刀（2.1，谷歌⑤）：第 5 档兜底需要"全量实测表"（含 urltest
		// 经 MergeProbeResults 校正后的值）——虚幻引擎类游戏（Fortnite）没有
		// 7770 测速模板，race 源长期空窗，若进场只认 race 表就会退化成盲选。
		// 全量表仅用于第 5 档及退避链的"有实测值"判定，race 源优先级不变。
		fullTable := m.rttTableLockedCopy()
		t.currentPrimary = m.pickPrimaryTempFull(dstIP, allProxies, rttTable, fullTable)
		cur := t.currentPrimary
		t.primaryMu.Unlock()
		if cur != "" {
			// 进场临时主节点立即同步全局 current_proxy（不算切换次数）
			RecordM3Active(cur)
		}
	} else {
		t.primaryMu.Unlock()
	}
	// F5：Fallbacks/autoPicked 的写入统一纳入 primaryMu（原实现在仅持
	// m.mu 读锁的 MatchTarget 路径下，并发首包会产生数据竞争），并以
	// autoPicked 预占防并发首包重复圈选。
	t.primaryMu.Lock()
	needPool := !t.autoPicked && len(t.Fallbacks) == 0
	if needPool {
		t.autoPicked = true // 预占，防并发首包重复圈选
	}
	doRefresh := !needPool && t.autoPicked && m.maybeRefresh(time.Now().UnixMilli())
	t.primaryMu.Unlock()
	if needPool {
		pool := m.autoPickPrimaryPool(dstIP, allProxies, rttTable)
		t.primaryMu.Lock()
		t.Fallbacks = pool
		t.primaryMu.Unlock()
		m.maybeRefresh(time.Now().UnixMilli()) // 记录刷新基准时间
		m.probeAndSettle(t, dstIP, allProxies) // v6.5: 命中即探测候选池，不等流量
		return
	}
	if doRefresh {
		pool := m.autoPickPrimaryPool(dstIP, allProxies, rttTable)
		log.Infoln("[GameRoute] refresh start candidates=%d", len(pool))
		t.primaryMu.Lock()
		t.Fallbacks = pool
		t.primaryMu.Unlock()
		m.probeAndSettle(t, dstIP, allProxies) // v6.5: 周期刷新后同样立即探测
	}
}

// pickPrimaryTemp 选择进场临时主节点（Auto-Pick Primary）：
// 优先级链（v6.6→v6.11 记忆优先+跨区切换+服务器侧优先）：
//  1. 记忆 PreferredProxy → 直接用（最高优先，含 region_actual 区域信息）
//     1.1) 记忆 region_actual → 优先选记忆区 + 邻近区 + 港台兜底的节点池
//  2. 服务器 GeoIP 地区：同地区池内 RTT 最低，无 RTT 则随机该地区池
//  3. 退避链：全局 RTT 最低 → 默认出口 → 上一出口 → 随机
//
// 服务器区明确（含段表命中）时不优先选玩家侧港台，仅当服务器区未知/不可信
// 且玩家侧有港台节点时才使用港台兜底。
func (m *Manager) pickPrimaryTemp(dstIP netip.Addr, allProxies []string, rttTable map[string]int) string {
	return m.pickPrimaryTempFull(dstIP, allProxies, rttTable, rttTable)
}

// pickPrimaryTempFull 为 v2.13 第二刀后的完整进场选主实现：
// raceTable 仅含 7770 赛马实测（第 1~4 档与既有语义不变），fullRTT 为全量
// 实测表（含 urltest 经 MergeProbeResults 校正后的值）。第 5 档为常态档：
// 只要 fullRTT 存在已实测的 HK/TW 节点就优先选港台最低（谷歌⑤"进场入口
// 永远优先已实测低延迟港台"）；服务器区已定且区内有 race 实测时由 GeoIP
// 分支先命中（区内优先，v2.12 语义保持）。调用方（ensureAutoPrimary）传入
// raceOnly 表 + 全量表；其他路径（TCP 固定通道/TCP 主节点）两表一致，第 5
// 档同样常态生效（有港台实测优先，不再落入退避链/先测再进）。
func (m *Manager) pickPrimaryTempFull(dstIP netip.Addr, allProxies []string, rttTable, fullRTT map[string]int) string {
	if fullRTT == nil {
		fullRTT = rttTable
	}
	// 1) 记忆条目有 PreferredProxy → 直接用（最高优先）
	if dstIP.IsValid() {
		if px := m.lookUpPreferredProxy(dstIP.String()); px != "" {
			log.Infoln("[GameRoute] temp primary = %s (memory preferred)", px)
			recordDiag("temp_primary", "reason=memory-preferred proxy=%s dst=%s", px, dstIP.String())
			m.recordPrimarySnapshot(px, "preferred-proxy", rttTable)
			return px
		}
	}

	// 1.1) 记忆 region_actual → 优先取该区 + 邻近区 + 港台兜底
	var regionActual = ""
	if dstIP.IsValid() {
		if r := m.lookUpRegionActual(dstIP.String()); r != "" {
			regionActual = r
			log.Infoln("[GameRoute] temp primary from memory region %s for %s", regionActual, dstIP.String())
		}
	}
	if regionActual != "" {
		combined := m.combineRegionNodes(allProxies, rttTable, regionActual, "HK", "TW")
		if len(combined) == 0 {
			// I 修复：记忆区节点缺失（改名/订阅更新），安全回退 GeoIP/退避链
			log.Infoln("[GameRoute] memory region %s pool empty, fallback to geoip", regionActual)
			goto geoipBranch
		}
		if best, ok := lowestRtt(combined, rttTable); ok {
			log.Infoln("[GameRoute] temp primary = %s (memory-region %s-rtt)", best, regionActual)
			recordDiag("temp_primary", "reason=memory-region-rtt proxy=%s region=%s dst=%s", best, regionActual, dstIP.String())
			if dstIP.IsValid() {
				m.rememberRegionActual(dstIP.String(), regionActual)
			}
			m.recordPrimarySnapshot(best, "memory-region", rttTable)
			return best
		}
		// v2.13 第二刀（2.2）：记忆区池内无实测值时同样禁止随机盲选——
		// 随机到 rtt=0 节点就是本次 Fortnite 189ms 的直接出口。改为下探
		// GeoIP 区选 / 第 5 档全量实测港台最低 / 退避链（仅认实测值）。
		if dstIP.IsValid() {
			m.rememberRegionActual(dstIP.String(), regionActual)
		}
		log.Infoln("[GameRoute] memory region %s pool has no measured node, defer to measured tiers", regionActual)
		recordDiag("temp_primary", "reason=memory-region-no-measured region=%s dst=%s", regionActual, dstIP.String())
		goto geoipBranch
	}

	// 2) 服务器 GeoIP 地区（geoipBranch）
geoipBranch:
	// v6.13 修复 D：无记忆新 IP 的 GeoIP 兜底加区约束——仅亚洲信任区
	// （HK/TW/MO/SG/JP/KR 等）或段表命中才按 GeoIP 定区选池；AWS 全球段
	// （216.244.0.0/16 等）GeoIP 国家码不可信，US/DE/NL/GB 等非亚洲区
	// 一律不作为定区依据，直接落入退避链（全局 RTT 最低），避免无记忆
	// 新 IP 被误选到欧美节点（如 Germany01 source=geoip）。
	if dstIP.IsValid() {
		if region := geoipCountryFor(dstIP); region != "" && (isTrustedServerCountry(region) || (SegmentTable().MatchIP(dstIP) && SegmentTable().RegionTrustedFor(dstIP))) { // F11: 云段不算区可信
			regional := FilterByRegion(allProxies, "", region)
			log.Infoln("[GameRoute] geoip select %s for %s (pool=%d)", region, dstIP.String(), len(regional))
			if len(regional) > 0 {
				best, bestRtt := "", 0
				for _, n := range regional {
					rt, ok := rttTable[n]
					if !ok || rt <= 0 {
						continue
					}
					if best == "" || rt < bestRtt {
						best, bestRtt = n, rt
					}
				}
				if best != "" {
					log.Infoln("[GameRoute] temp primary = %s (geoip-rtt-lowest)", best)
					recordDiag("temp_primary", "reason=geoip-rtt-lowest proxy=%s region=%s dst=%s", best, region, dstIP.String())
					m.recordPrimarySnapshot(best, "geoip", rttTable)
					return best
				}
				// v2.13 第二刀（2.2）：区内节点全无实测数据时**禁止随机盲选**
				// （Fortnite 被随机到 Japan 06 rtt=0 的直接出口）。继续下探
				// 第 5 档（全量实测港台最低）/ 退避链。
				log.Infoln("[GameRoute] geoip %s pool has no measured node, defer to measured tiers", region)
				recordDiag("temp_primary", "reason=geoip-no-measured region=%s dst=%s", region, dstIP.String())
			}
			// geoip pool=0：优先亚洲低延迟节点
			if asia := asiaLowLatencyPool(allProxies, rttTable); len(asia) > 0 {
				best, bestRtt := "", 0
				for _, n := range asia {
					rt, ok := rttTable[n]
					if !ok || rt <= 0 {
						continue
					}
					if best == "" || rt < bestRtt {
						best, bestRtt = n, rt
					}
				}
				if best != "" {
					log.Infoln("[GameRoute] temp primary = %s (asia-low-latency)", best)
					recordDiag("temp_primary", "reason=asia-low-latency proxy=%s dst=%s", best, dstIP.String())
					m.recordPrimarySnapshot(best, "geoip", rttTable)
					return best
				}
				// v2.13 第二刀（2.2）：亚洲池同样禁盲选——无实测值则下探
				// 第 5 档（全量实测港台最低）/ 退避链。
				log.Infoln("[GameRoute] asia pool has no measured node, defer to measured tiers")
				recordDiag("temp_primary", "reason=asia-no-measured dst=%s", dstIP.String())
			}
		} else if region := geoipCountryFor(dstIP); region != "" {
			log.Infoln("[GameRoute] geoip %s not trusted for %s (no memory/segment), skip regional pick", region, dstIP.String())
		} else {
			log.Infoln("[GameRoute] geoip not found for %s", dstIP.String())
		}
	}

	// 5) v2.13 第二刀（谷歌⑤）：race 空窗时全量实测表中 HK/TW 区 RTT 最低节点。
	// 虚幻引擎类游戏（Fortnite）无 7770 模板 → race 源空窗，第 4 档与
	// geoip 分支都拿不到数据；此时必须用 urltest 已实测（且经
	// MergeProbeResults 开销校正）的港台低延迟节点兜底，而不是退化盲选。
	// 玩家侧近距约束由此落地：大陆玩家进场入口在 race 空窗时优先已实测港台。
	// v2.13 修订（放开常态档语义的正确落点）：不限定"服务器区已定但全区无
	// 实测"的空窗场景——服务器区未知/不可信时（如 AWS 全球段、欧美服）
	// 同样优先港台实测兜底，不再落入退避链/先测再进；服务器区已定且区内
	// 有 race 实测时，GeoIP 分支先命中（区内优先，v2.12 语义保持），本档
	// 自然到不了。
	// race 有实测永远优先：race 为 7770 真实赛马数据（更可信），urltest
	// 仅为 HTTP 延迟校正——故本档仅在 raceOnly 表全空时启用，一旦表内
	// 存在任何实测（哪怕非港台），第 6 档退避链（race 全局最低）接棒，
	// 避免港台 urltest 压过更优的 race 实测（如港台 10ms vs 日本 5ms）。
	// 玩家侧前提（谷歌铁律适用域）：玩家在亚洲或玩家定位未完成时才启用
	// 港台兜底；玩家明确位于非亚洲区（US 等）时港台并非近距，维持原语义
	// 交退避链（全局 race 实测最低 / 先测再进），不做港台兜底。
	playerRegion := PlayerRegion()
	playerInAsia := playerRegion == "Asia" || playerRegion == ""
	if playerInAsia {
		raceHasMeasured := false
		for _, rt := range rttTable {
			if rt > 0 {
				raceHasMeasured = true
				break
			}
		}
		if !raceHasMeasured {
			if best, bestRtt, region := lowestRttByRegions(allProxies, fullRTT, "HK", "TW"); best != "" && bestRtt < urltestFallbackMaxRttMs {
				log.Infoln("[GameRoute] temp primary = %s (%s-urltest-lowest rtt=%dms)", best, region, bestRtt)
				recordDiag("temp_primary", "reason=urltest-lowest proxy=%s region=%s rtt=%dms dst=%s", best, region, bestRtt, dstIP.String())
				m.recordPrimarySnapshot(best, "urltest-lowest", fullRTT)
				return best
			}
		}
	}

	// 6) 退避链：全局 RTT 最低（只认有实测值 >0 的节点）→ 无实测则返回空串。
	// v2.13 第二刀（2.2）铁律：任何环节不得直接产出 rtt==0 的无实测节点
	// 作为主节点进场（Fortnite 被随机到 Japan 06 rtt=0 的根因）。全表无
	// 任何实测值时返回空串，交由 ensureAutoPrimary 的 probeAndSettle
	// "先测再进"（调用方 safeProxy 保持默认/上一出口，绝不直连断流）。
	// 只认 raceTable 的实测值：Cloudflare urltest 数据不得决定进场主节点
	// （retarget_v24 反向验收红线），urltest 只在第 5 档空窗兜底时受限使用。
	best, bestRtt := "", 0
	for _, n := range allProxies {
		rt, ok := rttTable[n]
		if !ok || rt <= 0 {
			continue
		}
		if best == "" || rt < bestRtt {
			best, bestRtt = n, rt
		}
	}
	if best != "" {
		log.Infoln("[GameRoute] temp primary = %s (rtt-lowest rtt=%dms)", best, bestRtt)
		recordDiag("temp_primary", "reason=rtt-lowest proxy=%s rtt=%dms dst=%s", best, bestRtt, dstIP.String())
		m.recordPrimarySnapshot(best, "fallback", rttTable)
		return best
	}
	log.Infoln("[GameRoute] no measured node for %s, defer to probe-first entry (禁盲选)", dstIP.String())
	recordDiag("temp_primary", "reason=no-measured-node defer=probe-first dst=%s", dstIP.String())
	return ""
}

// combineRegionNodes 合并多个地区标签的节点，按 RTT 升序。
func (m *Manager) combineRegionNodes(allProxies []string, rttTable map[string]int, tags ...string) []string {
	live := liveNodes(allProxies, rttTable)
	out := make([]string, 0, len(live))
	for _, tag := range tags {
		out = append(out, regionNodes(live, rttTable, tag)...)
	}
	// 去重
	seen := make(map[string]bool)
	unique := make([]string, 0, len(out))
	for _, n := range out {
		if !seen[n] {
			seen[n] = true
			unique = append(unique, n)
		}
	}
	return unique
}

// autoPickPrimaryPool 生成 Auto-Pick Primary 模式候选池（v6.2 玩家位置引导）：
// 候选池构成以"玩家侧就近优先 + 服务器侧补充"为准：内核启动时直连公网
// 出口 IP 定位玩家国家（见 player_loc.go），玩家在哪侧就近节点优先进池；
// 再按游戏服务器 GeoIP 地区补充（服务器在北美则加美加代表，防亚洲玩家
// 连北美服务器无解），最终由探测真实 RTT 裁决选路（分数最高为 primary，
// 其余为 fallbacks）。
//   - 玩家在亚洲（最常见）：香港全部 + 台湾全部全量进池（港台永远在，
//     离亚洲玩家最近，全量让探测挑）；再补新加坡/日本/韩国各 1-2 个
//     代表 + 服务器侧补充（服务器在北美/欧洲/大洋洲/中东时该地区代表
//     也进池）；
//   - 玩家在北美：美加全量进池，补港台新日韩代表 + 服务器侧补充；
//   - 玩家在欧洲：英德法荷俄全量进池，补港台新日韩 + 美加代表 + 服务器
//     侧补充；
//   - 玩家位置未知（定位失败/未完成）：按服务器地区引导（港台全量 +
//     日新韩代表 + 欧北美兜底，同 v6.1）。
//
// 池子上限 maxCandidatePool（12 个）；任何路径生成后不足 minCandidatePool
// （5 个）从全局活节点按 RTT 升序补足（禁枯竭）。池内无 DIRECT、无死节点。
const minCandidatePool = 5
const maxCandidatePool = 12

func (m *Manager) autoPickPrimaryPool(dstIP netip.Addr, allProxies []string, rttTable map[string]int) []string {
	// 1) 服务器地区判定（v6.12）：记忆 RegionActual → 段表命中 → GeoIP
	serverRegion := ""
	geo := ""
	if dstIP.IsValid() {
		// 1a) 记忆优先：该 IP 有 region_actual 记忆则直接用（最可信，
		// 来自历史真实选路结算/跨区切换的沉淀）
		if region := m.lookUpRegionActual(dstIP.String()); region != "" {
			serverRegion = region
			log.Infoln("[GameRoute] server region from memory: %s", serverRegion)
		}
	}
	if serverRegion == "" && dstIP.IsValid() {
		// 1b) 段表命中 → 已知游戏服务器，GeoIP 定区可信，作第二优先
		if SegmentTable().MatchIP(dstIP) {
			geo = geoipCountryFor(dstIP)
			if geo != "" {
				serverRegion = serverRegionOf(geo)
				log.Infoln("[GameRoute] server region from segment+geoip: %s", serverRegion)
			}
		}
	}
	if serverRegion == "" && dstIP.IsValid() {
		// 1c) GeoIP 兜底：普通外部 IP 也尝试定区（未命中段表但地区明确）
		geo = geoipCountryFor(dstIP)
		if geo != "" {
			serverRegion = serverRegionOf(geo)
		}
	}
	display := "未知"
	switch {
	case serverRegion != "":
		display = serverRegion
	case geo != "":
		display = "其他(" + geo + ")"
	}
	// 1.1) 玩家地区：启动时直连公网出口 IP 定位（未完成/未知为 ""）
	playerRegion := PlayerRegion()
	playerC := PlayerCountry()
	log.Infoln("[GameRoute] server region = %s (dst=%s geo=%s) player=%s/%s",
		display, dstIP.String(), geo, displayPlayerCountry(playerC), playerRegion)

	// 2) 服务器区信任判定 + 构建候选池
	live := liveNodes(allProxies, rttTable)
	var trustedServer bool
	segHit := false
	if dstIP.IsValid() {
		geo = geoipCountryFor(dstIP)
		// 内置段表命中 → 已知游戏服务器（GeoIP 定区可信）：
		// 区明确即按服务器侧就近优先（该区节点全量 + 港台兜底），
		// 不再仅凭 isTrustedServerCountry 的亚洲白名单判定。
		segHit = SegmentTable().MatchIP(dstIP)
		trustedServer = isTrustedServerCountry(geo) || (segHit && geo != "" && SegmentTable().RegionTrustedFor(dstIP))
	}
	log.Infoln("[GameRoute] server region = %s (dst=%s geo=%s) player=%s/%s trusted=%v seg=%v",
		display, dstIP.String(), geo, displayPlayerCountry(playerC), playerRegion, trustedServer, segHit)

	pool := buildPlayerPoolV66(playerRegion, serverRegion, geo, live, rttTable, trustedServer, segHit)
	// 3) 下限保护：不足 minCandidatePool 从全局活节点按 RTT 升序补足
	pool = ensureMinCandidatePool(pool, allProxies, rttTable, minCandidatePool)
	m.recordCandidateSnapshot(pool, rttTable)
	log.Infoln("[GameRoute] candidate pool (%d): %s", len(pool), strings.Join(pool, " "))
	return pool
}

// buildPlayerPoolV66 多区候选池生成（v6.6）：判定区节点优先 + 邻近区次之 + 港台兜底。
// 信任区（GeoIP 定区 + 段表命中）直接复用 buildServerPool 的已验证验收行为：
// 服务器大区对应核心全量 + 邻近/亚洲代表（港台新日韩等），保证候选池构成
// 不回归（v6.8 验收：港台全量核心 + 新日韩代表）。
func buildPlayerPoolV66(playerRegion, serverRegion, geo string, live []string, rttTable map[string]int, trustedServer, segHit bool) []string {
	// 信任区：GeoIP 定区 + 段表命中 → 复用 buildServerPool（核心全量 + 代表填充）
	if trustedServer {
		if serverRegion != "" {
			return buildServerPool(serverRegion, live, rttTable)
		}
		// 大区无法判定但 GeoIP 有国家码：港台全量 + 新日韩代表兜底
		core := regionNodes(live, rttTable, "HK", "TW")
		reps := fillReps(live, rttTable, maxCandidatePool-len(core), "SG", "JP", "KR")
		return append(core, reps...)
	}

	// 非信任区：fallback 到 playerRegion 或默认
	return buildPlayerPool(playerRegion, serverRegion, live, rttTable, trustedServer)
}

// unique 对字符串切片去重
func unique(slice []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// buildServerPool 按服务器大区生成候选池（v6.1 规则）：
// 全量核心（港台/本地区节点）绝不裁剪；代表部分按"每地各 1 个优先、
// 富余再补第 2 个"的顺序填充到 maxCandidatePool（12）上限。
//   - 亚洲分支：核心 = 香港全部 + 台湾全部；代表 = 新加坡/日本/韩国、
//     欧洲（英德法荷俄）、北美（美加）；
//   - 其他地区分支：核心 = 该地区全量；代表 = 邻近地区 + 亚洲（港台新日韩）；
//   - 无法判定分支：核心 = 港台全量；代表 = 全球主要地区（日新韩英德法
//     美加澳中东）。
func buildServerPool(serverRegion string, live []string, rttTable map[string]int) []string {
	switch serverRegion {
	case serverRegionAsia:
		// 港台全量进池（亚洲服务器的最优候选区，全部让探测挑；
		// regionNodes 保留无 RTT 节点，核心不因 RTT 缺失被裁剪）
		core := regionNodes(live, rttTable, "HK", "TW")
		// 亚洲代表优先：新加坡/日本/韩国先填满剩余容量（保证池内
		// 亚洲节点数 ≥ 欧美节点数，亚洲最优候选不被欧美挤占）；
		// 欧美仅作代表拿剩余容量（防地区误判兜底），受 maxCandidatePool
		// 硬上限约束，绝不作为核心全量进池。
		room := maxCandidatePool - len(core)
		asiaReps := fillReps(live, rttTable, room, "SG", "JP", "KR")
		out := append(append([]string(nil), core...), asiaReps...)
		left := maxCandidatePool - len(out)
		if left > 0 {
			euNaTags := append([]string{}, regionTagsOf(serverRegionEU)...)
			euNaTags = append(euNaTags, regionTagsOf(serverRegionNA)...)
			out = append(out, fillReps(live, rttTable, left, euNaTags...)...)
		}
		return out
	case serverRegionEU, serverRegionNA, serverRegionOC, serverRegionME:
		// 该地区节点优先（全量；regionNodes 保留无 RTT 节点，核心不因
		// RTT 缺失被裁剪；cappedPool 兜底保证核心过多时也不超上限）
		core := regionNodes(live, rttTable, regionTagsOf(serverRegion)...)
		// 邻近地区 1-2 个代表 + 亚洲（港台新日韩）各 1-2 个代表
		nb := nearbyServerRegions(serverRegion)
		nbTags := append([]string{}, regionTagsOf(nb[0])...)
		nbTags = append(nbTags, regionTagsOf(nb[1])...)
		nbTags = append(nbTags, "HK", "TW", "SG", "JP", "KR")
		reps := fillReps(live, rttTable, maxCandidatePool-len(core), nbTags...)
		return cappedPool(core, reps)
	default:
		// 地区无法判定/无对应节点：港台全量 + 全球主要地区代表各 1-2 个
		core := regionNodes(live, rttTable, "HK", "TW")
		reps := fillReps(live, rttTable, maxCandidatePool-len(core),
			"SG", "JP", "KR", "GB", "DE", "FR", "US", "CA", "AU",
			"AE", "SA", "TR", "IL")
		return append(core, reps...)
	}
}

// fillReps 按标签顺序填充代表节点，受 room 上限约束：
// 第一轮每组各取 1 个（保证"日新韩各 1 个代表"的验收底线），room 富余时
// 第二轮按组顺序补每组第 2 个，直到 room 填满或代表耗尽。
func fillReps(live []string, rttTable map[string]int, room int, tags ...string) []string {
	if room <= 0 {
		return nil
	}
	first := repPerGroup(live, rttTable, 1, tags...)
	if len(first) >= room {
		return first[:room]
	}
	out := append([]string(nil), first...)
	left := room - len(out)
	// 第二轮：补每组第 2 个（组内按 RTT 升序，排除已在池中的第 1 个）
	second := repPerGroup(live, rttTable, 2, tags...)
	for _, n := range second {
		dup := false
		for _, o := range out {
			if o == n {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		out = append(out, n)
		left--
		if left <= 0 {
			break
		}
	}
	return out
}

// asiaLowLatencyPool 从全局节点中筛出亚洲低延迟节点（香港/新加坡/台湾），
// 过滤非 DIRECT、过滤死节点（RTT 有记录且 <=0 视为死节点），
// 按已有 RTT 数据升序排序；无 RTT 数据的节点排在后面（探测校正阶段补齐）。
func asiaLowLatencyPool(allProxies []string, rttTable map[string]int) []string {
	asia := make([]string, 0, len(allProxies))
	for _, n := range allProxies {
		if n == "" || n == "DIRECT" {
			continue
		}
		if rt, ok := rttTable[n]; ok && rt <= 0 {
			continue // 死节点（探测失败/无效 RTT）
		}
		region, ok := extractRegionTag(n)
		if !ok {
			continue
		}
		if region != "HK" && region != "SG" && region != "TW" {
			continue
		}
		asia = append(asia, n)
	}
	// 有 RTT 数据的按升序排前，无 RTT 数据排后（保持原有先后顺序）
	sort.SliceStable(asia, func(i, j int) bool {
		ri, oki := rttTable[asia[i]]
		rj, okj := rttTable[asia[j]]
		if !oki {
			return false
		}
		if !okj {
			return true
		}
		return ri < rj
	})
	return asia
}

// ensureMinCandidatePool 候选池下限保护：不足 min 个时从全局节点中按 RTT
// 升序补足活节点（过滤非 DIRECT、过滤死节点），确保候选池 ≥ min（默认 5），
// 禁止枯竭到 1 个；全局活节点本身不足时按实际数量返回（不硬凑）。
func ensureMinCandidatePool(pool []string, allProxies []string, rttTable map[string]int, min int) []string {
	if min < minCandidatePool {
		min = minCandidatePool
	}
	if len(pool) >= min {
		return pool
	}
	seen := make(map[string]bool, len(pool))
	for _, n := range pool {
		seen[n] = true
	}
	// 全局活节点：非 DIRECT、非死节点，按 RTT 升序
	rest := make([]string, 0, len(allProxies))
	for _, n := range allProxies {
		if n == "" || n == "DIRECT" || seen[n] {
			continue
		}
		if rt, ok := rttTable[n]; ok && rt <= 0 {
			continue // 死节点
		}
		rest = append(rest, n)
	}
	sort.SliceStable(rest, func(i, j int) bool {
		ri, oki := rttTable[rest[i]]
		rj, okj := rttTable[rest[j]]
		if !oki {
			return false
		}
		if !okj {
			return true
		}
		return ri < rj
	})
	for _, n := range rest {
		if len(pool) >= min {
			break
		}
		pool = append(pool, n)
	}
	return pool
}

// geoipCountryFor 按目标 IP 反查国家代码（大写，如 US/HK/SG/JP）。
// 使用核心已有的 geoip 数据库（geodata/geoip，MMDB 加载同 GEOIP 规则）。
// 查询失败或数据库不可用时返回 ""（调用方按"无地区信息"退化到全局池）。
// 包级变量便于单测注入替换。
var geoipCountryFor = func(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	// MMDB 文件缺失（单测/未配置）时静默返回 ""，避免 mmdb.IPInstance
	// 内部 log.Fatalln 直接终止进程。
	if _, err := os.Stat(C.Path.MMDB()); err != nil {
		return ""
	}
	codes := mmdb.IPInstance().LookupCode(net.IP(ip.AsSlice()))
	for _, c := range codes {
		if c != "" {
			return strings.ToUpper(c)
		}
	}
	return ""
}

// maybeRefresh 按懒测低频控制周期刷新：距上次刷新未达最小间隔时不重圈。
func (m *Manager) maybeRefresh(now int64) bool {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	if now-m.lastRefreshAt < int64(m.refreshMinInterval) {
		return false
	}
	m.lastRefreshAt = now
	return true
}

// SetAllProxies 设置全局节点列表（从 mihomo 核心注入，供自动圈选使用）。
func (m *Manager) SetAllProxies(proxies []string) {
	total := len(proxies)
	// 需求 A（2026-10-17）：黄金枢纽池——候选池取值空间锁死五区
	// （HK/TW/SG/JP/KR），欧美/其他区在加载层即被踢出（Q9：显式配置
	// fallbacks 亦经同一过滤，见 SetTargets）。
	proxies = m.filterLaneRegions(proxies)
	m.mu.Lock()
	m.allProxies = append([]string(nil), proxies...)
	m.mu.Unlock()
	if total > 0 {
		log.Infoln("[GameRoute] pool filtered: kept %d / total %d (five-region lock)", len(proxies), total)
	}
	// 死六二：启动清洗在池就绪后执行（只清字段值，不删记忆条目）。
	m.reconcileMemoryForLanePool(proxies)
	// 需求 D3：候选池刷新时对"此刻已知"的模板目标批量主动预热（异步，
	// 不阻塞；模板键在触发时刻快照，避免与本调用之后的模板学习竞争）。
	// v2.4 第二刀（2.4 + 谷歌强制修正一②）：启动后 1s 先跑
	// PreheatRegionFanout（HK/TW 全量上 7770 跑道，独立预算 32），再跑
	// 既有批量预热——扇出先于 PreheatKnownTargets。
	go func() {
		time.Sleep(time.Second)
		m.PreheatRegionFanout(m.probeTemplateKeys())
		m.PreheatKnownTargets(m.probeTemplateKeys())
	}()
	// v2.13 第一刀（1.1）：STUN 保底扇出周期化——bestRaceWinner 永不因 TTL
	// 过期留空，从根上堵住"冠军过期 → pickPrimaryTemp 盲选"的掉档路径。
	m.startSTUNRefreshLoop()
}

// filterLaneRegions 五区过滤（需求 A）：节点名解析不出五区标签的一律
// 不进池（无区标签=区不可信）；被滤除节点计入汇总日志。
func (m *Manager) filterLaneRegions(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	kept := make([]string, 0, len(names))
	for _, n := range names {
		if tag, ok := extractRegionTag(n); ok && IsLaneRegion(tag) {
			kept = append(kept, n)
		}
	}
	return kept
}

// laneChampionsLocked LaneChampions 的锁内直读变体（v2.6 强制修正二）：
// 调用方必须已持有 m.mu（≥RLock）——MatchTarget 域分支第三级保底在持锁
// 环境取 HK 区冠军，严禁调 LaneChampions/SnapshotRTT（其内部 m.mu.RLock
// 在写者等待时与外层 RLock 构成死锁环，race.go 连败计数同源教训）。
// 选取逻辑与 LaneChampions 逐行同源：区内按 rttTable 升序、race 源优先
// （v2.4 漏洞二口径）、无数据回退池序第一；某区无节点则跳过。
func (m *Manager) laneChampionsLocked() map[string]string {
	rtt := make(map[string]int, len(m.rttTable))
	for k, v := range m.rttTable {
		rtt[k] = v
	}
	champions := make(map[string]string, 5)
	for _, region := range []string{"HK", "TW", "SG", "JP", "KR"} {
		members := FilterByRegion(m.allProxies, "", region)
		if len(members) == 0 {
			continue
		}
		best, bestKey, bestRtt := "", 0, 0
		for _, n := range members {
			rt, ok := rtt[n]
			if !ok || rt <= 0 {
				continue
			}
			key := 1
			if m.rttSource[n] == "race" {
				key = 2
			}
			if best == "" || key > bestKey || (key == bestKey && rt < bestRtt) {
				best, bestKey, bestRtt = n, key, rt
			}
		}
		if best != "" {
			champions[region] = best
		}
	}
	return champions
}

// LaneChampions 五区冠军选择（需求 F，2026-10-17）：每区选 Top-1 代表——
// 区内按 rttTable 升序，无数据取池序第一（Q7）；绝不跨区比大小（跨区
// 只由 Shadow Forking 赛马实测决定）。某区无节点则跳过（需求 A 边界）。
func (m *Manager) LaneChampions() map[string]string {
	m.mu.RLock()
	pool := append([]string(nil), m.allProxies...)
	rttSrc := make(map[string]string, len(m.rttSource))
	for k, v := range m.rttSource {
		rttSrc[k] = v
	}
	m.mu.RUnlock()
	rtt := m.SnapshotRTT()
	champions := make(map[string]string, 5)
	for _, region := range []string{"HK", "TW", "SG", "JP", "KR"} {
		members := FilterByRegion(pool, "", region)
		if len(members) == 0 {
			continue
		}
		// v2.4 漏洞二（谷歌强制）：选区代表优先按 Source=="race" 的 RTT
		// 升序——7770 赛马实测数据（如 HK 02=25ms）一经入表即当选冠军，
		// Cloudflare urltest 刷新不得再把代表篡改回 HK 01；该区无任何
		// race 数据时才回退 urltest/池序第一（旧行为）。
		best, bestKey, bestRtt := "", 0, 0
		for _, n := range members {
			rt, ok := rtt[n]
			if !ok || rt <= 0 {
				continue
			}
			key := 1
			if rttSrc[n] == "race" {
				key = 2
			}
			if best == "" || key > bestKey || (key == bestKey && rt < bestRtt) {
				best, bestKey, bestRtt = n, key, rt
			}
		}
		if best != "" {
			champions[region] = best
			continue
		}
		champions[region] = members[0]
	}
	return champions
}

// SetDefaultProxy 注入默认出口（当前策略组实际选中节点，如 Final 当前
// 香港节点）：GameLane 所有兜底路径的最终出口，游戏加速流量绝不直连。
func (m *Manager) SetDefaultProxy(name string) {
	if name == "" {
		return
	}
	m.defaultProxyMu.Lock()
	old := m.defaultProxy
	m.defaultProxy = name
	m.defaultProxyMu.Unlock()
	if old != name {
		log.Infoln("[GameRoute] default proxy = %s", name)
	}
}

// defaultProxyName 返回当前默认出口名；未注入返回 ""（此时空代理池
// 兜底只能保持 lastProxy，宁可等待不可直连）。
func (m *Manager) defaultProxyName() string {
	m.defaultProxyMu.Lock()
	defer m.defaultProxyMu.Unlock()
	return m.defaultProxy
}

// safeProxy 出口选择终极兜底：返回一个绝不为空、绝不为 DIRECT 的出口。
// 顺序：候选 → 默认出口 → 上一个可用出口；全部不可得返回 "" 表示
// "排队等待选路"（上层保持会话不放行，绝不直连）。
func (m *Manager) safeProxy(candidate string) string {
	if candidate != "" && candidate != "DIRECT" {
		return candidate
	}
	if dp := m.defaultProxyName(); dp != "" {
		return dp
	}
	m.lastProxyMu.Lock()
	defer m.lastProxyMu.Unlock()
	return m.lastProxy
}

// rememberProxy 记录一个实际用上的出口（用于极端兜底保持）。
func (m *Manager) rememberProxy(px string) {
	if px == "" || px == "DIRECT" {
		return
	}
	m.lastProxyMu.Lock()
	m.lastProxy = px
	m.lastProxyMu.Unlock()
}

// targetKeyFor 返回目标标识（进程名优先，否则命中 CIDR 前缀串），
// 调用方需保证持有 m.mu 读锁或无并发写 targets。
func (m *Manager) targetKeyFor(dstIP netip.Addr) string {
	if !dstIP.IsValid() {
		return ""
	}
	for i := range m.targets {
		t := &m.targets[i]
		if len(t.CIDR) > 0 && cidrContains(t.CIDR, dstIP) {
			if t.ProcessName != "" {
				return t.ProcessName
			}
			for _, c := range t.CIDR {
				if c.Contains(dstIP) {
					return c.String()
				}
			}
			return ""
		}
	}
	return ""
}

// rememberTargetProxy 记录目标上一次有效出口并写回 game_lane_state.json。
func (m *Manager) rememberTargetProxy(key, px string) {
	if key == "" || px == "" || px == "DIRECT" {
		return
	}
	// F7 写入侧区校验（诊断 RC7/E12）：last_proxies 污染（Canada 当游戏
	// 出口）曾因“读取侧校验、写入侧不校验”长期残留。与读取侧同一口径：
	// 代理名地区标签与该目标记忆 RegionActual 不一致时拒绝写入。
	if !m.lastProxyRegionWritable(key, px) {
		log.Warnln("[GameRoute] refuse polluted last proxy %s=%s (region mismatch)", key, px)
		return
	}
	m.lastProxyByTargetMu.Lock()
	if m.lastProxyByTarget == nil {
		m.lastProxyByTarget = make(map[string]string)
	}
	if m.lastProxyByTarget[key] == px {
		m.lastProxyByTargetMu.Unlock()
		return // 未变化不写盘
	}
	m.lastProxyByTarget[key] = px
	m.lastProxyByTargetMu.Unlock()
	m.saveLastProxies()
}

// lookupTargetLastProxy 按目标 IP 反查上一次有效出口（退避链"上一出口"）。
func (m *Manager) lookupTargetLastProxy(dstIP netip.Addr) string {
	key := m.targetKeyFor(dstIP)
	if key == "" {
		return ""
	}
	m.lastProxyByTargetMu.Lock()
	defer m.lastProxyByTargetMu.Unlock()
	return m.lastProxyByTarget[key]
}

// LoadLastProxies 启动时从 game_lane_state.json 恢复每个目标上一次有效出口。
func (m *Manager) LoadLastProxies(path string) {
	if path == "" {
		return
	}
	m.lastProxyPath = path
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st struct {
		LastProxies map[string]string `json:"last_proxies"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}
	m.lastProxyByTargetMu.Lock()
	if st.LastProxies == nil {
		m.lastProxyByTarget = make(map[string]string)
	} else {
		// v6.12: 复用 last_proxies 前校验地区一致性：代理名的地区标签
		// 与目标 IP 的记忆 RegionActual 不一致时丢弃（防污染记忆把
		// 欧美节点作为"上一出口"固化）；段表命中的目标豁免（已知游戏
		// 服务器，代理区以段表/GeoIP 为准）。
		clean := make(map[string]string, len(st.LastProxies))
		for k, v := range st.LastProxies {
			if !m.lastProxyRegionOK(k, v) {
				log.Warnln("[GameRoute] last proxy %s=%s region mismatch, drop", k, v)
				continue
			}
			clean[k] = v
		}
		m.lastProxyByTarget = clean
	}
	m.lastProxyByTargetMu.Unlock()
}

// lastProxyRegionWritable 写入侧校验：key 可能是 CIDR 串（"ip/32"）或
// 进程名；非 IP key（进程名目标）不做区校验直接放行。
func (m *Manager) lastProxyRegionWritable(key, proxy string) bool {
	ip := strings.TrimSuffix(key, "/32")
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.IsValid() {
		return true
	}
	pRegion, ok := extractRegionTag(proxy)
	if !ok || pRegion == "" {
		return true
	}
	if SegmentTable().MatchIP(addr) && SegmentTable().RegionTrustedFor(addr) {
		return true // 已知游戏段（非云段）：区以段表/GeoIP 为准
	}
	if r := m.lookUpRegionActual(ip); r != "" && r != pRegion {
		return false
	}
	return true
}

// lastProxyRegionOK 校验 last_proxies 条目地区一致性：代理名的地区标签
// 需与目标 IP 的记忆 RegionActual（如有）一致；段表命中且区可信的目标豁免
// （已知游戏服务器，代理区以段表/GeoIP 为准；云厂商段不豁免，红线 2）。
// 无地区标签的代理无法校验，保留（历史行为）。
func (m *Manager) lastProxyRegionOK(ip, proxy string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.IsValid() {
		return false
	}
	pRegion, ok := extractRegionTag(proxy)
	if !ok || pRegion == "" {
		return true
	}
	if SegmentTable().MatchIP(addr) && SegmentTable().RegionTrustedFor(addr) {
		return true
	}
	if r := m.lookUpRegionActual(ip); r != "" && r != pRegion {
		return false
	}
	return true
}

// StartupReconcile 启动后自动纠偏（config.parseGameLane 在 LoadMemory /
// LoadLastProxies 之后调用）：
//   - 五区口径启动清洗（死六二）：RegionActual 非五区、PreferredProxy 不在
//     五区池 → 仅清字段值，绝不删整条记忆；池未就绪时由 SetAllProxies 兜底
//     再试（reconcileMemoryForLanePool 内部保证一次性）；
//   - 重新校验 last_proxies 地区一致性（依赖清洗后的记忆区）。
//
// 全部只读修正内存态，不落盘（下次命中 touch/flush 自然持久化）。
// 2026-10-17（需求 E3/Q5）：原 reconcilePollutedMemory 随五区锁死删除。
func (m *Manager) StartupReconcile() {
	m.mu.RLock()
	pool := append([]string(nil), m.allProxies...)
	m.mu.RUnlock()
	m.reconcileMemoryForLanePool(pool)
	m.reconcileLastProxies()
}

// reconcileLastProxies 重新校验 last_proxies 地区一致性（复用 lastProxyRegionOK）。
func (m *Manager) reconcileLastProxies() {
	m.lastProxyByTargetMu.Lock()
	defer m.lastProxyByTargetMu.Unlock()
	clean := make(map[string]string, len(m.lastProxyByTarget))
	dropped := 0
	for k, v := range m.lastProxyByTarget {
		if !m.lastProxyRegionOK(k, v) {
			dropped++
			continue
		}
		clean[k] = v
	}
	if dropped > 0 {
		log.Infoln("[GameRoute] startup reconcile: %d last_proxies dropped", dropped)
	}
	m.lastProxyByTarget = clean
}

// saveLastProxies 将 last_proxies 合并写回 game_lane_state.json（保留面板
// 管理的 enabled/targets/enable_m3 字段），失败静默（下次命中重试）。
func (m *Manager) saveLastProxies() {
	m.lastProxyByTargetMu.Lock()
	path := m.lastProxyPath
	if path == "" {
		m.lastProxyByTargetMu.Unlock()
		return
	}
	lp := make(map[string]string, len(m.lastProxyByTarget))
	for k, v := range m.lastProxyByTarget {
		lp[k] = v
	}
	m.lastProxyByTargetMu.Unlock()

	var st map[string]any
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	if st == nil {
		st = map[string]any{}
	}
	st["last_proxies"] = lp
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o666); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// SetRTTTable 设置 RTT 表（从 mihomo 核心注入，供自动圈选使用）。
// 原地写回：保留旧表已有条目，新值覆盖同键——不替换切片，确保
// 探测结果完整覆盖旧表且不丢既有积累（自动圈选/被动积累数据）。
func (m *Manager) SetRTTTable(rttTable map[string]int) {
	m.mu.Lock()
	if m.rttTable == nil {
		m.rttTable = make(map[string]int, len(rttTable))
	}
	if m.rttSource == nil {
		m.rttSource = make(map[string]string)
	}
	for k, v := range rttTable {
		m.rttTable[k] = v
		// v2.4 第二刀（2.5）：外部注入的 RTT 表按实测数据口径标记
		// Source="race"（SetRTTTable 无生产调用方，语义=外部实测注入），
		// 使既有注入数据继续参与进场选主裁决；Cloudflare urltest 数据
		// 经 MergeProbeResults 标 "urltest"，被 raceOnlyRTTTableLocked 排除。
		m.rttSource[k] = "race"
	}
	m.mu.Unlock()
}

// SnapshotRTT 返回当前 RTT 表快照（探测结算/圈选用，避免持锁遍历）。
// v2.7 第二刀：熔断期内（badNodeUntil 未过期）对劣迹节点叠加 +200ms
// 惩罚权重——读取侧统一生效（lowestRtt/sortedByRttStable/pickPrimaryTemp/
// SwitchToBestFallback/probeAndSettle 全走本快照），不污染原始 rttTable
// 写入侧，熔断期满自动恢复正常读数。
func (m *Manager) SnapshotRTT() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]int, len(m.rttTable))
	for k, v := range m.rttTable {
		out[k] = v
	}
	// 锁序：m.mu(RLock) → badNodeMu；markBadNode 仅取 badNodeMu→bestRaceMu，
	// 无 m.mu 反向边，不构成死锁环。
	now := time.Now().UnixMilli()
	m.badNodeMu.Lock()
	defer m.badNodeMu.Unlock()
	for k := range m.badNodeUntil {
		if now < m.badNodeUntil[k] {
			out[k] += badNodeRttPenalty
		} else {
			delete(m.badNodeUntil, k)
		}
	}
	return out
}

// SetProbeSource 注入即时探测源：探测 URL + 全局节点对象映射。
// 核心在 parseGameLane 时注入（adapter.Proxy 真实对象），命中目标后
// 立即对候选池发起真实出站探测写回 RTT 表；无探测源时自动跳过
// （退化为原流量被动积累路径）。
func (m *Manager) SetProbeSource(url string, proxies map[string]C.Proxy) {
	m.probeMu.Lock()
	defer m.probeMu.Unlock()
	m.probeURL = url
	m.proxyObjs = make(map[string]C.Proxy, len(proxies))
	for k, v := range proxies {
		m.proxyObjs[k] = v
	}
}

// probeSample 单节点一次探测的样本（F1）：RttMs 为采样聚合值（中位数），
// Samples 为成功采样数，OK=false 表示本轮全部失败（是否判死由失败连击
// 策略决定，不再单轮置 0）。
type probeSample struct {
	RttMs   int
	Samples int
	OK      bool
	Source  string // v2.4 第二刀：数据源标签（"race"=7770 赛马实测 / "urltest"=Cloudflare；空=urltest）
}

// median3 三个采样值的中位数。
func median3(a, b, c int) int {
	if a > b {
		a, b = b, a
	}
	if b > c {
		b, c = c, b
	}
	if a > b {
		a, b = b, a
	}
	return b
}

// probeCandidates 对候选池发起即时真实探测（URLTest 出站测延迟）：
// 并发上限 4、单次超时 2.5s、每节点采样 3 次取中位数（F1：单发采样方差
// 过大是“分数乱跳”的主因之一）；全部失败记为失败样本（判死策略见
// MergeProbeResults）。探测源未注入返回 nil（调用方跳过结算）。
func (m *Manager) probeCandidates(pool []string) map[string]probeSample {
	m.probeMu.Lock()
	url := m.probeURL
	objs := m.proxyObjs
	m.probeMu.Unlock()
	if url == "" || len(objs) == 0 || len(pool) == 0 {
		return nil
	}
	results := make(map[string]probeSample, len(pool))
	recordDiag("probe_batch", "pool=%d url=%s", len(pool), url)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	var resMu sync.Mutex
	for _, name := range pool {
		p, ok := objs[name]
		if !ok || name == "" || name == "DIRECT" {
			continue
		}
		wg.Add(1)
		go func(n string, px C.Proxy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var okMs []int
			for i := 0; i < 3; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
				ms, err := px.URLTest(ctx, url, nil)
				cancel()
				if err == nil && ms > 0 {
					okMs = append(okMs, int(ms))
				}
			}
			s := probeSample{OK: false, Source: "urltest"}
			switch len(okMs) {
			case 3:
				s = probeSample{RttMs: median3(okMs[0], okMs[1], okMs[2]), Samples: 3, OK: true, Source: "urltest"}
			case 2:
				s = probeSample{RttMs: (okMs[0] + okMs[1]) / 2, Samples: 2, OK: true, Source: "urltest"}
			case 1:
				s = probeSample{RttMs: okMs[0], Samples: 1, OK: true, Source: "urltest"}
			}
			resMu.Lock()
			results[n] = s
			resMu.Unlock()
			recordDiag("probe_node", "name=%s rttMs=%d samples=%d ok=%v source=%s", n, s.RttMs, s.Samples, s.OK, s.Source)
		}(name, p)
	}
	wg.Wait()
	return results
}

// MergeProbeResults 把一批探测样本合入 rttTable（F1 数据层治理，替代原
// mergeRTT 的“单发值直接覆盖、失败即置 0”）：
//   - 成功样本：先做“URLTest 开销校正”（减去该节点已学习的
//     URLTest−游戏实测 差值，消除 TLS 握手等系统性虚高，实测港台节点
//     曾被写成 245-251ms 而真实游戏 RTT 仅 20-50ms），再与旧值 EMA 平滑
//     （0.5/0.5），杜绝单轮跳变直接覆盖（诊断 S6 分数乱跳）；
//   - 失败样本：失败连击 +1，连续 ≥3 轮失败才写 0（判死）——单轮失败
//     只保留旧值（视为抖动），防止一轮网络抖动把整池节点“测死”触发
//     随机选路（诊断 RC1/RC5a 成因）。
func (m *Manager) MergeProbeResults(results map[string]probeSample) {
	if len(results) == 0 {
		return
	}
	anyOK := false
	now := time.Now().UnixMilli()
	m.mu.Lock()
	if m.rttTable == nil {
		m.rttTable = make(map[string]int)
	}
	for name, s := range results {
		if s.OK && s.RttMs > 0 {
			anyOK = true
			if m.lastURLTest == nil {
				m.lastURLTest = make(map[string]int)
			}
			m.lastURLTest[name] = s.RttMs // 保留原始值供开销校准
			// v2.4 第二刀：数据源标签落库——进场选主（raceOnlyRTTTable）仅认
			// "race"（7770 赛马实测），Cloudflare urltest 数据不得参与裁决。
			if m.rttSource == nil {
				m.rttSource = make(map[string]string)
			}
			if s.Source == "" {
				s.Source = "urltest"
			}
			m.rttSource[name] = s.Source
			corr := s.RttMs
			if off := m.probeOffset[name]; off > 0 {
				if c2 := corr - off; c2 >= 10 {
					corr = c2
				} else {
					// 开销估计失效（节点链路已变化），退回原始值并清除估计
					delete(m.probeOffset, name)
				}
			}
			if old := m.rttTable[name]; old > 0 {
				corr = (corr + old) / 2
			}
			m.rttTable[name] = corr
			m.failStreakMu.Lock()
			delete(m.rttFailStreak, name)
			m.failStreakMu.Unlock()
			if m.rttLastOK == nil {
				m.rttLastOK = make(map[string]int64)
			}
			m.rttLastOK[name] = now
			continue
		}
		// 失败样本：连击 ≥3 才判死
		m.failStreakMu.Lock()
		m.rttFailStreak[name]++
		if m.rttFailStreak[name] >= 3 {
			m.rttTable[name] = 0
		}
		m.failStreakMu.Unlock()
	}
	m.mu.Unlock()
	if anyOK {
		m.lastProbeOKAt.Store(now)
	}
}

// MergeProbeResult 单节点探测样本入库（F6：会话级候选探测与 Manager 探测
// 共用同一张表、同一套平滑/判死策略，消除双探测口径漂移）。
func (m *Manager) MergeProbeResult(name string, rttMs float64, samples int, ok bool) {
	m.MergeProbeResults(map[string]probeSample{name: {RttMs: int(rttMs), Samples: samples, OK: ok}})
}

// RecordSessionRTT 回写当前主节点的会话实测 RTT（F1④：Observer LIFO 配对
// 的下行包往返，是“客户端→节点→游戏服务器”的真实链路延迟）。同时用它
// 校准该节点 URLTest 的系统性开销（TLS 握手等），供后续候选探测校正。
// 由 tunnel 层在 SessionConn 上周期性调用（5s 节流），不阻塞数据面。
func (m *Manager) RecordSessionRTT(proxy string, rttMs float64) {
	if proxy == "" || proxy == "DIRECT" || rttMs <= 0 || rttMs > 2000 {
		return
	}
	rtt := int(rttMs)
	now := time.Now().UnixMilli()
	m.mu.Lock()
	if m.rttTable == nil {
		m.rttTable = make(map[string]int)
	}
	if m.lastURLTest == nil {
		m.lastURLTest = make(map[string]int)
	}
	if m.probeOffset == nil {
		m.probeOffset = make(map[string]int)
	}
	// 开销校准：raw ≈ 校正后值 + 开销，指数平均避免单次抖动污染估计
	if raw := m.lastURLTest[proxy]; raw > rtt {
		off := raw - rtt
		if old := m.probeOffset[proxy]; old > 0 {
			off = (old + off) / 2
		}
		m.probeOffset[proxy] = off
	}
	m.rttTable[proxy] = rtt
	m.failStreakMu.Lock()
	delete(m.rttFailStreak, proxy)
	m.failStreakMu.Unlock()
	if m.rttLastOK == nil {
		m.rttLastOK = make(map[string]int64)
	}
	m.rttLastOK[proxy] = now
	m.mu.Unlock()
	m.lastProbeOKAt.Store(now)
}

// probeAndSettle 命中目标后立即对候选池发起真实探测并结算（v6.5→v6.7→v6.10）：
// 探测结果写回 RTT 表 → 剔除死节点（RTT=0）→ fallbacks 按 RTT 升序重排。
// v6.10：探测后若发现显著更优节点（RTT < 当前主节点 RTT 的 60%），
// 则更新 currentPrimary + RecordM3Active，不再输出"主节点不变"。
// 异步执行，不阻塞首包放行；无探测源时静默跳过。
func (m *Manager) probeAndSettle(t *Target, dstIP netip.Addr, allProxies []string) {
	// F5：每目标单飞——并发首包/周期刷新会重复触发探测与换主。
	if !atomic.CompareAndSwapInt32(&t.probeRunning, 0, 1) {
		return
	}
	go func() {
		defer atomic.StoreInt32(&t.probeRunning, 0)
		pool := t.SnapshotFallbacks()
		results := m.probeCandidates(pool)
		if len(results) == 0 {
			return
		}
		m.MergeProbeResults(results)
		rtt := m.SnapshotRTT()
		if ordered := sortedByRttStable(pool, rtt); len(ordered) > 0 {
			t.SetFallbacks(ordered)
			// v6.12: 探测结果写回 rttTable 后同步刷新 candidate_pool
			// 快照（面板展示与实际选路候选一致，含最新 RTT 数据）。
			m.recordCandidateSnapshot(ordered, rtt)
		}

		// v6.10: 探测显著更优 → 更新主节点
		// v2.13 第三刀（3.1 前置）：probeDst 在 curRtt>0 与 curRtt==0 两条
		// 路径共用，提到锁外统一计算。
		probeDst := ""
		if dstIP.IsValid() {
			probeDst = dstIP.String()
		} else if len(t.CIDR) > 0 && t.CIDR[0].Addr().Is4() {
			probeDst = t.CIDR[0].Addr().String()
		}
		t.primaryMu.Lock()
		cur := t.currentPrimary
		if cur == "" {
			// v2.13 第二刀（2.2）：禁盲选后，全表无实测值的冷启动会以空主
			// 节点进场（上层 safeProxy 兜默认/上一出口，不断流）。这里执行
			// "先测再进"：本轮探测已有结果即采纳，绝不再随机给 rtt=0 节点。
			bestProbe, bestProbeRtt := bestProbeCandidate(pool, rtt)
			if bestProbe != "" && bestProbeRtt > 0 {
				t.currentPrimary = bestProbe
				RecordM3Active(bestProbe)
				t.primaryMu.Unlock()
				log.Infoln("[GameRoute] probe-first entry: primary = %s (rtt=%dms, probe)", bestProbe, bestProbeRtt)
				recordDiag("probe_bootstrap", "primary=%s rtt=%dms candidates=%d dst=%s", bestProbe, bestProbeRtt, len(pool), probeDst)
				m.recordPrimarySnapshot(bestProbe, "probe", rtt)
				return
			}
			t.primaryMu.Unlock()
			log.Infoln("[GameRoute] probe settled candidates=%d (无实测节点, 保持空主节点等待下次探测)", len(pool))
			recordDiag("probe_settled", "candidates=%d current= reason=no-measured", len(pool))
			return
		}
		{
			curRtt := rtt[cur]
			// 第二刀（v2.7）+ v2.8 第一刀焊死：probeAndSettle 更新 RTT 处
			// curRtt>=150ms 的劣迹节点同样只记过（熔断+废黜赛马冠军），
			// 严禁按探测结果换主/rebuild——探测换主同样会改出口导致对局
			// 断流，命中即跳过本次换主（只结算 RTT 不动主节点）。
			if curRtt > badNodeTriggerMs {
				m.markBadNode(cur)
				log.Infoln("[GameRoute] probe best skipped: current %s marked bad (curRtt=%dms), keep current", displayProxy(cur), curRtt)
				recordDiag("probe_skipped", "current=%s curRtt=%dms reason=dethrone-no-switch", cur, curRtt)
				t.primaryMu.Unlock()
				return
			}
			bestProbe, bestProbeRtt := bestProbeCandidate(pool, rtt)
			if bestProbe == "" || bestProbeRtt <= 0 {
				t.primaryMu.Unlock()
				log.Infoln("[GameRoute] probe settled candidates=%d (主节点不变)", len(pool))
				recordDiag("probe_settled", "candidates=%d current=%s", len(pool), cur)
				return
			}
			if curRtt > 0 {
				if bestProbeRtt*10 < curRtt*6 {
					// 2026-10-18 v2.1 漏洞一（Q-F4 裁决）：赛马锁有效期内普通
					// 探测（URLTest）严禁篡位 currentPrimary——赛马实测（节点
					// →游戏服务器真实 UDP RTT）优先于一切普通探测；仅当锁被
					// 解锁（TTL 过期/M3 劣化解锁/连败解锁惰性裁决）后放行。
					// segmentLockActive 纯读无副作用，锁序 primaryMu→
					// segmentLockMu 无反向边（checkSegmentLock 不再触碰 m.mu）。
					if m.targetSegmentLocked(t, dstIP) {
						t.primaryMu.Unlock()
						log.Debugln("[GameRoute] probe best %s (rtt=%dms) skipped: segment lock active (race wins)", bestProbe, bestProbeRtt)
						recordDiag("probe_skipped", "best=%s rtt=%dms current=%s curRtt=%dms reason=segment-lock", bestProbe, bestProbeRtt, cur, curRtt)
						return
					}
					// 第一刀（v2.7，1.5 同步）：活跃会话免切锁——探测结果只
					// 结算 RTT，不换正在承载活跃对局会话的目标主节点（周期
					// 刷新/首包探测命中已建连对局流时，绝不允许换主/换区）。
					if probeDst != "" && m.targetHasActiveSession(probeDst, time.Now().UnixMilli()) {
						t.primaryMu.Unlock()
						log.Debugln("[GameRoute] probe best %s (rtt=%dms) skipped: active session on %s (免切锁)", bestProbe, bestProbeRtt, probeDst)
						recordDiag("probe_skipped", "best=%s rtt=%dms current=%s curRtt=%dms reason=session-active dst=%s", bestProbe, bestProbeRtt, cur, curRtt, probeDst)
						return
					}
					log.Infoln("[GameRoute] probe best %s (rtt=%dms) < current %s (rtt=%dms), switching", bestProbe, bestProbeRtt, cur, curRtt)
					recordDiag("probe_switch", "best=%s rtt=%dms current=%s curRtt=%dms", bestProbe, bestProbeRtt, cur, curRtt)
					t.currentPrimary = bestProbe
					RecordM3Active(bestProbe)
					t.primaryMu.Unlock()
					m.recordPrimarySnapshot(bestProbe, "probe", rtt)
					return
				}
			} else if bestProbeRtt < probeZeroCurRttMaxRttMs {
				// v2.13 第三刀（3.1，情况 B）：当前主节点 rtt==0（无实测值，
				// 历史盲选遗留）且非活跃期、探测已拿到 <80ms 实测节点 →
				// 允许替换。铁律：活跃对局期（targetHasActiveSession）与
				// 赛马锁定期一律不切换，避免换出口断流。
				if m.targetSegmentLocked(t, dstIP) {
					t.primaryMu.Unlock()
					log.Debugln("[GameRoute] zero-rtt primary %s replace skipped: segment lock active", displayProxy(cur))
					recordDiag("probe_skipped", "best=%s rtt=%dms current=%s curRtt=0 reason=segment-lock", bestProbe, bestProbeRtt, cur)
					return
				}
				if probeDst != "" && m.targetHasActiveSession(probeDst, time.Now().UnixMilli()) {
					t.primaryMu.Unlock()
					log.Infoln("[GameRoute] zero-rtt primary %s replace skipped: session active on %s", displayProxy(cur), probeDst)
					recordDiag("probe_skipped", "best=%s rtt=%dms current=%s curRtt=0 reason=session-active dst=%s", bestProbe, bestProbeRtt, cur, probeDst)
					return
				}
				log.Infoln("[GameRoute] zero-rtt primary %s replaced by %s (rtt=%dms, probe)", displayProxy(cur), bestProbe, bestProbeRtt)
				recordDiag("probe_switch", "best=%s rtt=%dms current=%s curRtt=0 reason=zero-cur-rtt", bestProbe, bestProbeRtt, cur)
				t.currentPrimary = bestProbe
				RecordM3Active(bestProbe)
				t.primaryMu.Unlock()
				m.recordPrimarySnapshot(bestProbe, "probe", rtt)
				return
			} else {
				t.primaryMu.Unlock()
				log.Debugln("[GameRoute] zero-rtt primary %s kept: probe best %s rtt=%dms >= %dms", displayProxy(cur), bestProbe, bestProbeRtt, probeZeroCurRttMaxRttMs)
				recordDiag("probe_skipped", "best=%s rtt=%dms current=%s curRtt=0 reason=zero-cur-rtt-no-gain", bestProbe, bestProbeRtt, cur)
				return
			}
		}
		t.primaryMu.Unlock()
		log.Infoln("[GameRoute] probe settled candidates=%d (主节点不变)", len(pool))
		recordDiag("probe_settled", "candidates=%d current=%s", len(pool), cur)
	}()
}

// probeZeroCurRttMaxRttMs v2.13 第三刀（3.1 情况 B）阈值：当前主节点 rtt==0
// （无实测值）时，只有探测到 <80ms 的实测节点才允许替换——80ms 以上替换
// 收益不明确且会改出口（换 NAT 源端口），宁可保持到下一轮探测。
const probeZeroCurRttMaxRttMs = 80

// urltestFallbackMaxRttMs v2.13 第二刀第 5 档港台兜底的上限阈值：全量实测
// 表中港台最低值低于该值（真·低延迟线路）才优先进场；超过说明港台线路
// 本身差（如 120ms），不强上港台，交退避链全局 race 实测最低。
const urltestFallbackMaxRttMs = 80

// bestProbeCandidate 从候选池挑本轮探测 RTT 最低的节点（只认 rt>0 实测值，
// 绝不返回 rtt=0 的未测节点）。抽为独立函数供 probeAndSettle 的三条路径
// （先测再进 / 情况 A 显著更优 / 情况 B rtt==0 替换）共用同一口径。
func bestProbeCandidate(pool []string, rtt map[string]int) (string, int) {
	best, bestRtt := "", 0
	for _, n := range pool {
		rt, ok := rtt[n]
		if !ok || rt <= 0 {
			continue
		}
		if best == "" || rt < bestRtt {
			best, bestRtt = n, rt
		}
	}
	return best, bestRtt
}

// SwitchToBestFallback 对局 UDP 实时劣化切换（v6.9→v6.10 RTT 劣化触发）：
// 已接管目标在观测窗口内 UDP 发送无响应时立即调用：区内劣化 →
// 邻近区 → 港台兜底，逐级降级。
// v6.10 增加 RTT 维度劣化判定：主节点 RTT 持续 >120ms 或比候选池最优高 1.5 倍，
// 且候选池存在更优节点 → 立即触发切换（不再等 UDP 无响应），监控周期 3-5 秒。
// dst 为会话远端 IP，用于定位命中的 Target。
// 仅 autoPrimary 模式生效；显式配置目标由 M3 SessionConn 会话级切换负责。
// 返回 true 表示已切换主节点。
func (m *Manager) SwitchToBestFallback(dst string) bool {
	t := m.targetByDst(dst)
	if t == nil {
		return false
	}
	if !t.IsAutoPrimary() {
		return false
	}

	// v2.8 铁律一/铁律三：出生保护门卫（Manager 级最后防线）——会话出生
	// 后 30s 内，无论有包无包，严禁任何入口调用 SwitchToBestFallback 换
	// 节点（tunnel 层因 dueDegradeCheck 扫到刚创建 laneEntry 误判死链、
	// 以及 MatchTarget/probeAndSettle 内部顺手调用等路径全部在此拦截）。
	// 出生期 0 回包是握手/地图加载的正常现象，不是死链。
	if m.birthProtected(dst, time.Now().UnixMilli()) {
		recordDiag("birth_protected", "dst=%s skip switch (birth grace %ds)", dst, birthGraceMs/1000)
		return false
	}

	// 第二刀（v2.7，批复顺序铁律）+ v2.8 第一刀焊死：curRtt>=150ms 的
	// 劣迹节点只标记 badNode（30min 熔断 + 废黜 bestRaceWinner，供新会话
	// 换健康节点上位），严禁对当前已连通会话执行任何切换/rebuild session
	// ——对局服务器一旦被换出口（换 NAT 源端口）立即拒收后续所有包
	// （2026-10-19 17:23:14 sent=2001 recv=0 彻底断流实锤）。命中即返回，
	// 不进入后续 degraded/region-changed 判定，杜绝"门卫漏判放行"路径。
	if cur := t.EffectiveProxy(); cur != "" {
		if curRtt := m.SnapshotRTT()[cur]; curRtt > badNodeTriggerMs {
			m.markBadNode(cur)
			recordDiag("dethrone_no_switch", "dst=%s cur=%s curRtt=%dms mark-bad-only", dst, displayProxy(cur), curRtt)
			return false
		}
	}

	// 第一刀（v2.7，确认点 1）：活跃会话终身免切锁——目标正在承载活跃
	// 对局会话（recv>=1 且 10s 内有回包）时，本局绝不换主/换区（局中
	// 跨区切出口被 EA 拒收，报 code.net 连接服务器超时的根因）。仅当
	// 连续 10s 完全 0 回包（死链）才放行切换抢救。
	if m.targetHasActiveSession(dst, time.Now().UnixMilli()) {
		recordDiag("session_locked", "dst=%s skip switch (active session, recv within 10s)", dst)
		return false
	}

	// F2 切换冷却：Manager 级切换是绕过 SessionConn 保护期的唯一入口，
	// 每目标 30s 冷却，冷却期内一律拒绝。否则 rttTable 的抖动（诊断 RC1）
	// 会把“自动换优”放大成秒级切换风暴（实测 26 秒内同一会话被重建 8 次，
	// 诊断 E1/RC2）。
	if until := m.switchCooldownUntil(dst); until > 0 {
		log.Debugln("[GameRoute] switch cooldown, skip (%s, remaining=%dms)", dst, until-time.Now().UnixMilli())
		recordDiag("cooldown_skip", "dst=%s remaining=%dms", dst, until-time.Now().UnixMilli())
		return false
	}

	// 死六四②（2026-10-17 批复）：对局劣化到达本函数 = 解锁重赛条件②——
	// 移除 /24 锁死（旧条目入 stale 供重赛防抖动），随后按既有劣化切换
	// 逻辑执行；重赛由静态预热/下一轮测速流触发，防抖动按 Q4/死六四裁决。
	if seg := segmentKey24(dst); seg != "" {
		m.UnlockSegmentForRerace(dst, "degrade-switch")
	}

	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()

	// 查找当前主节点所属地区标签（已持有 primaryMu，直接读字段避免重入死锁）
	foundRegionTag := ""
	if cur := t.currentPrimary; cur != "" {
		if tag, ok := extractRegionTag(cur); ok {
			foundRegionTag = tag
		}
	}
	if foundRegionTag == "" {
		// 主节点无地区标签：无法做跨区切换，直接探测兜底
		go m.probeAndSettle(t, netip.Addr{}, m.allProxies)
		return false
	}

	rtt := m.SnapshotRTT()
	best, bestRtt := "", 0
	cur := t.currentPrimary
	curRtt := 0
	if cur != "" {
		curRtt = rtt[cur]
	}

	// v2.8 铁律二：一切基于 RTT 比大小的换优/劣化分支（curRtt>120ms、
	// >1.5x best、候选池更低即切）已全部删除——24ms vs 19ms 之类的
	// 微小差异严禁触发局中换节点。切换触发条件仅由调用方（tunnel 层）
	// 门控：会话度过 30s 出生期且连续 10s 完全 0 回包（真死链）才允许
	// 调用本函数换备用节点；有回包即禁止因 RTT 差异换节点。

	// 第一轮：候选池（fallbacks）内 RTT 最低健康节点
	// （v6.8 验收：CIDR 命中 + autoPrimary + fallbacks 有 RTT 数据 → 切到
	// 池内 RTT 最低健康节点；未配置候选池时回退全局同区节点）
	// 已持有 primaryMu，直接读字段避免重入死锁
	// v2.7 确认点 2：fallbacks 池亦强制按当前区过滤（HK 目标只在 HK 池内换）。
	pool := make([]string, len(t.Fallbacks))
	copy(pool, t.Fallbacks)
	if len(pool) == 0 {
		pool = FilterByRegion(m.allProxies, "", foundRegionTag)
	} else {
		pool = FilterByRegion(pool, "", foundRegionTag)
		if len(pool) == 0 {
			pool = FilterByRegion(m.allProxies, "", foundRegionTag)
		}
	}
	bestInRegion, _ := lowestRtt(pool, rtt)
	if bestInRegion != "" {
		best, bestRtt = bestInRegion, rtt[bestInRegion]
	}

	// v2.7 确认点 2（严格同区铁律）：HK 目标只能在 HK 池内换，彻底删除
	// 原第二轮"区内劣化→邻近区（TW/SG/JP/KR）"与第三轮"邻近区也劣化→
	// 港台兜底"分支——局中跨区换出口会被 EA 拒收（训练场卡死根因：HK→TW
	// 后 code.net 连接服务器超时）。切换只发生在第一轮同区候选池内。

	// 无 RTT 数据时立即探测
	if best == "" {
		go m.probeAndSettle(t, netip.Addr{}, m.allProxies)
		return false
	}

	if best == cur {
		return false
	}

	// 已持有 primaryMu，直接写字段；RecordM3Active 同步全局 current_proxy
	t.currentPrimary = best
	RecordM3Active(best)
	bestRegionTag, _ := extractRegionTag(best)
	reason := "degraded"
	if foundRegionTag != bestRegionTag {
		reason = "region-changed"
		log.Warnln("[GameRoute] regionActual %s -> %s for %s",
			foundRegionTag, bestRegionTag, dst)
		m.rememberRegionActual(dst, bestRegionTag)
	} else {
		log.Warnln("[GameRoute] UDP degraded, switch %s -> %s (rtt=%dms) [region %s]",
			displayProxy(cur), best, bestRtt, foundRegionTag)
	}
	recordDiag("switch_done", "reason=%s %s -> %s (cur=%dms best=%dms) [region %s] dst=%s",
		reason, displayProxy(cur), best, curRtt, bestRtt, foundRegionTag, dst)
	m.recordSwitchHistory(cur, best, foundRegionTag, bestRegionTag, reason, bestRtt)
	m.recordPrimarySnapshot(best, "fallback", rtt)
	// F2：切换落地即武装冷却（switchCooldownMs，与会话保护期一致）。
	m.armSwitchCooldown(dst)
	return true
}

// switchCooldownMs Manager 级切换的每目标冷却时长（与会话保护期一致）。
const switchCooldownMs = int64(30000)

// ---- v2.7 第一刀/第二刀常量（《根治训练场 1~2 分钟后切换卡死超时指令》）----

// activeSessionGraceMs 活跃会话判定窗口：目标 IP 在 10s 内有回包 = 正在
// 承载活跃对局会话（确认点 1：recv>=1 且 10s 内有回包），本局绝不换主/换区。
const activeSessionGraceMs = int64(10000)

// birthGraceMs v2.8 铁律一：会话出生保护期（30s）。laneEntry 创建第 0
// 毫秒注册出生，出生后 30s 内无论有包无包，严禁 dueDegradeCheck 或任何
// 入口调用 SwitchToBestFallback 换节点（给足握手和地图加载时间）。
const birthGraceMs = int64(30000)

// badNodeTriggerMs 劣迹节点熔断触发阈值：curRtt > 150ms 即记过（确认点 3）。
const badNodeTriggerMs = 150

// badNodePenaltyMs 劣迹节点熔断期：30 分钟（确认点 3）。
const badNodePenaltyMs = int64(30 * 60 * 1000)

// badNodeRttPenalty 熔断期内读取侧叠加的 RTT 惩罚权重：+200ms（确认点 3）。
const badNodeRttPenalty = 200

// markBadNode 劣迹节点记过：curRtt>150ms 或 degraded 触发即写入熔断表
// （30 分钟），并废黜 bestRaceWinner——防下一局/下一个新目标进场时
// 劣迹节点继续当赛马冠军害人（批复顺序铁律：必须在活跃会话门卫之前执行，
// 当场记过拉黑，但本局不斩立决）。
func (m *Manager) markBadNode(proxy string) {
	if proxy == "" {
		return
	}
	until := time.Now().UnixMilli() + badNodePenaltyMs
	now := time.Now().UnixMilli()
	m.badNodeMu.Lock()
	if m.badNodeUntil == nil {
		m.badNodeUntil = make(map[string]int64)
	}
	oldUntil := m.badNodeUntil[proxy]
	fresh := oldUntil == 0 || oldUntil <= now
	if until > m.badNodeUntil[proxy] {
		m.badNodeUntil[proxy] = until
	}
	m.badNodeMu.Unlock()
	recordDiag("bad_mark", "proxy=%s fresh=%v until=%s penaltyMs=%d rttPenalty=%dms", displayProxy(proxy), fresh, time.UnixMilli(until).Format("15:04:05.000"), badNodePenaltyMs, badNodeRttPenalty)
	// 废黜 bestRaceWinner：若劣迹节点正是当前赛马实测冠军，清除
	// （下一局/下一个新目标立即换健康节点上位）。
	m.bestRaceMu.Lock()
	if m.bestRace != nil && m.bestRace.Proxy == proxy {
		log.Warnln("[GameRoute] bad node %s dethroned from bestRaceWinner (curRtt>=%dms)", displayProxy(proxy), badNodeTriggerMs)
		recordDiag("bad_dethrone", "proxy=%s trigger=curRtt>=%dms", displayProxy(proxy), badNodeTriggerMs)
		m.bestRace = nil
	}
	m.bestRaceMu.Unlock()
	log.Warnln("[GameRoute] bad node penalized: %s (30min, read-side +%dms)", displayProxy(proxy), badNodeRttPenalty)
}

// isBadNode 节点是否处于熔断期（>0ms 惩罚生效中）。
func (m *Manager) isBadNode(proxy string, now int64) bool {
	if proxy == "" {
		return false
	}
	m.badNodeMu.Lock()
	defer m.badNodeMu.Unlock()
	until, ok := m.badNodeUntil[proxy]
	if !ok {
		return false
	}
	if now >= until {
		delete(m.badNodeUntil, proxy)
		return false
	}
	return true
}

// ReportActiveRecv 上报目标 IP 收到回包（tunnel 层 markRecv 同点调用）：
// 活跃会话注册表的唯一写入源，供 SwitchToBestFallback/probeAndSettle
// 门卫判定"目标是否正在承载活跃对局会话"。
func (m *Manager) ReportActiveRecv(dst string, now int64) {
	if dst == "" {
		return
	}
	m.sessionActiveMu.Lock()
	if m.sessionActiveRecvAt == nil {
		m.sessionActiveRecvAt = make(map[string]int64)
	}
	if now > m.sessionActiveRecvAt[dst] {
		m.sessionActiveRecvAt[dst] = now
	}
	m.sessionActiveMu.Unlock()
}

// RegisterBirth 注册会话出生时刻（laneEntry 创建第 0 毫秒调用）：出生
// 保护期起点。出生后 birthGraceMs(30s) 内，无论有包无包，严禁任何入口
// 调用 SwitchToBestFallback 换节点（握手/地图加载期 0 回包是正常现象）。
func (m *Manager) RegisterBirth(dst string, now int64) {
	if dst == "" {
		return
	}
	m.sessionActiveMu.Lock()
	if m.sessionBirthAt == nil {
		m.sessionBirthAt = make(map[string]int64)
	}
	if now > m.sessionBirthAt[dst] {
		m.sessionBirthAt[dst] = now
	}
	m.sessionActiveMu.Unlock()
}

// birthProtected 会话是否处于出生保护期（30s 内）：命中 = 禁止一切
// SwitchToBestFallback 换节点（铁律一）。保护期度过自动清除注册，避免
// 注册表无限膨胀；后续切换资格由活跃会话门卫（10s 有回包）与隧道层
// 连续 10s 0 回包死链判定接管。
func (m *Manager) birthProtected(dst string, now int64) bool {
	if dst == "" {
		return false
	}
	m.sessionActiveMu.Lock()
	defer m.sessionActiveMu.Unlock()
	at, ok := m.sessionBirthAt[dst]
	if !ok {
		return false
	}
	if now-at < birthGraceMs {
		return true
	}
	delete(m.sessionBirthAt, dst)
	return false
}

// targetHasActiveSession 目标 IP 是否承载活跃对局会话（10s 内有回包）：
// 命中 = 本局免切锁生效，禁止 SwitchToBestFallback / probeAndSettle 换主。
// 顺带清理 60s 前的陈旧条目，防注册表无限膨胀。
func (m *Manager) targetHasActiveSession(dst string, now int64) bool {
	if dst == "" {
		return false
	}
	m.sessionActiveMu.Lock()
	defer m.sessionActiveMu.Unlock()
	at, ok := m.sessionActiveRecvAt[dst]
	if !ok {
		return false
	}
	if now-at >= activeSessionGraceMs {
		// 已连续 10s 无回包（死链）：清除并放行切换
		delete(m.sessionActiveRecvAt, dst)
		return false
	}
	for k, v := range m.sessionActiveRecvAt {
		if now-v > 60000 {
			delete(m.sessionActiveRecvAt, k)
		}
	}
	return true
}

// switchCooldownUntil 返回目标切换冷却剩余状态：>0 表示仍在冷却期（值为截止 UnixMilli），0 表示无冷却。
func (m *Manager) switchCooldownUntil(dst string) int64 {
	m.switchCooldownMu.Lock()
	defer m.switchCooldownMu.Unlock()
	until := m.switchCooldown[dst]
	if until == 0 {
		return 0
	}
	if time.Now().UnixMilli() >= until {
		delete(m.switchCooldown, dst)
		return 0
	}
	return until
}

// armSwitchCooldown 切换落地后武装冷却（F2）。map 惰性初始化（测试用裸
// Manager 时安全）。
func (m *Manager) armSwitchCooldown(dst string) {
	m.switchCooldownMu.Lock()
	if m.switchCooldown == nil {
		m.switchCooldown = make(map[string]int64)
	}
	m.switchCooldown[dst] = time.Now().UnixMilli() + switchCooldownMs
	m.switchCooldownMu.Unlock()
	recordDiag("cooldown_arm", "dst=%s cooldownMs=%d", dst, switchCooldownMs)
}

// SwitchCooldownUntil 暴露给状态 API（F12 可观测性）：目标 dst 的冷却截止（0=无冷却）。
func (m *Manager) SwitchCooldownUntil(dst string) int64 { return m.switchCooldownUntil(dst) }

// targetByDst 按会话远端 IP 查找命中目标（CIDR 匹配），未命中返回 nil。
func (m *Manager) targetByDst(dst string) *Target {
	addr, err := netip.ParseAddr(dst)
	if err != nil || !addr.IsValid() {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.targets {
		t := &m.targets[i]
		if len(t.CIDR) > 0 && cidrContains(t.CIDR, addr) {
			return t
		}
	}
	return nil
}

// EffectiveProxyForIP 返回该目标 IP 现行主路节点名（重建会话将拨的节点，
// 2026-10-18 v2.2 铁律一比较基准）。强制修正二（批复）：目标刚注册、
// currentPrimary 未初始化（auto 排队返回空串）时，主动走一次
// ensureAutoPrimary 链（段锁→记忆→GeoIP）尽量拿到确定节点名完成同节点
// 短路；仍拿不到返回空串，由铁律二 handshakeProtected 兜底（双保险）。
// 未注册 IP 返回空串。锁序与 MatchTarget 一致（m.mu.RLock 内走
// ensureAutoPicked，m.mu→primaryMu 既有顺序）。
func (m *Manager) EffectiveProxyForIP(ip string) string {
	if ip == "" {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.IsValid() {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var t *Target
	for i := range m.targets {
		if len(m.targets[i].CIDR) > 0 && cidrContains(m.targets[i].CIDR, addr) {
			t = &m.targets[i]
			break
		}
	}
	if t == nil {
		return ""
	}
	if name := t.EffectiveProxy(); name != "" {
		return name
	}
	// 门卫用 Proxy 模式（显式配置已在上方返回非空；autoPrimary 旗标要等
	// ensureAutoPrimary 才置位，不能作为这里的判据——否则目标从未 Match
	// 时初始化路径被挡，强制修正二失效）。
	if t.Proxy != "" && t.Proxy != "auto" {
		return ""
	}
	m.ensureAutoPicked(t, addr, "", m.allProxies, m.rttTable)
	return t.EffectiveProxy()
}

// bestRaceEntry 全局赛马实测最优条目（v2.4 第二刀 2.1）。
type bestRaceEntry struct {
	Proxy  string
	Region string
	RTTMs  int
	At     int64 // UnixMilli
}

// bestRaceTTL 全局最优新鲜期：超过即允许下一位赢家无条件覆盖（批复 2.1）。
const bestRaceTTL = 10 * 60 * 1000

// updateBestRaceWinner 赛马回包择优更新：仅当新赢家 rttMs < 现值、现值为
// 空、或现值超 10 分钟过期才更新——早回包的香港服赢家（28ms）绝不被晚
// 回包的欧美服赢家（160ms）篡位（批复 2.1 强制：bestRaceWinner 而非
// lastRaceWinner）。
func (m *Manager) updateBestRaceWinner(proxy, region string, rttMs int) {
	if proxy == "" || rttMs <= 0 {
		return
	}
	now := time.Now().UnixMilli()
	m.bestRaceMu.Lock()
	defer m.bestRaceMu.Unlock()
	if m.bestRace != nil && now-m.bestRace.At < bestRaceTTL && rttMs >= m.bestRace.RTTMs {
		return
	}
	old := ""
	if m.bestRace != nil {
		old = m.bestRace.Proxy
	}
	m.bestRace = &bestRaceEntry{Proxy: proxy, Region: region, RTTMs: rttMs, At: now}
	if old != proxy {
		log.Infoln("[GameRoute] best-race-winner = %s (%s, rtt=%dms)", proxy, region, rttMs)
	}
}

// bestRaceWinnerProxy 返回全场最优节点出口（v2.13 第一刀 1.2：Stale-While-Revalidate
// 软降级）。改造前 10min 过期即返回 false → 进场链掉到 pickPrimaryTemp 盲选
// （Fortnite 189ms 的起点）。改造后：
//   - 未过期：原样返回冠军（行为不变）；
//   - 已过期但冠军不在 badNode 熔断期：**仍返回旧冠军**（它已被 7770 实测为
//     全场最优，远优于任何 rtt=0 盲选），并异步触发一次 STUN 周期刷新来
//     重新确权（in-flight + 最小间隔去重，绝不并发重复扇出）；
//   - 已过期且冠军在 badNode：返回 false，交给后续档位（劣迹节点绝不复用）。
//
// 锁序：先取 bestRaceMu 快照并立即释放，再查 badNodeMu——与 markBadNode
// （badNodeMu → bestRaceMu）保持同向，杜绝反向锁环。
func (m *Manager) bestRaceWinnerProxy() (string, bool) {
	m.bestRaceMu.Lock()
	if m.bestRace == nil {
		m.bestRaceMu.Unlock()
		return "", false
	}
	proxy := m.bestRace.Proxy
	ageMs := time.Now().UnixMilli() - m.bestRace.At
	m.bestRaceMu.Unlock()

	if ageMs < bestRaceTTL {
		return proxy, true
	}
	now := time.Now().UnixMilli()
	if m.isBadNode(proxy, now) {
		log.Warnln("[GameRoute] stale best-race-winner %s is bad node, drop", displayProxy(proxy))
		recordDiag("best_race_stale_bad", "proxy=%s ageMs=%d", displayProxy(proxy), ageMs)
		return "", false
	}
	recordDiag("best_race_stale_reuse", "proxy=%s ageMs=%d", displayProxy(proxy), ageMs)
	log.Infoln("[GameRoute] best-race-winner %s stale (age=%ds) but healthy, reuse + async refresh",
		displayProxy(proxy), ageMs/1000)
	m.triggerSTUNRefreshAsync("best-race-stale")
	return proxy, true
}

// bestRaceEmpty 全局最优是否从未产生（冷启动扇出触发条件，漏洞一③）。
func (m *Manager) bestRaceEmpty() bool {
	m.bestRaceMu.Lock()
	defer m.bestRaceMu.Unlock()
	return m.bestRace == nil
}

// raceOnlyRTTTableLocked 仅保留 7770 赛马实测（Source=="race"）条目的拷贝——
// Cloudflare URLTest 数据不得参与进场选主裁决（v2.4 第二刀 2.5/反向验收）。
// 锁约定：调用方必须已持有 m.mu（≥RLock）——ensureAutoPrimary 的三个调用方
// （MatchTarget / RegisterTargetIPTrusted / matchTargetTCP）均满足既定锁序
// m.mu→primaryMu；锁内直读避免同 goroutine 写锁内再取 RLock 的自死锁。
func (m *Manager) raceOnlyRTTTableLocked() map[string]int {
	out := make(map[string]int, len(m.rttTable))
	for name, rt := range m.rttTable {
		if m.rttSource != nil && m.rttSource[name] == "race" {
			out[name] = rt
		}
	}
	return out
}

// rttTableLockedCopy 全量 RTT 表拷贝（含 race + urltest 全部实测值）。
// v2.13 第二刀（2.1）：进场选主第 5 档需要"全量实测"口径，与
// raceOnlyRTTTableLocked 相对。锁约定同 raceOnlyRTTTableLocked：调用方
// 必须已持有 m.mu（≥RLock）。
func (m *Manager) rttTableLockedCopy() map[string]int {
	out := make(map[string]int, len(m.rttTable))
	for name, rt := range m.rttTable {
		out[name] = rt
	}
	return out
}

// maxIntTable 合并两张 RTT 表（同名取较大值，语义为"更保守的耗时"），
// 供 recordPrimarySnapshot 记录与状态展示使用；不改变选路决策。
func maxIntTable(a, b map[string]int) map[string]int {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	out := make(map[string]int, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if old, ok := out[k]; !ok || v > old {
			out[k] = v
		}
	}
	return out
}

// lowestRttByRegions 在指定区标签序列内挑 RTT 最低的**已实测**节点（rtt>0），
// 返回节点名 / RTT / 命中区。用于 v2.13 第二刀第 5 档：race 源空窗时用
// urltest 已实测的港台低延迟节点兜底，保证"只选实测过的节点"铁律。
func lowestRttByRegions(allProxies []string, rttTable map[string]int, tags ...string) (string, int, string) {
	if len(allProxies) == 0 || len(rttTable) == 0 || len(tags) == 0 {
		return "", 0, ""
	}
	best, bestRtt, bestTag := "", 0, ""
	for _, tag := range tags {
		for _, n := range FilterByRegion(allProxies, "", tag) {
			rt, ok := rttTable[n]
			if !ok || rt <= 0 {
				continue
			}
			if best == "" || rt < bestRtt {
				best, bestRtt, bestTag = n, rt, tag
			}
		}
		// 玩家侧近距约束：高优先区标签（"HK" 在 "TW" 之前）已有实测节点
		// 即定案，不再让远处区以微小 RTT 差越级——大陆玩家入口优先港。
		if best != "" {
			return best, bestRtt, bestTag
		}
	}
	return best, bestRtt, bestTag
}

// MarkGameActive 游戏临战活跃态（v2.4 漏洞三修正）：任一游戏特征事件
// （捕获 7770 测速包 / IsGameDomain 命中 / MatchIP 段表命中 / 识别游戏
// 进程）刷新 now+60s——玩家一打开游戏发了任何测速/登录包，内核立刻进入
// 临战态，对局首包 100% 走 1.2 秒接管路径。
func (m *Manager) MarkGameActive() {
	m.gameActiveUntil.Store(time.Now().UnixMilli() + 60000)
}

// GameActive 返回是否处于游戏临战活跃态（60s 内有游戏特征事件）。
func (m *Manager) GameActive() bool {
	return m.gameActiveUntil.Load() > time.Now().UnixMilli()
}

// recordTargetHit 记录目标命中：包数 +1、更新最后活跃时间、
// 当前实际出口与区域、RTT（取现有测量缓存，不新增探测）。
// t 必须是 MatchTarget 命中返回的 *Target（指向注册表内元素，
// 调用方持有 m.mu 读锁，扩展字段由 t.extMu 保护）。
func (m *Manager) recordTargetHit(t *Target, dstIP netip.Addr, proxy string, rttTable map[string]int) {
	now := time.Now()
	t.extMu.Lock()
	t.Packets++
	t.LastSeen = &now
	if proxy != "" {
		t.CurrentProxy = proxy
		if reg, ok := extractRegionTag(proxy); ok {
			t.CurrentRegion = reg
		}
	}
	if rt, ok := rttTable[proxy]; ok && rt > 0 {
		t.RTT = rt
	}
	if t.Region == "" {
		if r := m.lookUpRegionActual(dstIP.String()); r != "" {
			t.Region = r
		}
	}
	t.extMu.Unlock()
}

// lowestRtt 从候选池取 RTT 最低且有效的节点；全部无 RTT 数据返回 ("", false)。
func lowestRtt(names []string, rttTable map[string]int) (string, bool) {
	best, bestRtt := "", 0
	for _, n := range names {
		rt, ok := rttTable[n]
		if !ok || rt <= 0 {
			continue
		}
		if best == "" || rt < bestRtt {
			best, bestRtt = n, rt
		}
	}
	return best, best != ""
}

// safeRandomPick 空池安全的随机选择（F5 崩溃加固）：len(pool)==0 时
// rand.Intn(0) 会直接 panic（2026-10-16 02:42 实锤进程崩溃，诊断 RC5a），
// 全部随机选点统一收口到本函数。
func safeRandomPick(pool []string) (string, bool) {
	if len(pool) == 0 {
		return "", false
	}
	return pool[rand.Intn(len(pool))], true
}

// 自动圈选：从全局节点列表中过滤同地区节点，按 RTT 排序取 top N。
// fallbacks 由配置决定：配置写了则优先于自动圈选。
func (m *Manager) autoPickFallbacks(proxyName string, allProxies []string, rttTable map[string]int) []string {
	// 提取主代理的地区标签
	region, hasRegion := extractRegionTag(proxyName)
	if !hasRegion {
		// 无法确定地区标签，退回配置优先逻辑
		return nil
	}

	// 过滤同地区节点
	regional := FilterByRegion(allProxies, proxyName, region)
	if len(regional) == 0 {
		// 兜底：无同地区节点 → 退化到全局 RTT top N
		regional = make([]string, 0, len(allProxies))
		for _, n := range allProxies {
			if rt, ok := rttTable[n]; ok && rt > 0 {
				regional = append(regional, n)
			}
		}
	}

	// 按 RTT 排序，取 top N
	return topNByRtt(regional, rttTable, m.candidateTopN)
}

func cidrContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// MatchTCP 判定 TCP 元数据是否命中 gameroute 固定快速通道
// （PUBG 大厅/登录等仅 TCP 流量阶段的入口）。
//
// 与 Match（UDP 预测式切换）严格隔离，硬约束：
//   - TCP 只走固定快速通道：auto 目标取进场临时主节点（最低 RTT/随机）作为
//     固定出口快照，显式目标取配置 Proxy，之后保持稳定；
//   - 绝不参与预测式切换 / 劣化自动切换：不生成候选池（Fallbacks 保持原样）、
//     不触发候选探测换优、不刷新 RTT 圈选（TCP 是有状态协议，中途切节点 =
//     连接断开重连，比不加速更糟）；
//   - TCP 会话不计入 switch_count / last_switch_at / 乒乓判定——切换语义只属于
//     UDP 预测式切换（RecordM3Active 仅刷新 current_proxy，不做任何切换记账）；
//   - 命中回报 current_proxy（出口非空时），让大厅阶段面板有真实出口展示。
//
// 返回当前固定出口名（auto 模式为空池时回退默认出口；仍无则保持上一
// 出口或返回空串排队等待选路，绝不直连），未命中返回 ("", false)，
// 对默认流程零影响。
func (m *Manager) MatchTCP(metadata *C.Metadata, isTUN bool) (string, bool) {
	t, ok := m.matchTargetTCP(metadata, isTUN)
	if !ok {
		return "", false
	}
	px := t.EffectiveProxy()
	if px == "" {
		// 游戏加速流量绝不直连：空池回退默认出口，仍无则保持上一出口。
		px = m.safeProxy("")
		if px == "" {
			log.Errorln("[GameRoute] no proxy available, holding (tcp)")
		}
	}
	m.rememberProxy(px)
	if px != "" {
		// 回报具体出口；空值表示排队等待选路（不放行直连）
		RecordM3Active(px)
	}
	log.Infoln("[GameRoute] tcp matched target -> proxy %s (fixed, fallbacks=%d)",
		displayProxy(px), len(t.Fallbacks))
	return px, true
}

// displayProxy 仅用于日志展示：空出口（排队等待选路）显示为 holding。
func displayProxy(px string) string {
	if px == "" {
		return "holding"
	}
	return px
}

// matchTargetTCP 同 MatchTCP 但返回命中的 Target（仅包内使用）。
// 命中判定与 MatchTarget 一致（进程名非 TUN 优先，其次 CIDR），
// 但命中后只走 ensureTCPPrimary 固定出口逻辑，绝不生成候选池。
func (m *Manager) matchTargetTCP(metadata *C.Metadata, isTUN bool) (*Target, bool) {
	if !m.Enabled() {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	targets := m.targets
	allProxies := m.allProxies
	rttTable := m.rttTable
	if len(targets) == 0 {
		return nil, false
	}

	processName := metadata.Process
	if !isTUN && processName == "" {
		// PID 优先：Process 未填充时按会话源地址反查一次进程
		if _, name := findProcess(metadata); name != "" {
			processName = name
		}
	}

	for i := range targets {
		t := &targets[i]
		if !isTUN && t.ProcessName != "" && t.ProcessName == processName {
			m.ensureTCPPrimary(t, metadata.DstIP, allProxies, rttTable)
			px := t.EffectiveProxy()
			if px == "" {
				// 游戏加速流量绝不直连：空出口回退默认出口，
				// 默认出口也缺失时保持上一个可用出口。
				px = m.safeProxy("")
			}
			m.recordTargetHit(t, metadata.DstIP, px, rttTable)
			return t, true
		}
		if len(t.CIDR) > 0 && cidrContains(t.CIDR, metadata.DstIP) {
			m.ensureTCPPrimary(t, metadata.DstIP, allProxies, rttTable)
			px := t.EffectiveProxy()
			if px == "" {
				px = m.safeProxy("")
			}
			m.recordTargetHit(t, metadata.DstIP, px, rttTable)
			return t, true
		}
	}
	return nil, false
}

// ensureTCPPrimary 为 TCP 固定快速通道保证出口快照可用：
//   - auto 目标（Proxy 为空或 "auto"）：标记 autoPrimary，若尚无主节点则按
//     pickPrimaryTemp 选定固定出口（GeoIP 同地区 RTT 最低/随机，记忆 Proxy 优先），
//     已有则保持不动；
//   - 显式目标：出口即配置 Proxy，无需处理；
//   - 不做任何候选池圈选/刷新（区别于 ensureAutoPrimary 的 UDP 语义）。
func (m *Manager) ensureTCPPrimary(t *Target, dstIP netip.Addr, allProxies []string, rttTable map[string]int) {
	if t.Proxy != "" && t.Proxy != "auto" {
		return
	}
	t.primaryMu.Lock()
	defer t.primaryMu.Unlock()
	t.autoPrimary = true
	if t.currentPrimary == "" {
		t.currentPrimary = m.pickPrimaryTemp(dstIP, allProxies, rttTable)
	}
}
