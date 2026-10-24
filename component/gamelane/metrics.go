package gamelane

// v2.10 P1（2026-10-19）：GameLane 示波器埋点计数器。
//
// 设计红线：
//  1. 热路径只允许 atomic.Add，零锁、零分配、零字符串格式化——
//     isGameProcessName / IsSpeedtestProbePayloadForPort / isKnownGamePort /
//     isCloudSegmentIP / IsGameDomain 都跑在每包或每 DNS 查询路径上，
//     任何 recordDiag（Sprintf + 环形锁）都会被秒级风暴打爆。
//  2. 环形事件（recordDiagFields）只允许出现在"每会话一次"或"每次切换一次"
//     的低频决策点，保证 2048 槽覆盖足够长的因果链。
//
// 计数器回答的问题：v2.9 扩容的名单/端口/段/魔数到底命中了多少次、被哪一道
// 闸门挡掉多少次——事件流只记录决策结果，计数器记录判定分布。

import (
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

var (
	// ---- 进程识别（A 项 29 条关键词 + Code.exe 排除）----
	metricsProcKeywordHit   atomic.Uint64 // isGameProcessName 命中关键词
	metricsProcCodeExcluded atomic.Uint64 // VSCode Code.exe 被显式排除

	// ---- 注册路径（RegisterGameTargetIfNeeded）----
	metricsRegSegmentHit      atomic.Uint64 // 段表命中直接注册
	metricsRegDomainHit       atomic.Uint64 // 游戏域名命中直接注册
	metricsRegProcHit         atomic.Uint64 // 进程名确认后注册
	metricsRegBlockPort       atomic.Uint64 // 排除端口总闸拦截
	metricsRegBlockFakeIP     atomic.Uint64 // Fake-IP 地址拦截
	metricsRegBlockExcluded   atomic.Uint64 // 排除段/非公网拦截
	metricsRegBlockNotGame    atomic.Uint64 // 进程非游戏拦截
	metricsRegBlockUnknownPID atomic.Uint64 // 进程反查失败

	// ---- 字节扳机（D 项：0xffffffff / STUN / RakNet）----
	metricsProbeMagicHit   atomic.Uint64 // 0xffffffff 命中
	metricsProbeStunHit    atomic.Uint64 // STUN Binding Request 命中
	metricsProbeRaknetHit  atomic.Uint64 // RakNet Unconnected Ping 命中
	metricsProbeGuardBlock atomic.Uint64 // 端口守卫挡掉的 STUN/RakNet 候选包

	// ---- 端口 / 段 / 域名（B/C/E 项）----
	metricsKnownPortHit       atomic.Uint64 // isKnownGamePort 命中（flow 打分强信号）
	metricsMatchServerPortHit atomic.Uint64 // isMatchServerPort 命中（含 5000-5500）
	metricsCloudSegHit        atomic.Uint64 // cloudGameSegments 命中
	metricsDomainTableHit     atomic.Uint64 // 段表域名树命中
	metricsSuffixHit          atomic.Uint64 // 内置后缀清单命中

	// ---- 记忆加载（LoadMemory，v2.10.2）----
	// 红线：proc_keyword_hit 只统计"运行期真实进程判定"，不得被记忆文件
	// 加载时的历史条目校验污染——加载校验走下面这组独立计数器。
	metricsMemoryProcValidated atomic.Uint64 // 加载时污染校验遍历过的进程条目数
	metricsMemoryLoaded        atomic.Uint64 // 加载实际载入的条目数（累计）
	metricsMemoryReloadSkipped atomic.Uint64 // 配置重载命中幂等/快照而跳过重复加载的次数

	// ---- 入口分母（2026-10-21 可观测性 P0-2）----
	// 口径：GameLane 激活态流经 ObserveUDPFlow 的 UDP 包总数（含已注册/
	// 非候选/被闸门拒绝），与注册成功目标总数。前者观测"流量是否进内核"，
	// 后者与 dump 的 target_count 变化对齐。
	metricsObservedFlowTotal atomic.Uint64 // ObserveUDPFlow 调用总数
	metricsRegisteredTotal   atomic.Uint64 // RegisterTargetIPTrusted 注册成功总数
)

// DiagMetrics 是计数器快照的对外结构（GET /gameroute/diag/metrics）。
// 全部为单调递增累计值，前端按两次采样的差值算速率。
type DiagMetrics struct {
	ProcKeywordHit   uint64 `json:"proc_keyword_hit"`
	ProcCodeExcluded uint64 `json:"proc_code_excluded"`

	RegSegmentHit      uint64 `json:"reg_segment_hit"`
	RegDomainHit       uint64 `json:"reg_domain_hit"`
	RegProcHit         uint64 `json:"reg_proc_hit"`
	RegBlockPort       uint64 `json:"reg_block_port"`
	RegBlockFakeIP     uint64 `json:"reg_block_fakeip"`
	RegBlockExcluded   uint64 `json:"reg_block_excluded"`
	RegBlockNotGame    uint64 `json:"reg_block_notgame"`
	RegBlockUnknownPID uint64 `json:"reg_block_unknown_pid"`

	ProbeMagicHit   uint64 `json:"probe_magic_hit"`
	ProbeStunHit    uint64 `json:"probe_stun_hit"`
	ProbeRaknetHit  uint64 `json:"probe_raknet_hit"`
	ProbeGuardBlock uint64 `json:"probe_guard_block"`

	KnownPortHit       uint64 `json:"known_port_hit"`
	MatchServerPortHit uint64 `json:"match_server_port_hit"`
	CloudSegHit        uint64 `json:"cloud_seg_hit"`
	DomainTableHit     uint64 `json:"domain_table_hit"`
	SuffixHit          uint64 `json:"suffix_hit"`

	// 记忆加载口径（与 proc_keyword_hit 彻底解耦）
	MemoryProcValidated uint64 `json:"memory_proc_validated"`
	MemoryLoaded        uint64 `json:"memory_loaded"`
	MemoryReloadSkipped uint64 `json:"memory_reload_skipped"`

	// 入口分母（2026-10-21 P0-2）：observed_flow_total ≥ registered_total。
	ObservedFlowTotal uint64 `json:"observed_flow_total"`
	RegisteredTotal   uint64 `json:"registered_total"`
}

// DiagMetricsSnapshot 读取全部计数器（无锁快照，各字段之间不保证严格同一时刻，
// 用于观测趋势与命中分布，不作为一致性断言依据）。
func DiagMetricsSnapshot() DiagMetrics {
	return DiagMetrics{
		ProcKeywordHit:   metricsProcKeywordHit.Load(),
		ProcCodeExcluded: metricsProcCodeExcluded.Load(),

		RegSegmentHit:      metricsRegSegmentHit.Load(),
		RegDomainHit:       metricsRegDomainHit.Load(),
		RegProcHit:         metricsRegProcHit.Load(),
		RegBlockPort:       metricsRegBlockPort.Load(),
		RegBlockFakeIP:     metricsRegBlockFakeIP.Load(),
		RegBlockExcluded:   metricsRegBlockExcluded.Load(),
		RegBlockNotGame:    metricsRegBlockNotGame.Load(),
		RegBlockUnknownPID: metricsRegBlockUnknownPID.Load(),

		ProbeMagicHit:   metricsProbeMagicHit.Load(),
		ProbeStunHit:    metricsProbeStunHit.Load(),
		ProbeRaknetHit:  metricsProbeRaknetHit.Load(),
		ProbeGuardBlock: metricsProbeGuardBlock.Load(),

		KnownPortHit:       metricsKnownPortHit.Load(),
		MatchServerPortHit: metricsMatchServerPortHit.Load(),
		CloudSegHit:        metricsCloudSegHit.Load(),
		DomainTableHit:     metricsDomainTableHit.Load(),
		SuffixHit:          metricsSuffixHit.Load(),

		MemoryProcValidated: metricsMemoryProcValidated.Load(),
		MemoryLoaded:        metricsMemoryLoaded.Load(),
		MemoryReloadSkipped: metricsMemoryReloadSkipped.Load(),

		ObservedFlowTotal: metricsObservedFlowTotal.Load(),
		RegisteredTotal:   metricsRegisteredTotal.Load(),
	}
}

// ---- v2.10.1 诊断：proc_keyword_hit 命中来源采样 ----
//
// 目的：定位"没开游戏但 proc_keyword_hit 持续增长"的命中来源——记录命中
// 进程名 + 调用方函数名。加锁与格式化仅发生在命中分支（低频），不触碰
// 每包判定路径的零分配红线；同名首次及每 50 次各打一条 info 日志，避免
// 日志风暴。
var procKwHitSamples struct {
	sync.Mutex
	byName   map[string]uint64
	byCaller map[string]uint64
}

func recordProcKwHitSample(name string) {
	metricsProcKeywordHit.Add(1)
	caller := "unknown"
	if pc, _, _, ok := runtime.Caller(2); ok {
		if fn := runtime.FuncForPC(pc); fn != nil {
			caller = fn.Name()
			if i := strings.LastIndex(caller, "."); i >= 0 {
				caller = caller[i+1:]
			}
		}
	}
	s := &procKwHitSamples
	s.Lock()
	if s.byName == nil {
		s.byName = make(map[string]uint64)
	}
	if s.byCaller == nil {
		s.byCaller = make(map[string]uint64)
	}
	s.byName[name]++
	s.byCaller[caller]++
	n := s.byName[name]
	c := s.byCaller[caller]
	s.Unlock()
	if n == 1 || n%50 == 0 {
		log.Infoln("[GameRoute] proc-keyword hit name=%q caller=%s count=%d caller_count=%d", name, caller, n, c)
	}
}

// probeProtoMagic / probeProtoSTUN / probeProtoRakNet 是 tunnel 层上报的扳机类型。
const (
	probeProtoMagic  = "magic"
	probeProtoSTUN   = "stun"
	probeProtoRakNet = "raknet"

	// probeKindGuard：形似 STUN/RakNet 但端口被守卫否决（仅计数口径）。
	probeKindGuard = "guard"
	// probeKindNone：不是测速探针。
	probeKindNone = ""
)

// RecordProbeTrigger 由 tunnel 层在字节扳机命中、即将起跑赛马时调用（每会话
// 至多一次，低频）。事件进入环形缓冲后，示波器可以直接看到"是哪种魔数把
// 这条会话拉进了五路克隆"，避免 v2.9 新分支成为黑盒。
func RecordProbeTrigger(proto, dst string, dport uint16) {
	recordDiagFields("probe_trigger", dst, int(dport), "", proto,
		"%s probe trigger %s:%d", proto, dst, dport)
}

// RecordProbeTriggerFromPayload 供 tunnel 在已确认命中扳机后补记一次事件：
// 内部复用 probeKind 判定类型（不重复计数），保证与 IsSpeedtestProbePayloadForPort
// 完全同口径。
//
// 风暴保护：扳机判定跑在每包路径上（例如 GameLift 探测包可能成串到达），
// 同一 dst:port 2 秒内只产生一条事件，避免 2048 槽被单条会话刷爆；守卫表
// 每分钟惰性清理一次过期项，规模上限与会话数同阶。
func RecordProbeTriggerFromPayload(payload []byte, dst string, dport uint16) {
	key := dst + "|" + strconv.Itoa(int(dport))
	now := time.Now().UnixMilli()

	probeEmitGuard.Lock()
	if probeEmitGuard.seen == nil {
		probeEmitGuard.seen = make(map[string]int64)
	}
	if now-probeEmitGuard.lastSweep > probeEmitSweepMillis {
		for k, v := range probeEmitGuard.seen {
			if now-v > probeEmitSweepMillis {
				delete(probeEmitGuard.seen, k)
			}
		}
		probeEmitGuard.lastSweep = now
	}
	if last, ok := probeEmitGuard.seen[key]; ok && now-last < probeEmitDedupeMillis {
		probeEmitGuard.Unlock()
		return
	}
	probeEmitGuard.seen[key] = now
	probeEmitGuard.Unlock()

	proto := probeKind(payload, dport)
	if proto == probeKindNone || proto == probeKindGuard {
		proto = "unknown"
	}
	RecordProbeTrigger(proto, dst, dport)
}

const (
	probeEmitDedupeMillis = 2000
	probeEmitSweepMillis  = 60000
)

var probeEmitGuard struct {
	sync.Mutex
	seen      map[string]int64
	lastSweep int64
}
