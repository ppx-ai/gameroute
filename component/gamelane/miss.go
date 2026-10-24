package gamelane

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// ---- 未命中聚合表（2026-10-21 miss.go）----
//
// 需求背景：识别即注册链路的"拒绝"分支此前只有 metrics.go 的 8 个 atomic
// 计数器（只记次数不记是谁），isGameProcess 算出的细分原因在 notgame 分支
// 被直接丢弃；diag.go 的 2048 条事件环专供卡顿因果链，不能塞未命中明细。
// 结果是"某游戏为什么没被加速"无法定位。
//
// 本文件只做纯观测：
//   - 一级聚合 key = 进程完整路径（小写）。单进程只占 1 槽位，杜绝
//     chrome/微信 之类进程连几百个 dst 冲爆容量上限；
//   - 进程反查失败（拿不到 PID/路径）单独入 <<unknown_pid>> 桶；
//   - 进程反查之前的闸门（排除端口总闸 / Fake-IP）无身份可用，入
//     <<no_proc>> 桶（这两处按设计位于 findProcessByPort 之前，做反查
//     会引入秒级首包延迟，因此不反查、只记闸门命中量）；
//   - 表容量 256、TTL 10 分钟惰性清理、读写加锁；
//   - 判定逻辑零改动：所有原因码都在本文件映射，isGameProcess /
//     RegisterTargetIPTrusted / flow.go 的 return 语义一字未动。
//
// 读取方式：GET /gameroute/diag/miss（见 hub/route/gamelane.go）。

const (
	// MissTableCapacity 聚合表容量上限（条目数）。
	MissTableCapacity = 256
	// MissTTLSec 条目有效期（秒），与 missTTL 同源。
	MissTTLSec = 600
	// missTTL 条目有效期：lastSeen 距今超过该值即视为失效。
	missTTL = 10 * time.Minute
	// missSampleDstMax 每个进程保留的目标样本数上限（"ip:port"）。
	missSampleDstMax = 5
	// missDirFilesMax 目录内文件名采样上限（DLL/子目录名）。
	missDirFilesMax = 10
	// missActiveHitCount 高活跃判定阈值（priority +2）。
	missActiveHitCount = 20
	// missKeyUnknownPID 进程反查失败专用桶。
	missKeyUnknownPID = "<<unknown_pid>>"
	// missKeyNoProc 进程反查之前的闸门（port/fakeip）专用桶。
	missKeyNoProc = "<<no_proc>>"
)

// 原因码（钉死，与现有代码/计数器一一对应）。
const (
	// MissReasonUnrecognized isGameProcess=false 且 reason 为空（无关键词、无引擎 DLL）。
	MissReasonUnrecognized = "unrecognized"
	// MissReasonAux isGameProcess=false 且 reason 为 aux/vscode（辅助/启动器/编辑器）。
	MissReasonAux = "aux"
	// MissReasonUnknownPID 进程反查失败（findProcessByPort/findProcess 拿不到路径）。
	MissReasonUnknownPID = "unknown_pid"
	// MissReasonExcluded 排除层/非公网 IPv4 拦截（isExcludedIP 等）。
	MissReasonExcluded = "excluded"
	// MissReasonPort 排除端口拦截（skipAutoRegPorts）。
	MissReasonPort = "port"
	// MissReasonFakeIP Fake-IP 地址拦截（resolver.IsFakeIP）。
	MissReasonFakeIP = "fakeip"
	// MissReasonFlowLowScore flow 打分不足（低分忽略 / 疑似分未连续上升），
	// 2026-10-21 可观测性 P0-1：让"差多少分才没注册"可见。
	MissReasonFlowLowScore = "flow_low_score"
)

// missGameDirFeatures 游戏安装目录特征（priority +3，只作排序不作判定）。
var missGameDirFeatures = []string{
	"steamapps", "epic games", "riot games", "origin games", "battle.net", `\games\`,
}

// missExeNameFeatures 可执行文件名宽泛游戏特征（priority +1，只作排序不作判定）。
var missExeNameFeatures = []string{
	"shipping", "launcher", "win64", "game", "play",
}

// MissEntry 单条未命中聚合记录（API 输出结构）。
// 未导出字段为内部聚合状态，不参与 JSON 序列化。
type MissEntry struct {
	ProcessPath string            `json:"process_path"`          // 进程完整路径（小写，<用户名> 已脱敏）
	ExeName     string            `json:"exe_name"`              // 进程 basename
	HitCount    uint64            `json:"hit_count"`             // 聚合命中次数
	FirstSeen   int64             `json:"first_seen"`            // 首次命中（UnixMilli）
	LastSeen    int64             `json:"last_seen"`             // 最近命中（UnixMilli）
	Reasons     map[string]uint64 `json:"reasons"`               // reason -> 计数
	SampleDsts  []string          `json:"sample_dsts"`           // 目标样本（最多 5 个 "ip:port"）
	CheckedDir  string            `json:"checked_dir,omitempty"` // 判定时嗅探的进程目录
	DirFiles    []string          `json:"dir_files,omitempty"`   // 目录内 DLL/子目录名采样（最多 10 个）
	Priority    int               `json:"priority"`              // 排序优先级
	// FlowScore/FlowThreshold 仅 flow_low_score 条目有值：最近一次打分与判定
	// 阈值（疑似线），用于回答"离注册还差多少分"。
	FlowScore     int `json:"flow_score,omitempty"`
	FlowThreshold int `json:"flow_threshold,omitempty"`

	// sampleAddrs 内部保存结构化目标：热路径比较零分配，快照时才格式化。
	sampleAddrs []netip.AddrPort
	// basePriority 与命中次数无关的优先级（路径特征 + exeName 特征）。
	basePriority int
}

// MissReport GET /gameroute/diag/miss 的响应体。
type MissReport struct {
	Capacity int         `json:"capacity"`
	TTLSec   int         `json:"ttl_sec"`
	Total    int         `json:"total"`
	Entries  []MissEntry `json:"entries"`
	// ObservedTotal / RegisteredTotal 入口分母（2026-10-21 P0-2）：
	// GameLane 激活态流经 ObserveUDPFlow 的 UDP 包总数 与 注册成功目标总数。
	// 两者均为 0 表示流量根本没进内核（①）；observed 大而 entries 空表示
	// 全部加速成功；observed 大、registered 小、entries 有值 → 看原因码。
	ObservedTotal   uint64 `json:"observed_total"`
	RegisteredTotal uint64 `json:"registered_total"`
}

var (
	missMu    sync.RWMutex
	missTable = make(map[string]*MissEntry, MissTableCapacity)
)

// missRecord 记录一次未命中（纯埋点，判定逻辑零影响）。
//
// 热路径约束（同指令 §3）：
//   - 已存在条目只做 map 查找 + 计数累加 + 时间戳更新；
//   - 不做字符串格式化（dst 以 netip.Addr 传入，快照时才拼 "ip:port"）；
//   - 首次建行才计算 basename / 目录并做一次目录采样；
//   - 严禁调用 recordDiag（事件环只服务卡顿因果链）。
//
// processPath 为进程完整路径（可为空：空表示无进程身份，按 reason 落桶）。
func missRecord(processPath string, dst netip.Addr, port uint16, reason string) {
	if reason == "" {
		return
	}
	key := missAggregateKey(processPath, reason)
	nowMs := time.Now().UnixMilli()
	addrPort := netip.AddrPortFrom(dst, port)
	hasDst := dst.IsValid()

	missMu.Lock()
	e := missTable[key]
	if e != nil && nowMs-e.LastSeen > missTTL.Milliseconds() {
		delete(missTable, key)
		e = nil
	}
	if e != nil {
		e.HitCount++
		e.LastSeen = nowMs
		e.Reasons[reason]++
		e.Priority = missPriority(e.basePriority, e.HitCount)
		if hasDst {
			missAddSampleLocked(e, addrPort)
		}
		missMu.Unlock()
		return
	}
	// 惰性清理：只在新建条目时扫一遍（表容量 256，开销可忽略）。
	missPruneExpiredLocked(nowMs)
	if len(missTable) >= MissTableCapacity {
		missEvictOneLocked()
	}
	e = &MissEntry{
		ProcessPath: strings.ToLower(processPath),
		HitCount:    1,
		FirstSeen:   nowMs,
		LastSeen:    nowMs,
		Reasons:     map[string]uint64{reason: 1},
	}
	if e.ProcessPath != "" {
		e.ExeName = processBaseName(e.ProcessPath)
		dir := filepath.Dir(e.ProcessPath)
		if dir != "" && dir != "." && dir != e.ProcessPath {
			e.CheckedDir = dir
		}
	}
	e.basePriority = missBasePriority(e.ProcessPath, e.ExeName)
	e.Priority = missPriority(e.basePriority, e.HitCount)
	if hasDst {
		missAddSampleLocked(e, addrPort)
	}
	missTable[key] = e
	checkedDir := e.CheckedDir
	missMu.Unlock()

	// 首次建行才采样目录内容（磁盘 I/O 不持锁，也不进入重复热路径）。
	if checkedDir != "" {
		files := missSampleDirFiles(checkedDir)
		if len(files) > 0 {
			missMu.Lock()
			if cur, ok := missTable[key]; ok && cur == e && len(cur.DirFiles) == 0 {
				cur.DirFiles = files
			}
			missMu.Unlock()
		}
	}
}

// missRecordFlow flow 打分拒绝专用埋点（2026-10-21 P0-1）：
// 先按 flow_low_score 落一条 miss（复用 missRecord 的全部聚合/淘汰/脱敏逻辑），
// 再回填最近一次打分与阈值。只回填字段，不做任何判定，不影响既有调用方。
//
// 锁序：调用方（flow.go）此时持 m.flowsMu，本函数内部只碰 missMu，
// 严禁在 missMu 内反向调用任何 Manager/flow 方法（现无此路径）。
func missRecordFlow(processPath string, dst netip.Addr, port uint16, score, threshold int) {
	missRecord(processPath, dst, port, MissReasonFlowLowScore)
	key := missAggregateKey(processPath, MissReasonFlowLowScore)
	missMu.Lock()
	if e := missTable[key]; e != nil {
		e.FlowScore = score
		e.FlowThreshold = threshold
	}
	missMu.Unlock()
}

// MissSnapshot 返回当前有效条目的只读快照（TTL 惰性清理在此发生）。
// 顺序：priority desc, hit_count desc, last_seen desc。
func MissSnapshot() MissReport {
	nowMs := time.Now().UnixMilli()

	missMu.Lock()
	missPruneExpiredLocked(nowMs)
	out := make([]MissEntry, 0, len(missTable))
	for _, e := range missTable {
		cp := *e
		cp.ProcessPath = missMaskPath(e.ProcessPath)
		cp.CheckedDir = missMaskPath(e.CheckedDir)
		if len(e.Reasons) > 0 {
			cp.Reasons = make(map[string]uint64, len(e.Reasons))
			for k, v := range e.Reasons {
				cp.Reasons[k] = v
			}
		}
		cp.SampleDsts = make([]string, 0, len(e.sampleAddrs))
		for _, ap := range e.sampleAddrs {
			cp.SampleDsts = append(cp.SampleDsts, ap.String())
		}
		if len(e.DirFiles) > 0 {
			cp.DirFiles = append([]string(nil), e.DirFiles...)
		}
		cp.sampleAddrs = nil
		out = append(out, cp)
	}
	missMu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if out[i].HitCount != out[j].HitCount {
			return out[i].HitCount > out[j].HitCount
		}
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].ProcessPath < out[j].ProcessPath
	})

	return MissReport{
		Capacity:        MissTableCapacity,
		TTLSec:          MissTTLSec,
		Total:           len(out),
		Entries:         out,
		ObservedTotal:   metricsObservedFlowTotal.Load(),
		RegisteredTotal: metricsRegisteredTotal.Load(),
	}
}

// missReasonForIdent 把 isGameProcess 的 reason 映射成 miss 原因码
// （aux/vscode 统一归 aux，其余 false 情形归 unrecognized）。
func missReasonForIdent(reason string) string {
	switch reason {
	case "aux", "vscode":
		return MissReasonAux
	default:
		return MissReasonUnrecognized
	}
}

// missReasonForCandidate 把 isAutoRegCandidate=false 细分出 port / excluded。
// 只读取现有判定表，不新增判定逻辑。
func missReasonForCandidate(metadata *C.Metadata) string {
	if skipAutoRegPorts[metadata.DstPort] {
		return MissReasonPort
	}
	return MissReasonExcluded
}

// missAggregateKey 聚合 key：进程路径优先，无身份时按 reason 落专用桶。
func missAggregateKey(processPath, reason string) string {
	if processPath != "" {
		return strings.ToLower(processPath)
	}
	if reason == MissReasonUnknownPID {
		return missKeyUnknownPID
	}
	return missKeyNoProc
}

// missPriority 优先级 = 路径/exe 特征 + 高活跃加权（≥20 次 +2）。
func missPriority(base int, hitCount uint64) int {
	p := base
	if hitCount >= missActiveHitCount {
		p += 2
	}
	return p
}

// missBasePriority 路径特征 +3、exeName 特征 +1（只作排序，不作判定）。
func missBasePriority(processPath, exeName string) int {
	p := 0
	for _, f := range missGameDirFeatures {
		if strings.Contains(processPath, f) {
			p += 3
			break
		}
	}
	for _, f := range missExeNameFeatures {
		if exeName != "" && strings.Contains(exeName, f) {
			p++
			break
		}
	}
	return p
}

// missAddSampleLocked 追加目标样本（去重，最多 missSampleDstMax 个）。
func missAddSampleLocked(e *MissEntry, ap netip.AddrPort) {
	for _, cur := range e.sampleAddrs {
		if cur == ap {
			return
		}
	}
	if len(e.sampleAddrs) >= missSampleDstMax {
		return
	}
	e.sampleAddrs = append(e.sampleAddrs, ap)
}

// missPruneExpiredLocked 清理 lastSeen 超 TTL 的条目（调用方持写锁）。
func missPruneExpiredLocked(nowMs int64) {
	ttlMs := missTTL.Milliseconds()
	for k, e := range missTable {
		if nowMs-e.LastSeen > ttlMs {
			delete(missTable, k)
		}
	}
}

// missEvictOneLocked 淘汰一个条目（调用方持写锁）：
// 优先级最低者优先，同优先级淘汰 lastSeen 最旧者。
// 选择"单条淘汰"而非"整表重置"：游戏目录条目 priority 高，不会被普通
// 系统进程的噪音流量冲掉。
func missEvictOneLocked() {
	var victimKey string
	var victim *MissEntry
	for k, e := range missTable {
		if victim == nil {
			victimKey, victim = k, e
			continue
		}
		if e.Priority < victim.Priority ||
			(e.Priority == victim.Priority && e.LastSeen < victim.LastSeen) {
			victimKey, victim = k, e
		}
	}
	if victim != nil {
		delete(missTable, victimKey)
	}
}

// missSampleDirFiles 采样进程目录内的文件名（DLL / 子目录名，最多 10 个）。
// 只在首次建行时调用一次，失败静默返回 nil。
func missSampleDirFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, missDirFilesMax)
	for _, ent := range entries {
		if len(out) >= missDirFilesMax {
			break
		}
		name := ent.Name()
		if ent.IsDir() {
			name += "\\"
		}
		out = append(out, name)
	}
	return out
}

// missMaskPath 路径脱敏：C:\Users\<用户名>\ → C:\Users\<U>\（发布版防泄露用户名）。
func missMaskPath(p string) string {
	if p == "" {
		return ""
	}
	const marker = `\users\`
	idx := missIndexFold(p, marker)
	if idx < 0 {
		return p
	}
	start := idx + len(marker)
	if start >= len(p) {
		return p
	}
	end := strings.IndexByte(p[start:], '\\')
	if end < 0 {
		return p[:start] + "<U>"
	}
	return p[:start] + "<U>" + p[start+end:]
}

// missIndexFold ASCII 大小写无关子串查找（避免 ToLower 改变字节长度导致下标错位）。
func missIndexFold(s, sub string) int {
	n := len(sub)
	if n == 0 || len(s) < n {
		return -1
	}
	for i := 0; i+n <= len(s); i++ {
		ok := true
		for j := 0; j < n; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// missTableReset 清空聚合表（单测隔离用，不对外暴露）。
func missTableReset() {
	missMu.Lock()
	missTable = make(map[string]*MissEntry, MissTableCapacity)
	missMu.Unlock()
}

// missTableSize 当前条目数（单测断言用）。
func missTableSize() int {
	missMu.RLock()
	n := len(missTable)
	missMu.RUnlock()
	return n
}
