package gamelane

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Observer 会话级观测器：原子统计上行/下行包数、下行字节与到达时间戳，
// 并按 上行发送时刻 → 下行到达时刻 配对采样 RTT。
// 未观测的会话保持全零，对默认路径零影响。
type Observer struct {
	sent   atomic.Uint64
	recv   atomic.Uint64
	bytes  atomic.Uint64
	isQUIC bool

	mu   sync.Mutex
	tsMs []int64 // 下行包到达时间戳（ms），上限 256 个

	sendTs    []time.Time // 上行发送时刻（LIFO，与下行包配对计算 RTT）
	rttMs     []float64   // 下行包 RTT 采样（ms），上限 256 个
	lastRTTMs float64     // 最近一次配对成功的下行包 RTT（ms）
}

func newObserver(isQUIC bool) *Observer {
	return &Observer{isQUIC: isQUIC}
}

// OnSent 记录一个上行包（ts 为发送时刻，供 RTT 配对）。
func (o *Observer) OnSent(ts time.Time) {
	o.sent.Add(1)
	o.mu.Lock()
	o.sendTs = append(o.sendTs, ts)
	if len(o.sendTs) > 256 {
		o.sendTs = o.sendTs[len(o.sendTs)-256:]
	}
	o.mu.Unlock()
}

// OnRecv 记录一个下行包（n 为字节数，ts 为到达时刻）。
// 有未配对的上行发送时刻时按 LIFO 配对计算 RTT（lastRTTMs / rttMs 采样）：
// 游戏场景下行包多为对最近一次上行请求的响应/推进，FIFO 会把突发发送
// 的排队延迟误测为 RTT（虚高到窗口量级），LIFO 取最近上行更贴近真实往返。
func (o *Observer) OnRecv(n int, ts time.Time) {
	o.recv.Add(1)
	o.bytes.Add(uint64(n))
	o.mu.Lock()
	o.tsMs = append(o.tsMs, ts.UnixMilli())
	if len(o.tsMs) > 256 {
		o.tsMs = o.tsMs[len(o.tsMs)-256:]
	}
	if len(o.sendTs) > 0 {
		sentAt := o.sendTs[len(o.sendTs)-1]
		o.sendTs = o.sendTs[:len(o.sendTs)-1]
		rtt := ts.Sub(sentAt)
		if rtt > 0 {
			o.lastRTTMs = float64(rtt) / float64(time.Millisecond)
			o.rttMs = append(o.rttMs, o.lastRTTMs)
			if len(o.rttMs) > 256 {
				o.rttMs = o.rttMs[len(o.rttMs)-256:]
			}
		}
	}
	o.mu.Unlock()
}

// LastRTTMs 返回最近一次配对成功的下行包 RTT（ms）；尚未配对返回 0。
func (o *Observer) LastRTTMs() float64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastRTTMs
}

// Counters 返回 (上行包数, 下行包数)。
func (o *Observer) Counters() (sent, recv uint64) {
	return o.sent.Load(), o.recv.Load()
}

// Snapshot 返回当前窗口可用的观测快照：上行/下行包数、下行字节、jitter。
func (o *Observer) Snapshot() (sent, recv, bytes uint64, jitterMs float64) {
	o.mu.Lock()
	ts := append([]int64(nil), o.tsMs...)
	o.mu.Unlock()
	return o.sent.Load(), o.recv.Load(), o.bytes.Load(), jitterMsFrom(ts)
}

// IsQUIC 返回该会话是否 sniff 判定为 QUIC。
func (o *Observer) IsQUIC() bool {
	return o.isQUIC
}

// SwitchFunc 由上层注入，负责"新建 PacketConn → 原子替换读路径 → 关闭旧连接"。
// toPrimary=true 表示回切快速通道主出口，false 表示切到备用出口。
type SwitchFunc func(toPrimary bool) error

// ProbeDialer 由上层注入：新建一条走 primary 出口的探测连接（仅用于探测，
// 不切换会话流量）。返回的连接由探测循环独占读。
type ProbeDialer func() (C.PacketConn, error)

// CandidateDialer 由上层注入：按候选出口名新建一条走该出口的探测连接，
// 用于候选池切换前逐个探测评分。返回的连接由候选探测循环独占读。
type CandidateDialer func(name string) (C.PacketConn, error)

// 候选体检专用确定性探测端点：公共 DNS 8.8.8.8:53，发送标准 A 查询必然
// 收到 DNS 响应（除非链路完全不可达）。候选体检镜像游戏流量之外，主动向
// 该端点补发探测包，保证稀疏流量/无上行时每个候选都有回包样本。
var (
	probeEndpointAddr = &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	// probePayload 为标准 DNS A 查询（example.com，RD=1）：header + question。
	probePayload = []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
)

// candProbeSampleFloor 候选体检的有效样本下限（F6）：回包数低于该值的候选
// 视为“未验证”（score=0 不参选、不回写健康结论），防止小样本把偶发回包
// 当健康证据——实测同批节点两轮探测间 0↔100 完全翻转（诊断 S6/E4）。
const candProbeSampleFloor = 4

// probeState 单次 primary 恢复探测的状态：镜像会话上行包到探测连接，
// 统计丢包与 RTT，探测结束后回填 Predictor.OnPrimaryProbe。
type probeState struct {
	conn      C.PacketConn
	sent      int
	recv      int
	rttSum    time.Duration
	sendTimes []time.Time // 镜像发送时刻，按序对应回包用于 RTT 采样
	lastSend  time.Time
	deadline  time.Time
	maxPkts   int
}

// candidateScore 单个候选出口的探测评分结果。
type candidateScore struct {
	name  string
	score float64
}

// candidateProbeState 候选池探测状态：并发 2 路建连接、镜像会话上行包、
// 统计丢包/RTT 评分，全部完成后选最优候选并触发切换。
type candidateProbeState struct {
	names       []string
	conns       []C.PacketConn // 每个候选的探测连接（并发 2 路）
	sent        []int
	recv        []int
	rttSum      []time.Duration
	sendTimes   [][]time.Time // 镜像发送时刻，按序对应回包用于 RTT 采样
	lastSend    []time.Time
	deadline    time.Time // 整体探测超时（从启动起 5s）
	maxPkts     int
	scores      []candidateScore // 与 names 等长，index 对齐
	done        []bool
	probeTarget net.Addr // 确定性回包端点（公共 DNS 探测包目标）
	extended    []bool   // 该候选是否已延长过探测窗口（无样本兜底只延一次）
}

// SessionConn 是命中快速通道的 UDP 会话观测包装层：
// 实现完整 C.PacketConn 接口，读写统一委托当前连接并在路径上计数，
// 每包驱动预测器；预测器给出切换动作时调用注入的 SwitchFunc 完成原子切换。
type SessionConn struct {
	obsDst       string // 铁令 B（v2.4）：[obs] 行目标现形（handleUDPConn 创建后写入 dstIP:port）
	key          string
	cur          atomic.Pointer[C.PacketConn]
	epoch        atomic.Uint64 // 每次 Switch 递增；读循环据此区分"切换导致的旧连接读错误"与真实错误
	obs          *Observer
	p            *Predictor
	sw           SwitchFunc
	swBusy       atomic.Bool // 切换动作串行化，防止异步并发重复切换
	switchSilent atomic.Bool // 本次切换为静默换优（Auto-Pick），不计 switch_count
	closed       atomic.Bool

	probeDialer ProbeDialer
	probeMu     sync.Mutex
	probe       *probeState

	// 候选池（M3 二期）：fallbacks 为备用出口候选列表，切换前对每个候选
	// 逐个体检评分，选最优出口切换；单候选时保持旧版直接切换行为。
	fallbacks        []string
	candidateDialer  CandidateDialer
	candMu           sync.Mutex
	candProbe        *candidateProbeState
	selectedFallback string
	candSem          chan struct{} // 候选探测并发槽位（2 路）

	// v2 Auto-Pick Primary（先进游戏，后测后换）：autoPick 标记该会话处于
	// 自动主节点模式（Target.Proxy 为空/"auto"）；首次上行后自动对候选池
	// 体检，探测完成选最优出口与当前临时主节点比较，更优才切换；
	// currentPrimary 为当前实际主节点名，primaryObs 为切换后回报回调。
	autoPick       atomic.Bool
	autoPickDone   atomic.Bool
	primaryMu      sync.Mutex
	currentPrimary string
	primaryObs     func(name string)

	// H 修复：会话保护期。SessionConn 建立后前 30 秒为保护期，
	// 期间 degraded 切换与 auto-pick 切换全部禁止（只记录不执行），
	// 让游戏测速完整跑完；切换后新会话重新计算保护期。
	protectedSince atomic.Int64 // Unix 毫秒，0 表示无保护期

	// F1④：会话实测 RTT 周期回写（5s 节流）。tunnel 层注入 Manager 的
	// RecordSessionRTT，把“客户端→节点→游戏服务器”真实链路延迟写回
	// rttTable，作为选路/切换决策的真实锚点。
	rttReporter func(proxy string, rttMs float64)
	rttReportAt atomic.Int64

	// F6：候选探测结果回写（与 Manager 探测同一张 rttTable、同一套
	// 平滑/判死策略），消除双探测口径漂移。
	probeSink func(name string, rttMs float64, samples int, ok bool)

	// 断流检测（训练场卡顿定位 2026-10-19）：上行持续发送但下行超时
	// 无回包时记录 recv_stall / recv_resume 诊断事件——"客户端→节点"通、
	// "节点→客户端"断是训练场卡住后连接服务器超时的直接证据链。
	lastSentAt  atomic.Int64 // 最近一次上行发送时刻（UnixMilli，0=从未）
	lastRecvAt  atomic.Int64 // 最近一次下行回包时刻（UnixMilli，0=从未）
	lastStallAt atomic.Int64 // 最近一次断流事件记录时刻（0=当前未断流）

	// v2.8 第一刀：拦截类日志/诊断节流（5s 一条）。保护期与活跃会话门卫
	// 拦截期间曾出现 2046 条 m3_blocked 刷屏，把诊断环形缓冲（capacity
	// 2048）全部淹没，真实切换事件反而不可回溯。
	lastBlockLogAt atomic.Int64
}

// NewSessionConn 构造观测包装层。switchFn 可为 nil（纯观测，不切换）。
func NewSessionConn(pc C.PacketConn, key string, isQUIC bool, cfg Config, switchFn SwitchFunc) *SessionConn {
	sc := &SessionConn{
		key:     key,
		obs:     newObserver(isQUIC),
		p:       NewPredictor(cfg),
		sw:      switchFn,
		candSem: make(chan struct{}, 4), // 候选探测并发 2-4 路（v6.1 放宽至 4）
	}
	sc.cur.Store(&pc)
	sc.protectedSince.Store(time.Now().UnixMilli() + protectedDurationMs)
	recordDiag("session_open", "key=%s isQUIC=%v", key, isQUIC)
	return sc
}

const protectedDurationMs = int64(30000) // 30 秒保护期

// isProtected 返回当前是否处于保护期内。保护期从会话建立起 30 秒，
// 期间 degraded 切换与 auto-pick 切换均禁止执行。
func (sc *SessionConn) isProtected() bool {
	expireMs := sc.protectedSince.Load()
	return expireMs > 0 && time.Now().UnixMilli() < expireMs
}

// sessionAliveBlocksSwitch 会话活跃门卫（v2.8 第一刀焊死）：过去 10s 内
// 收到过回包 = 连接存活（APEX 服务器固定 20Hz Tickrate 回包，recv/sent
// 比例低是健康的帧率比，不是丢包），严禁任何切换 / rebuild session。
// 唯一允许切换条件 = 连续 10s recvDelta==0（真死链，如 2026-10-19
// 17:23:14 sent=2001 recv=0 彻底断流）。返回 true 表示拦截切换。
func (sc *SessionConn) sessionAliveBlocksSwitch(actName string) bool {
	lastRecv := sc.lastRecvAt.Load()
	if lastRecv <= 0 {
		return false // 从未收到回包：允许切换（死链抢救路径）
	}
	now := time.Now().UnixMilli()
	if now-lastRecv < activeSessionGraceMs {
		sc.logBlockedThrottled("session_locked", "session-alive: %s blocked (key=%s, lastRecv=%dms ago)", actName, sc.key, now-lastRecv)
		return true
	}
	return false
}

// logBlockedThrottled 节流输出"被拦截"类日志与诊断事件（5s 一条）：
// 保护期/活跃会话拦截期间曾出现 2046 条 m3_blocked 刷屏，把诊断环形
// 缓冲（capacity=2048）全部淹没，真实切换事件反而不可回溯。
func (sc *SessionConn) logBlockedThrottled(kind, format string, args ...interface{}) {
	now := time.Now().UnixMilli()
	prev := sc.lastBlockLogAt.Load()
	if prev > 0 && now-prev < 5000 {
		return
	}
	sc.lastBlockLogAt.Store(now)
	log.Infoln("[GameRoute] "+format, args...)
	recordDiag(kind, format, args...)
}

// SetFallbacks 注入候选池（备用出口列表，单元素即旧版单 fallback 行为）。
func (sc *SessionConn) SetFallbacks(names []string) {
	sc.candMu.Lock()
	sc.fallbacks = append([]string(nil), names...)
	sc.candMu.Unlock()
}

// SetCandidateDialer 注入候选探测建连工厂：按候选出口名新建探测连接。
func (sc *SessionConn) SetCandidateDialer(d CandidateDialer) {
	sc.candMu.Lock()
	sc.candidateDialer = d
	sc.candMu.Unlock()
}

// SetAutoPick 标记 v2 Auto-Pick Primary 模式：首次上行后自动对候选池体检，
// 探测完成选最优出口，与当前临时主节点比较，更优才自动切换。
func (sc *SessionConn) SetAutoPick(enabled bool) {
	sc.autoPick.Store(enabled)
}

// SetCurrentPrimary 设置当前实际主节点名（autoPrimary 模式进场临时节点）。
func (sc *SessionConn) SetCurrentPrimary(name string) {
	sc.primaryMu.Lock()
	sc.currentPrimary = name
	sc.primaryMu.Unlock()
}

// CurrentPrimary 返回当前实际主节点名（临时节点或探测后选中的最优出口）。
func (sc *SessionConn) CurrentPrimary() string {
	sc.primaryMu.Lock()
	defer sc.primaryMu.Unlock()
	return sc.currentPrimary
}

// SetPrimaryObserver 注入主节点变更回调：候选探测切换后通知上层
// 回报 Manager（GET /gameroute/targets 输出即取该值）。
func (sc *SessionConn) SetPrimaryObserver(fn func(name string)) {
	sc.primaryMu.Lock()
	sc.primaryObs = fn
	sc.primaryMu.Unlock()
}

// SelectedFallback 返回候选池探测选中的最优出口名。
// 优先级：探测完成有选中结果 → 返回该结果；单候选（无候选池探测）→
// 返回首元素（旧版直接切换行为）；多候选探测未完成 → 不盲目返回
// fallbacks[0]，返回已确认健康的探测最优（recv>0 且 RTT 最低）；
// 尚无健康样本 → 返回空串，由调用方保持当前节点（避免切到未确认节点）。
func (sc *SessionConn) SelectedFallback() string {
	sc.candMu.Lock()
	defer sc.candMu.Unlock()
	if sc.selectedFallback != "" {
		return sc.selectedFallback
	}
	if len(sc.fallbacks) == 1 {
		return sc.fallbacks[0]
	}
	if sc.candProbe != nil {
		best := ""
		var bestRTT time.Duration
		for i, n := range sc.candProbe.names {
			if i < len(sc.candProbe.recv) && sc.candProbe.recv[i] > 0 &&
				i < len(sc.candProbe.rttSum) && sc.candProbe.rttSum[i] > 0 {
				avg := sc.candProbe.rttSum[i] / time.Duration(sc.candProbe.recv[i])
				if best == "" || avg < bestRTT {
					best = n
					bestRTT = avg
				}
			}
		}
		if best != "" {
			return best
		}
	}
	return ""
}

// Key 返回会话 NAT key。
func (sc *SessionConn) Key() string {
	return sc.key
}

// LastSettledLossRate 返回预测器最近一次评估窗口的丢包率
// （切换动作后即触发丢包率），供上层上报 M3 全局状态。
func (sc *SessionConn) LastSettledLossRate() float64 {
	if sc.p == nil {
		return 0
	}
	return sc.p.LastSettledLossRate()
}

// Current 返回当前出站连接。
func (sc *SessionConn) Current() C.PacketConn {
	return *sc.cur.Load()
}

// Switch 原子切换出站连接：替换读路径引用后关闭旧连接。
// epoch 递增使正在旧连接上阻塞的读循环识别"切换导致的读错误"，
// 从而重读新连接而不是把整个 NAT 会话退出（避免乒乓与连接被 defer 误关）。
func (sc *SessionConn) Switch(pc C.PacketConn) {
	old := sc.cur.Swap(&pc)
	sc.epoch.Add(1)
	if old != nil {
		_ = (*old).Close()
	}
}

// Observer 返回观测器。
func (sc *SessionConn) Observer() *Observer {
	return sc.obs
}

// afterPacket 每包观测后驱动预测器并执行建议动作。
// SetObsDst 记录会话远端（铁令 B：[obs] 行补 dstIP:dport，50870 类会话
// 目标直接可见，不再盲猜/抓包）。创建后立即调用一次。
func (sc *SessionConn) SetObsDst(dst string) {
	sc.obsDst = dst
}

func (sc *SessionConn) afterPacket(sent, recv bool, n int) {
	ts := time.Now()
	if recv {
		sc.obs.OnRecv(n, ts)
	} else if sent {
		sc.obs.OnSent(ts)
	}
	if sc.obs.sent.Load()%1000 == 1 || sc.obs.recv.Load()%1000 == 1 {
		log.Infoln("[GameRoute][obs] key=%s sent=%d recv=%d mode=%d epoch=%d",
			sc.key, sc.obs.sent.Load(), sc.obs.recv.Load(), sc.p.Mode(), sc.epoch.Load())
	}
	// 断流检测（训练场卡顿定位 2026-10-19）：上行持续发送但下行超时
	// 无回包 → 记录 recv_stall；恢复回包 → recv_resume。阈值 5s，
	// 事件节流 5s，环形缓冲可回溯断流前后 60s 的完整因果链。
	now := ts.UnixMilli()
	if recv {
		sc.lastRecvAt.Store(now)
		if lastStall := sc.lastStallAt.Swap(0); lastStall > 0 {
			recordDiag("recv_resume", "key=%s sent=%d recv=%d stallMs=%d primary=%s",
				sc.key, sc.obs.sent.Load(), sc.obs.recv.Load(), now-lastStall, sc.CurrentPrimary())
		}
	} else if sent {
		sc.lastSentAt.Store(now)
		if sc.obs.sent.Load() > 30 {
			if lastRecv := sc.lastRecvAt.Load(); lastRecv > 0 && now-lastRecv > 5000 {
				if lastStall := sc.lastStallAt.Load(); lastStall == 0 || now-lastStall > 5000 {
					sc.lastStallAt.Store(now)
					recordDiag("recv_stall", "key=%s sent=%d recv=%d idleMs=%d primary=%s epoch=%d",
						sc.key, sc.obs.sent.Load(), sc.obs.recv.Load(), now-lastRecv, sc.CurrentPrimary(), sc.epoch.Load())
				}
			}
		}
	}
	// F1④：会话实测 RTT 周期回写（5s 节流，下行有配对采样才报）。
	if sc.rttReporter != nil && recv {
		if now := ts.UnixMilli(); now-sc.rttReportAt.Load() >= 5000 {
			sc.rttReportAt.Store(now)
			if rtt := sc.obs.LastRTTMs(); rtt > 0 {
				if name := sc.CurrentPrimary(); name != "" {
					sc.rttReporter(name, rtt)
				}
			}
		}
	}
	if sc.p == nil || sc.sw == nil {
		return
	}
	if sent {
		sc.maybeBeginAutoPickProbe()
	}
	// RTT 维度接线：下行包经 Observer 配对后喂入预测器，否则 rttP50 恒空、
	// RTT 权重（30%）永久中性。
	act := sc.p.OnPacketEx(sent, recv, n, sc.obs.LastRTTMs(), ts, sc.obs.isQUIC)
	switch act {
	case ActionSwitchToFallback:
		recordDiag("m3_action", "key=%s act=to-fallback primary=%s epoch=%d", sc.key, sc.CurrentPrimary(), sc.epoch.Load())
		sc.doSwitchToFallback()
	case ActionSwitchToPrimary:
		recordDiag("m3_action", "key=%s act=to-primary primary=%s epoch=%d", sc.key, sc.CurrentPrimary(), sc.epoch.Load())
		sc.doSwitchAsync(true)
	}
	// fallback 好窗口达标时尝试发起 primary 恢复探测（探测不切换会话流量）
	if sc.p.TryBeginProbe(ts) {
		sc.beginProbe()
	}
}

// SetProbeDialer 注入 primary 探测连接工厂（由上层传入走主出口的建连函数）。
func (sc *SessionConn) SetProbeDialer(d ProbeDialer) {
	sc.probeDialer = d
}

// SetRTTReporter 注入会话实测 RTT 回写函数（F1④；须在会话产生流量前设置，
// 之后只读访问无锁）。
func (sc *SessionConn) SetRTTReporter(fn func(proxy string, rttMs float64)) {
	sc.rttReporter = fn
}

// SetProbeResultSink 注入候选探测结果回写函数（F6；须在会话产生流量前设置）。
func (sc *SessionConn) SetProbeResultSink(fn func(name string, rttMs float64, samples int, ok bool)) {
	sc.probeSink = fn
}

// beginProbe 发起一次 primary 恢复探测：通过 ProbeDialer 建一条主出口连接，
// 镜像会话上行包统计丢包/RTT。建连失败或无注入时按"未恢复"结算释放探测槽。
func (sc *SessionConn) beginProbe() {
	if sc.closed.Load() || sc.probeDialer == nil {
		sc.p.OnPrimaryProbe(1, 0, time.Now())
		return
	}
	sc.probeMu.Lock()
	if sc.probe != nil {
		sc.probeMu.Unlock()
		return
	}
	conn, err := sc.probeDialer()
	if err != nil {
		sc.probeMu.Unlock()
		sc.p.OnPrimaryProbe(1, 0, time.Now())
		return
	}
	sc.probe = &probeState{conn: conn, maxPkts: 32, deadline: time.Now().Add(5 * time.Second)}
	sc.probeMu.Unlock()
	go sc.probeLoop()
}

// probeLoop 探测读循环：读探测连接回包直到达到样本上限或超时，
// 结束后按丢包/RTT 结算回填 Predictor，关闭探测连接并释放探测槽。
func (sc *SessionConn) probeLoop() {
	sc.probeMu.Lock()
	pr := sc.probe
	sc.probeMu.Unlock()
	if pr == nil {
		return
	}
	buf := make([]byte, 65536)
	for {
		now := time.Now()
		if now.After(pr.deadline) {
			break
		}
		if pr.sent >= pr.maxPkts && (pr.recv >= pr.maxPkts || now.Sub(pr.lastSend) > time.Second) {
			break
		}
		_ = pr.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, _, err := pr.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		sc.probeMu.Lock()
		idx := pr.recv
		if idx < len(pr.sendTimes) {
			pr.rttSum += time.Since(pr.sendTimes[idx])
		}
		pr.recv++
		sc.probeMu.Unlock()
		if n > 0 {
			_ = n
		}
	}
	sc.probeMu.Lock()
	loss := 1.0
	if pr.sent > 0 {
		loss = float64(pr.sent-pr.recv) / float64(pr.sent)
		if loss < 0 {
			loss = 0
		}
	}
	rttMs := 0.0
	if pr.recv > 0 {
		rttMs = float64(pr.rttSum/time.Millisecond) / float64(pr.recv)
	}
	sc.probe = nil
	sc.probeMu.Unlock()
	sc.p.OnPrimaryProbeEx(loss, rttMs, 0, uint64(pr.recv), time.Now())
	_ = pr.conn.Close()
}

// mirrorProbe 探测期间镜像会话上行包到探测连接（有界：maxPkts 或 deadline）。
// 仅镜像，绝不切换会话流量——探测期流量仍全部走当前出口。候选池体检时
// 上行包同时镜像到候选探测连接，使候选连接产生真实回包用于评分。
func (sc *SessionConn) mirrorProbe(p []byte, addr net.Addr) {
	now := time.Now()
	// 候选池体检镜像：对每个仍在探测中（连接非空且未满样本）的候选
	// 同步镜像，使候选连接产生真实回包用于评分。稀疏流量时按整体
	// deadline（5s）兜底：凑不齐 16 包则按已收样本结算。
	// （候选体检独立于 primary 恢复探测，先于 primary 镜像执行，
	//  避免 primary 探测为空时提前 return 跳过候选镜像）
	sc.candMu.Lock()
	cp := sc.candProbe
	if cp == nil || now.After(cp.deadline) {
		sc.candMu.Unlock()
	} else {
		for ci := range cp.names {
			if cp.conns[ci] == nil || cp.done[ci] || cp.sent[ci] >= cp.maxPkts {
				continue
			}
			cp.sent[ci]++
			cp.lastSend[ci] = now
			cp.sendTimes[ci] = append(cp.sendTimes[ci], now)
			candConn := cp.conns[ci]
			if _, err := candConn.WriteTo(p, addr); err != nil {
				if cp.sent[ci] > 0 && len(cp.sendTimes[ci]) > 0 {
					cp.sent[ci]--
					cp.sendTimes[ci] = cp.sendTimes[ci][:len(cp.sendTimes[ci])-1]
				}
			}
		}
		sc.candMu.Unlock()
	}
	sc.probeMu.Lock()
	pr := sc.probe
	if pr == nil || now.After(pr.deadline) || pr.sent >= pr.maxPkts {
		sc.probeMu.Unlock()
		return
	}
	// 先计数后发送：确保探测连接回包到达时 sendTimes 已含本包，
	// 否则 probeLoop 按 recv 顺序配对 RTT 时计数超前，rttSum 虚高。
	pr.sent++
	pr.lastSend = now
	pr.sendTimes = append(pr.sendTimes, now)
	sc.probeMu.Unlock()
	if _, err := pr.conn.WriteTo(p, addr); err != nil {
		// 发送失败回滚计数，避免 sent 虚高导致丢包率误判
		sc.probeMu.Lock()
		if pr.sent > 0 && len(pr.sendTimes) > 0 {
			pr.sent--
			pr.sendTimes = pr.sendTimes[:len(pr.sendTimes)-1]
		}
		sc.probeMu.Unlock()
	}
}

// maybeBeginAutoPickProbe v2 Auto-Pick Primary：autoPrimary 模式首次上行
// （游戏 UDP 会话建立/有上行流量）后立即在后台对候选池发起体检，不阻塞游戏
// 流量；空池/已探测/会话关闭时安全跳过。autoPickDone 保证只自动触发一次，
// 后续候选刷新沿用既有懒测路径（劣化触发体检，60s 冷却内直接沿用选中结果）。
func (sc *SessionConn) maybeBeginAutoPickProbe() {
	if !sc.autoPick.Load() || sc.autoPickDone.Load() || sc.closed.Load() {
		return
	}
	// H 修复：保护期内禁止 auto-pick 触发切换（探测仍照跑，仅延缓切换）。
	if sc.isProtected() {
		sc.logBlockedThrottled("m3_blocked", "protected: auto-pick blocked (key=%s, remaining=%dms)", sc.key, sc.protectedSince.Load()-time.Now().UnixMilli())
		return
	}
	sc.candMu.Lock()
	hasPool := len(sc.fallbacks) > 0 && sc.candidateDialer != nil
	probing := sc.candProbe != nil
	sc.candMu.Unlock()
	if !hasPool || probing {
		return
	}
	sc.autoPickDone.Store(true)
	sc.beginCandidateProbe()
}

// BeginAutoPickProbe 会话建立后立即对候选池发起体检（auto-register /
// memory-hit / flow-score 目标注册成功、会话建立即触发，不再等首次上行）；
// 空池/已探测/会话关闭时安全跳过，60s 冷却仅约束重复探测。
func (sc *SessionConn) BeginAutoPickProbe() {
	sc.maybeBeginAutoPickProbe()
}

// doSwitchToFallback 劣化切换入口：单候选直接异步切换（兼容旧行为，乒乓 0）；
// 多候选时先对候选池逐个体检评分，选最优出口后再切换；
// 处于懒测 interval（60s）内时跳过体检、直接沿用既有选中结果切换。
func (sc *SessionConn) doSwitchToFallback() {
	// v2.8 第一刀焊死：会话 10s 内有回包 = 连接存活，严禁任何 degraded
	// 切换 / rebuild session（recv/sent 比例低是 APEX 20Hz 回包的正常
	// 帧率比，不是丢包）。先于候选探测拦截，省掉整轮体检。
	if sc.sessionAliveBlocksSwitch("degraded") {
		return
	}
	// H 修复：保护期内不执行 degraded 切换，只记录。
	// 让游戏测速完整跑完后再评估，防止 30 秒内反复切节点。
	if sc.isProtected() {
		sc.logBlockedThrottled("degrade_blocked", "protected: degraded switch blocked (key=%s, remaining=%dms)", sc.key, sc.protectedSince.Load()-time.Now().UnixMilli())
		return
	}
	sc.candMu.Lock()
	multi := len(sc.fallbacks) > 1 && sc.candidateDialer != nil
	probing := sc.candProbe != nil
	if !multi || probing {
		sc.candMu.Unlock()
		sc.doSwitchAsync(false)
		return
	}
	// 懒测下限：距上次候选探测完成不足 CooldownCandidateInterval 则跳过体检
	lastFinish := sc.p.candLastFinish.Load()
	inCooldown := lastFinish > 0 && time.Since(time.UnixMilli(lastFinish)) < sc.p.cfg.CooldownCandidateInterval
	sc.candMu.Unlock()
	if inCooldown {
		sc.doSwitchAsync(false)
		return
	}
	sc.beginCandidateProbe()
}

// beginCandidateProbe 发起候选池体检：并发 2 路为候选池建探测连接并启动
// 探测循环；每个候选镜像会话上行包统计丢包/RTT，全部完成后选最优出口
// 写入 selectedFallback 并触发切换。懒测 interval 下限 60s（距上次探测
// 完成不足 60s 则跳过）；整体探测超时 5s（稀疏流量兜底：凑不齐 16 包
// 时按已收样本结算，超时仍无样本则该候选记 0 分）。
func (sc *SessionConn) beginCandidateProbe() {
	sc.candMu.Lock()
	if sc.candProbe != nil || sc.closed.Load() {
		sc.candMu.Unlock()
		return
	}
	// 懒测下限：距上次候选探测完成不足 CooldownCandidateInterval 则跳过
	lastFinish := sc.p.candLastFinish.Load()
	if lastFinish > 0 {
		elapsed := time.Since(time.UnixMilli(lastFinish))
		if elapsed < sc.p.cfg.CooldownCandidateInterval {
			sc.candMu.Unlock()
			return
		}
	}
	names := append([]string(nil), sc.fallbacks...)
	// 整体探测超时动态放宽（v6.1）：max(基础超时, N×0.5s)，N=池内节点数，
	// 港台全量池（10-12 节点）保证每候选都有充分样本，不再按固定 5s 一刀切。
	probeTimeout := sc.p.cfg.CandidateProbeTimeout
	if dyn := time.Duration(len(names)) * 500 * time.Millisecond; dyn > probeTimeout {
		probeTimeout = dyn
	}
	cp := &candidateProbeState{
		names:       names,
		conns:       make([]C.PacketConn, len(names)),
		sent:        make([]int, len(names)),
		recv:        make([]int, len(names)),
		rttSum:      make([]time.Duration, len(names)),
		sendTimes:   make([][]time.Time, len(names)),
		lastSend:    make([]time.Time, len(names)),
		deadline:    time.Now().Add(probeTimeout), // 整体探测超时（默认 5s，按池大小动态）
		maxPkts:     16,
		scores:      make([]candidateScore, len(names)),
		done:        make([]bool, len(names)),
		probeTarget: probeEndpointAddr, // 确定性回包端点：公共 DNS 8.8.8.8:53
		extended:    make([]bool, len(names)),
	}
	sc.candProbe = cp
	sc.candMu.Unlock()
	recordDiag("cand_probe_batch", "key=%s pool=%d timeout=%dms autoPick=%v", sc.key, len(names), probeTimeout/time.Millisecond, sc.autoPick.Load())
	// 并发 4 路：最多同时探测 4 个候选，其余排队等待空闲槽位
	for i := range names {
		go func(idx int) {
			sc.candSem <- struct{}{} // 获取槽位（无空位则等待）
			sc.probeCandidate(idx)
			<-sc.candSem // 释放槽位
		}(i)
	}
}

// probeCandidate 为第 i 个候选建探测连接；建连失败按 0 分记录并标记完成。
// 并发安全：最多 2 个候选同时在探测（candidateLoop 内用槽位信号量限制）。
func (sc *SessionConn) probeCandidate(i int) {
	sc.candMu.Lock()
	cp := sc.candProbe
	if cp == nil || i >= len(cp.names) || cp.done[i] {
		sc.candMu.Unlock()
		return
	}
	name := cp.names[i]
	dialer := sc.candidateDialer
	sc.candMu.Unlock()
	conn, err := dialer(name)
	sc.candMu.Lock()
	if err != nil {
		// 建连失败：该候选 0 分，直接完成（score=0 不参与选路）
		log.Infoln("[GameRoute] probe candidate %s dial failed: %v (score=0)", name, err)
		recordDiag("cand_probe_node", "key=%s name=%s result=dial-fail err=%v", sc.key, name, err)
		cp.scores[i] = candidateScore{name: name, score: 0}
		cp.done[i] = true
		sc.candMu.Unlock()
		sc.finishCandidateProbe()
		return
	}
	cp.conns[i] = conn
	cp.sent[i] = 0
	cp.recv[i] = 0
	cp.rttSum[i] = 0
	cp.sendTimes[i] = nil
	cp.lastSend[i] = time.Time{}
	sc.candMu.Unlock()
	sc.runCandidateLoop(i)
}

// runCandidateLoop 候选探测读循环：读第 i 个候选探测连接回包直到达到样本
// 上限或整体超时，结算该候选评分（scoreMetrics：丢包 50% + RTT 30% +
// 抖动 20%；候选体检仅有丢包/RTT 样本，抖动按满分中性处理），关闭连接
// 后标记完成并触发 finishCandidateProbe。
func (sc *SessionConn) runCandidateLoop(i int) {
	sc.candMu.Lock()
	cp := sc.candProbe
	if cp == nil || i >= len(cp.names) || cp.conns[i] == nil {
		sc.candMu.Unlock()
		return
	}
	conn := cp.conns[i]
	sc.candMu.Unlock()

	buf := make([]byte, 65536)
	for {
		sc.candMu.Lock()
		now := time.Now()
		if now.After(cp.deadline) {
			// E 修复：探测窗口结束仍无回包样本（recv==0 且已发包）→ 延长
			// 窗口一次（+2s）继续补发，避免"发包数不足导致无样本"直接记 0 分。
			if cp.recv[i] == 0 && cp.sent[i] > 0 && cp.probeTarget != nil && !cp.extended[i] {
				cp.extended[i] = true
				cp.deadline = now.Add(2 * time.Second)
			} else {
				sc.candMu.Unlock()
				break
			}
		}
		if cp.sent[i] >= cp.maxPkts && (cp.recv[i] >= cp.maxPkts || now.Sub(cp.lastSend[i]) > time.Second) {
			sc.candMu.Unlock()
			break
		}
		// E 修复：主动补发确定性探测包（公共 DNS A 查询 → 8.8.8.8:53）。
		// 镜像游戏流量不足（稀疏/无上行）时仍保证候选有回包样本；
		// 间隔 200ms 控制节奏，避免与镜像流量混发过频导致 RTT 配对紊乱。
		if cp.probeTarget != nil && cp.sent[i] < cp.maxPkts && now.Sub(cp.lastSend[i]) >= 200*time.Millisecond {
			cp.sent[i]++
			cp.lastSend[i] = now
			cp.sendTimes[i] = append(cp.sendTimes[i], now)
			if _, err := conn.WriteTo(probePayload, cp.probeTarget); err != nil {
				cp.sent[i]--
				cp.sendTimes[i] = cp.sendTimes[i][:len(cp.sendTimes[i])-1]
			}
		}
		sc.candMu.Unlock()
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		sc.candMu.Lock()
		idx := cp.recv[i]
		if idx < len(cp.sendTimes[i]) {
			cp.rttSum[i] += time.Since(cp.sendTimes[i][idx])
		}
		cp.recv[i]++
		sc.candMu.Unlock()
	}

	sc.candMu.Lock()
	loss := 1.0
	if cp.sent[i] > 0 {
		loss = float64(cp.sent[i]-cp.recv[i]) / float64(cp.sent[i])
		if loss < 0 {
			loss = 0
		}
	}
	rttMs := 0.0
	if cp.recv[i] > 0 {
		rttMs = float64(cp.rttSum[i]/time.Millisecond) / float64(cp.recv[i])
	}
	// 候选体检：抖动维度按满分中性处理；recv==0 时 rttScore 判 0 分（无样本不按 0ms 满分）。
	// F6：有效样本下限——回包 <candProbeSampleFloor 的候选视为“未验证”
	//（score=0 不参选），防止小样本把偶发回包当健康证据。
	recvN := uint64(cp.recv[i])
	score := 0.0
	if recvN >= candProbeSampleFloor {
		score = scoreMetrics(loss, rttMs, 0, recvN, sc.p.cfg)
	}
	cp.scores[i] = candidateScore{name: cp.names[i], score: score}
	conn = cp.conns[i]
	cp.conns[i] = nil
	cp.done[i] = true
	sc.candMu.Unlock()
	recordDiag("cand_probe_node", "key=%s name=%s loss=%.2f rttMs=%.1f recv=%d score=%.1f", sc.key, cp.names[i], loss, rttMs, recvN, score)
	_ = conn.Close()
	sc.finishCandidateProbe()
}

// finishCandidateProbe 全部候选探测完成后选最优出口并切换。
// 兜底：所有候选探测均 0 分（建连失败/稀疏流量超时无样本）时，直接切
// 候选池首元素，避免选到"最后一个零分候选"导致出口更差。
func (sc *SessionConn) finishCandidateProbe() {
	sc.candMu.Lock()
	cp := sc.candProbe
	if cp == nil {
		sc.candMu.Unlock()
		return
	}
	for _, d := range cp.done {
		if !d {
			sc.candMu.Unlock()
			return
		}
	}
	// 全部探测完成：打印每候选探测分（验收日志），再选最优出口
	for _, s := range cp.scores {
		log.Infoln("[GameRoute] probe score %s = %.1f", s.name, s.score)
	}
	best := ""
	bestScore := -1.0
	for _, s := range cp.scores {
		if s.score > bestScore {
			bestScore = s.score
			best = s.name
		}
	}
	if bestScore <= 0 && len(cp.names) > 0 {
		// F 修复：全部候选均无回包（建连失败/全丢包/窗口无样本）时允许
		// 兜底选择——按候选池顺序取首个（FIRST），保证故障出口能尽快
		// 切到探测口径下最优的出口，而不是停留在已判死的当前节点。
		log.Infoln("[GameRoute] probe all zero scores, fallback first candidate %s (candidates=%d)", cp.names[0], len(cp.names))
		best = cp.names[0]
		bestScore = 0
	}
	sc.selectedFallback = best
	sc.p.candLastFinish.Store(time.Now().UnixMilli())
	candidates := len(cp.names)
	sc.candProbe = nil
	sc.candMu.Unlock()
	if best == "" {
		log.Infoln("[GameRoute] probe finished: no candidate, keep current (candidates=%d)", candidates)
		recordDiag("cand_probe_settled", "key=%s candidates=%d result=keep-current", sc.key, candidates)
		return
	}
	if sc.autoPick.Load() {
		// v2 Auto-Pick Primary：探测完成选最优，与当前临时主节点比较，
		// 更优才切换；最优即当前 → 不动（避免无谓乒乓）。
		log.Infoln("[GameRoute] auto-pick primary = %s score=%.1f candidates=%d", best, bestScore, candidates)
		if best == sc.CurrentPrimary() {
			log.Infoln("[GameRoute] auto-pick %s already primary, no switch", best)
			recordDiag("cand_probe_settled", "key=%s best=%s score=%.1f candidates=%d result=already-primary", sc.key, best, bestScore, candidates)
			return
		}
		sc.primaryMu.Lock()
		sc.currentPrimary = best
		obs := sc.primaryObs
		sc.primaryMu.Unlock()
		if obs != nil {
			obs(best)
		}
		// Auto-Pick 换优非故障切换：走静默切换路径，不计 switch_count /
		// last_switch_at / loss_rate（current_proxy 已由 obs 回报刷新）。
		recordDiag("cand_probe_settled", "key=%s best=%s score=%.1f candidates=%d result=auto-pick", sc.key, best, bestScore, candidates)
		sc.doSwitchSilentAsync()
		return
	}
	log.Infoln("[GameRoute] fallback picked = %s score=%.1f candidates=%d", best, bestScore, candidates)
	recordDiag("cand_probe_settled", "key=%s best=%s score=%.1f candidates=%d result=fallback", sc.key, best, bestScore, candidates)
	sc.doSwitchAsync(false)
}

// SwitchSilent 返回最近一次发起的切换是否为静默切换（Auto-Pick 换优，
// 不计 switch_count / last_switch_at / loss_rate，仅刷新 current_proxy）。
func (sc *SessionConn) SwitchSilent() bool {
	return sc.switchSilent.Load()
}

// doSwitchAsync 异步执行故障切换动作：建连接等耗时操作不阻塞 UDP 读写路径，
// 避免同步切换期间读循环阻塞导致整段丢包；swBusy 保证动作串行。
func (sc *SessionConn) doSwitchAsync(toPrimary bool) {
	sc.launchSwitch(toPrimary, false)
}

// doSwitchSilentAsync 异步执行 Auto-Pick 换优切换（静默，不计数）。
func (sc *SessionConn) doSwitchSilentAsync() {
	sc.launchSwitch(false, true)
}

// launchSwitch 异步执行切换动作：建连接等耗时操作不阻塞 UDP 读写路径，
// 避免同步切换期间读循环阻塞导致整段丢包；swBusy 保证动作串行。
// silent=true 表示 Auto-Pick 换优（不计 switch_count），false 表示故障切换。
func (sc *SessionConn) launchSwitch(toPrimary bool, silent bool) {
	actName := "to-fallback"
	if toPrimary {
		actName = "to-primary"
	}
	if silent {
		actName = "auto-pick"
	}
	// v2.8 第一刀焊死：会话 10s 内有回包 = 连接存活，严禁任何切换 /
	// rebuild session（含 degraded / auto-pick / 回切 primary）。
	if sc.sessionAliveBlocksSwitch(actName) {
		return
	}
	// H 修复：保护期内禁止执行切换。
	if sc.isProtected() {
		sc.logBlockedThrottled("m3_blocked", "protected: launchSwitch blocked (key=%s, remaining=%dms)", sc.key, sc.protectedSince.Load()-time.Now().UnixMilli())
		return
	}
	if !sc.swBusy.CompareAndSwap(false, true) {
		return
	}
	sc.switchSilent.Store(silent)
	go func() {
		defer sc.swBusy.Store(false)
		err := sc.sw(toPrimary)
		// H 修复：切换成功后重新进入 30s 保护期（新连接同样需要稳定期，
		// 防止刚切换完又被劣化检测立即切走形成乒乓）。
		if err == nil {
			recordDiag("m3_apply", "key=%s act=%s silent=%v primary=%s epoch=%d", sc.key, actName, silent, sc.CurrentPrimary(), sc.epoch.Load())
			sc.protectedSince.Store(time.Now().UnixMilli() + protectedDurationMs)
		}
	}()
}

// WriteTo 上行路径：委托当前连接并计数；探测期同时镜像到探测连接（不切换流量）。
func (sc *SessionConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := sc.Current().WriteTo(p, addr)
	if err == nil {
		sc.afterPacket(true, false, 0)
		sc.mirrorProbe(p, addr)
	}
	return n, err
}

// ReadFrom 下行路径（net.PacketConn 兼容）：委托当前连接并计数。
// 切换导致旧连接被关闭时返回的读错误会被识别并重读新连接。
func (sc *SessionConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		cur := sc.cur.Load()
		epoch := sc.epoch.Load()
		n, addr, err := (*cur).ReadFrom(p)
		if err != nil {
			if sc.epoch.Load() != epoch {
				continue // switch closed the previous conn; read from the new one
			}
			return 0, nil, err
		}
		sc.afterPacket(false, true, n)
		return n, addr, err
	}
}

// WaitReadFrom 下行路径（tunnel 主读循环）：委托当前连接并计数。
// 切换导致旧连接被关闭时返回的读错误会被识别并重读新连接。
func (sc *SessionConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	for {
		cur := sc.cur.Load()
		epoch := sc.epoch.Load()
		data, put, addr, err := (*cur).WaitReadFrom()
		if err != nil {
			if sc.epoch.Load() != epoch {
				continue // switch closed the previous conn; read from the new one
			}
			return nil, nil, nil, err
		}
		sc.afterPacket(false, true, len(data))
		return data, put, addr, err
	}
}

// Close 关闭当前出站连接（旧连接已在 Switch 中关闭），并终止探测连接。
func (sc *SessionConn) Close() error {
	if sc.closed.CompareAndSwap(false, true) {
		sc.probeMu.Lock()
		if sc.probe != nil {
			_ = sc.probe.conn.Close()
		}
		sc.probeMu.Unlock()
		sc.candMu.Lock()
		if sc.candProbe != nil {
			for _, c := range sc.candProbe.conns {
				if c != nil {
					_ = c.Close()
				}
			}
			// 会话已关闭：挂起的候选探测不得再触发切换并新建连接（泄漏）。
			sc.candProbe = nil
		}
		sc.candMu.Unlock()
		return sc.Current().Close()
	}
	return nil
}

// LocalAddr 委托当前连接。
func (sc *SessionConn) LocalAddr() net.Addr {
	return sc.Current().LocalAddr()
}

// SetDeadline 委托当前连接。
func (sc *SessionConn) SetDeadline(t time.Time) error {
	return sc.Current().SetDeadline(t)
}

// SetReadDeadline 委托当前连接。
func (sc *SessionConn) SetReadDeadline(t time.Time) error {
	return sc.Current().SetReadDeadline(t)
}

// SetWriteDeadline 委托当前连接。
func (sc *SessionConn) SetWriteDeadline(t time.Time) error {
	return sc.Current().SetWriteDeadline(t)
}

// Chains 实现 C.Connection。
func (sc *SessionConn) Chains() C.Chain {
	return sc.Current().Chains()
}

// ProviderChains 实现 C.Connection。
func (sc *SessionConn) ProviderChains() C.Chain {
	return sc.Current().ProviderChains()
}

// AppendToChains 实现 C.Connection。
func (sc *SessionConn) AppendToChains(adapter C.ProxyAdapter) {
	sc.Current().AppendToChains(adapter)
}

// RemoteDestination 实现 C.Connection。
func (sc *SessionConn) RemoteDestination() string {
	return sc.Current().RemoteDestination()
}

// ResolveUDP 实现 C.PacketConn。
func (sc *SessionConn) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	return sc.Current().ResolveUDP(ctx, metadata)
}
