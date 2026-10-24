package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/gamelane"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/nat"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/slowdown"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	P "github.com/metacubex/mihomo/constant/provider"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"golang.org/x/exp/slices"
)

const (
	queueCapacity  = 64  // chan capacity tcpQueue and udpQueue
	senderCapacity = 128 // chan capacity of PacketSender

	// hiBurstLimit caps consecutive high-priority UDP packets before a
	// normal packet is drained (3:1 round-robin) to prevent starvation.
	hiBurstLimit = 3

	// retryRegisterIntervalMs 首包进程反查失败（UDP 表未更新）的会话，
	// 后续包按此节流持续重试 findProcessByPort，查到游戏进程立即注册接管。
	retryRegisterIntervalMs = 500

	// recvTimeoutMs 对局 UDP 会话劣化判定阈值：观测窗口内
	// lastRecvAt 持续超时即判定链路劣化，立即切 fallbacks。
	// v2.7（确认点 1/2）：由 5000 提升至 10000——"10s 内有回包"判定为
	// 活跃会话（免切锁），"连续 10s 完全 0 回包"才放行死链切换抢救。
	recvTimeoutMs = 10000
	// degradeCheckIntervalMs 退化检查周期：onLane 会话的 no-recv 死链
	// 观测周期（v2.8 起不再承载 RTT 劣化巡检——RTT 比较换优分支已整体
	// 删除，仅连续 10s 完全 0 回包的真死链才允许换备用节点）。
	degradeCheckIntervalMs = 3500
	// birthGraceMs 出生保护期（铁律一 v2.8，与 gamelane.birthGraceMs 一致）：
	// laneEntry 创建（会话出生）后 30 秒内，无论有包无包，严禁
	// dueDegradeCheck 或任何入口调用 SwitchToBestFallback——给足握手与
	// 地图加载时间（18:13:34.674 首包进场同毫秒被巡检误判死链切走的根治门）。
	birthGraceMs = int64(30000)
)

var (
	status          = atomic.NewInt32Enum(Suspend)
	udpInit         sync.Once
	udpQueuesHi     []chan C.PacketAdapter
	udpQueuesNormal []chan C.PacketAdapter
	// laneCache records whether a UDP session (by SNAT key) is on the
	// gameroute fast path, plus the session's remote host (for retargeting
	// when gameroute targets are updated after the session was created).
	// It is fixed from the first packet so a session never switches queues
	// and per-session packet order is preserved.
	laneCache xsync.Map[string, *laneEntry]
	natTable  = nat.New()
	// gamelaneUDPPackets 累计 GameLane 快速通道出站 UDP 包数（状态 API
	// stats.udp_packets 来源，原子累加，无锁开销）。
	gamelaneUDPPackets = atomic.NewUint64(0)
	rules              []C.Rule
	listeners          = make(map[string]C.InboundListener)
	subRules           map[string][]C.Rule
	proxies            = make(map[string]C.Proxy)
	providers          map[string]P.ProxyProvider
	ruleProviders      map[string]P.RuleProvider
	configMux          sync.RWMutex

	// for compatibility, lazy init
	tcpQueue  chan C.ConnContext
	tcpInOnce sync.Once
	udpQueue  chan C.PacketAdapter
	udpInOnce sync.Once

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	findProcessMode = atomic.NewInt32Enum(process.FindProcessStrict)

	snifferDispatcher *sniffer.Dispatcher
	sniffingEnable    = false

	ruleUpdateCallback = utils.NewCallback[P.RuleProvider]()
)

type tunnel struct{}

var Tunnel = tunnel{}
var _ C.Tunnel = Tunnel
var _ P.Tunnel = Tunnel
var _ proxydialer.Tunnel = Tunnel

func (t tunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	connCtx := icontext.NewConnContext(conn, metadata)
	handleTCPConn(connCtx)
}

func initUDP() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}

	udpQueuesHi = make([]chan C.PacketAdapter, numUDPWorkers)
	udpQueuesNormal = make([]chan C.PacketAdapter, numUDPWorkers)
	for i := 0; i < numUDPWorkers; i++ {
		hiQueue := make(chan C.PacketAdapter, queueCapacity)
		normalQueue := make(chan C.PacketAdapter, queueCapacity)
		udpQueuesHi[i] = hiQueue
		udpQueuesNormal[i] = normalQueue
		go processUDP(hiQueue, normalQueue)
	}
	// 2026-10-18 v2.1 漏洞三联动：赛马赢家进场真正变更目标主路时，按目标
	// IP 触发会话重建（走 scheduleRetarget，继承 F4 400ms 去抖与 RC4 收窄）。
	gamelane.Default().SetRetargetHook(scheduleRetarget)
}

func (t tunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	udpInit.Do(initUDP)

	packetAdapter := C.NewPacketAdapter(packet, metadata)
	key := packetAdapter.Key()

	// UDP 流特征观察：每个出站 UDP 包喂入统计（不依赖进程名/游戏名单）。
	// 当某个目标 IP 的流呈现"持续高频小包"的游戏对局特征时自动注册，
	// 并立即重评估已建立的 UDP 会话，使后续包命中 GameLane 快速通道。
	if gamelane.Default().ObserveUDPFlow(metadata, len(packet.Data())) {
		// F4：新注册目标 → 去抖后按 IP 精确重建（不再全表重建，诊断 RC4：
		// 数据中心测速阶段连环被打断的直接根因）。
		for _, ip := range gamelane.Default().DrainNewRegistrations() {
			scheduleRetarget(ip)
		}
	}

	// Shadow Forking 扳机（2026-10-17 需求 B；2026-10-18 返工 v2 防爆三原则）：
	// ①外层主线程只做纯内存判定（魔数+长度+端口守卫）与 fake-ip 反查
	//   （resolver.FindHostByIP，纯内存），绝不同步查 DNS；反查失败直接
	//   放行放弃（绝不把 198.18/24 写进锁死表）。
	// ②内层协程再 ResolveIP（1.5s 超时）→ realIP 判锁/学习/赛马——DNS 慢
	//   只卡旁路协程，原包照发、主链路 UDP 不阻塞。
	// ③realIP 算锁、origDst 写回（批复 Q-A 方案 (ii)：addr=原包目的地址
	//   值拷贝——fake-ip 路径=客户端认识的 fake-ip，绝不引用会被
	//   preHandleMetadata 清空的 metadata.DstIP）。原路回包永不拦截
	//   （批复修正一）。未命中路径仅一次 4 字节比较+长度比较，零分配。
	// v2.9 裁决 2：先取目的端口再判魔数——STUN/RakNet 分支需要 dport 守卫
	// （3478/3479/5349/19302 及排除端口一律不算测速探针）。
	if origDstIP, dport, ok := udpDstOf(metadata); ok && gamelane.IsSpeedtestProbePayloadForPort(packet.Data(), dport) {
		// Q-A 方案 (ii)：原包目的地址值拷贝存下（绝不引用 metadata.DstIP）
		origDstAddr := &net.UDPAddr{IP: origDstIP.AsSlice(), Port: int(dport)}
		writeBack := gamelane.PacketWriteBackSink(packet, origDstAddr)
		payload := append([]byte(nil), packet.Data()...)
		// v2.10 P1：记录扳机类型（magic/stun/raknet）到内核事件环，让示波器
		// 能看到"是哪种魔数把这条会话拉进了赛马"，而非只有结果。
		gamelane.RecordProbeTriggerFromPayload(payload, origDstIP.String(), dport)
		if resolver.MappingEnabled() && resolver.IsFakeIP(origDstIP) {
			// 第二招兜底：外层仅纯内存反查域名；反查失败放弃赛马（批复②）
			host, hok := resolver.FindHostByIP(origDstIP)
			if !hok {
				log.Debugln("[GameRoute] fake-ip host not found, race abandoned (dst=%s)", origDstIP)
			} else if gamelane.Default().PendingHostsAdd(host) {
				go func() {
					// 死六二铁律（批复 Q-D）：占位 100% 释放——defer 首行
					// 挂删除，ResolveIP 超时/失败/放弃路径均不泄漏占位。
					defer gamelane.Default().PendingHostsDelete(host)
					gamelane.Default().StartShadowForkingForFakeHost(host, dport, payload, writeBack)
				}()
			}
		} else if origDstIP.Is4() {
			// 真实 IP 模式（第一招已让游戏域名走真实解析）：纯内存判定后触发
			if gamelane.Default().SegmentNeedsRace(origDstIP, dport) {
				gamelane.Default().LearnProbeTemplate(origDstIP.String(), dport, payload)
				go gamelane.Default().StartShadowForking(netip.AddrPortFrom(origDstIP, dport), payload, writeBack)
			}
		}
	}

	hash := utils.MapHash(key)
	queueNo := uint(hash) % uint(len(udpQueuesNormal))

	target := selectUDPQueue(key, metadata, queueNo)

	// 统计 GameLane 快速通道出站 UDP 包（stats.udp_packets 来源）。
	// selectUDPQueue 对同一会话的队列决策固定，通道比较即可区分快速通道。
	if target == udpQueuesHi[queueNo] {
		gamelaneUDPPackets.Add(1)
	}

	select {
	case target <- packetAdapter:
	default:
		packet.Drop()
	}
}

// GameLaneSessionStats 返回 GameLane 快速通道的会话与流量统计，供
// GET /gameroute/status 的 stats 输出：managed = 当前 onLane 会话数
// （laneCache 快照遍历，非精确并发计数但足够监控用），udp = 累计
// 快速通道出站 UDP 包数。只读，无副作用。
func GameLaneSessionStats() (managed int64, udp uint64) {
	laneCache.Range(func(_ string, info *laneEntry) bool {
		if info.onLane {
			managed++
		}
		return true
	})
	return managed, gamelaneUDPPackets.Load()
}

// laneEntry 记录单个 UDP 会话在 gameroute 快速通道上的状态。
// onLane 与 selectUDPQueue 首包决策一致；dst 保存远端主机（IP），
// 供 targets 更新后 RetargetUDP 精确判断该会话是否应重新匹配。
// pendingRetry 标记首包进程反查失败（UDP 表未更新）的会话，后续包
// 按 retryRegisterIntervalMs 节流持续重试注册，查到游戏进程立即接管；
// retryAt 为下次重试时间（毫秒）。
// lastRecvAt 记录该会话最后一次收到目标响应的时间（毫秒时间戳），
// 用于对局 UDP 实时监控：观测窗口内无 recv（lastRecvAt 持续超时）
// 即判定链路劣化，立即切换 fallbacks 中 RTT 最低节点。
type laneEntry struct {
	onLane       bool
	dst          string
	activeProxy  string // 铁律一（v2.2）：会话实际拨号节点（handleUDPConn 出口确定后写回；M3 内部切换后可能陈旧，由铁律二兜底）
	recvCount    int    // 铁律二（v2.2）：累计回包数（markRecv 递增；>=1 即五元组已握手绑定）
	dport        uint16 // 铁律二（v2.3）：目标端口（IsStatelessProbePort 判定用；10200 等动态对局端口不在 gamePortRanges，绝不按黑名单放行）
	pendingRetry bool
	retryAt      int64

	// mu 保护下列监控时间戳（F3）：下行 connection.go 与上行 selectUDPQueue
	// 并发更新，原“Load-改-Store 整条回写”存在丢失更新竞态——活跃会话会被
	// 误判 5s 无回包而触发重建（诊断 RC3）。v2.2 起 activeProxy/recvCount
	// 亦由本锁保护。
	mu                 sync.Mutex
	lastRecvAt         int64 // 毫秒时间戳
	lastDegradeCheckAt int64 // 毫秒时间戳
	lastOverdueAt      int64 // 5s 无回包分支的连续超时观测（需连续两个周期才触发）
	birthAt            int64 // 铁律一（v2.8）：会话出生时刻（laneEntry 创建第 0 毫秒），30s 出生保护期判定基线
}

// markRecv 收到目标响应即刷新 recv 时间戳（原子合并写，不再整条回写）。
// v2.2：同时递增 recvCount——>=1 即该会话已与服务器完成握手绑定（铁律二）。
func (e *laneEntry) markRecv(now int64) {
	e.mu.Lock()
	if now > e.lastRecvAt {
		e.lastRecvAt = now
	}
	e.recvCount++
	e.lastOverdueAt = 0
	e.mu.Unlock()
}

// setActiveProxy 会话拨号出口确定后写回（铁律一数据基座，handleUDPConn 调用）。
func (e *laneEntry) setActiveProxy(name string) {
	e.mu.Lock()
	e.activeProxy = name
	e.mu.Unlock()
}

// snapshotActiveProxy 读取当前拨号节点名（铁律一比较用）。
func (e *laneEntry) snapshotActiveProxy() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activeProxy
}

// setDst fake-ip 回填 realIP 后同步更新远端记录（v2.3 批复第二节：
// laneEntry.dst 必须与真实目标 IP 一致，否则 collectRetargetKeys 的
// dstMatchTargets 永远失配）。读侧统一走 snapshotDst（mu 保护）。
func (e *laneEntry) setDst(dst string) {
	e.mu.Lock()
	e.dst = dst
	e.mu.Unlock()
}

// snapshotDst 读取远端记录（写侧 setDst 带 mu，读侧一并收口防撕裂）。
func (e *laneEntry) snapshotDst() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dst
}

// snapshotDport 读取目标端口（IsStatelessProbePort 判定用）。
func (e *laneEntry) snapshotDport() uint16 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dport
}

// handshakeProtected 铁律二判定（v2.2 批复）：已走五区代理 + 已握手
// （recvCount>=1）+ 最近 recvTimeoutMs(5s) 内有回包 → 活跃已绑定会话，
// 禁止因 auto-register / 赢家进场掐断重建；新节点只服务下一个新建会话
// 或死链抢救（Q-G3：握手成功后保持五元组不断连是最高死命令）。
// 唯一放行：从未握手（recvCount==0）或连续 5s 无回包（链路已死）。
func (e *laneEntry) handshakeProtected(now int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.onLane && e.recvCount >= 1 && now-e.lastRecvAt < recvTimeoutMs
}

// birthProtected 铁律一判定（v2.8）：会话出生（laneEntry 创建）后
// birthGraceMs（30s）内，无论有包无包，严禁 dueDegradeCheck 或任何
// 入口调用 SwitchToBestFallback——握手/地图加载期 0 回包是正常现象，
// 不是死链（18:13:34.674 首包进场同毫秒被巡检误切走香港02 的根治门）。
func (e *laneEntry) birthProtected(now int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return now-e.birthAt < birthGraceMs
}

// dueDegradeCheck 3.5s 周期检查入口：到期返回 true 并推进检查时间。
func (e *laneEntry) dueDegradeCheck(now, intervalMs int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if now-e.lastDegradeCheckAt < intervalMs {
		return false
	}
	e.lastDegradeCheckAt = now
	return true
}

// noRecvOverdue 连续两个观测周期（间隔 >= intervalMs）仍满足 lastRecvAt 超时
// 才判定劣化（F3：单次误判不再触发切换重建）。
func (e *laneEntry) noRecvOverdue(now, timeoutMs, intervalMs int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if now-e.lastRecvAt < timeoutMs {
		e.lastOverdueAt = 0
		return false
	}
	if e.lastOverdueAt == 0 {
		e.lastOverdueAt = now
		return false
	}
	if now-e.lastOverdueAt >= intervalMs {
		e.lastOverdueAt = now
		return true
	}
	return false
}

// resetRecv 会话重建成功后重置监控基线。
func (e *laneEntry) resetRecv(now int64) {
	e.mu.Lock()
	e.lastRecvAt = now
	e.lastOverdueAt = 0
	e.mu.Unlock()
}

// fakeIPHostLookup fake-ip → host 反查（v2.3 修改②数据源；包级变量便于
// 单测注入，生产 = resolver.FindHostByIP，纯内存纳秒级）。
var fakeIPHostLookup = func(ip netip.Addr) (string, bool) {
	return resolver.FindHostByIP(ip)
}

// selectUDPQueue decides the scheduling queue for a UDP packet.
// When gameroute is enabled, the first packet of a session is matched
// against the fast-path targets and the result is cached per session, so
// all packets of one session stick to the same queue and per-session
// packet order is never reordered. When gameroute is disabled the normal
// queue is always used, leaving default behaviour untouched.
func selectUDPQueue(key string, metadata *C.Metadata, queueNo uint) chan C.PacketAdapter {
	if !gamelane.Default().Enabled() {
		return udpQueuesNormal[queueNo]
	}
	// 铁令 C（2026-10-18 v2.4 批复）：排除端口（8125 遥测/443 QUIC/53 DNS
	// 等）一票否决——严禁注册/onLane/SessionConn 包装观测（RC12 回归修复）。
	if gamelane.IsExcludedAutoRegPort(metadata.DstPort) {
		return udpQueuesNormal[queueNo]
	}
	if lane, ok := laneCache.Load(key); ok {
		if lane.onLane {
			now := time.Now().UnixMilli()
			// 铁律一/铁律三（v2.8）：出生保护期（30s）内，无论有包无包，
			// 严禁因任何原因调 SwitchToBestFallback（dueDegradeCheck rtt
			// 巡检分支已整体删除——首包进场 recv==0 时 lastDegradeCheckAt
			// 立即到期，扫到刚创建的 laneEntry 误判死链切走香港02 的根因）。
			// 铁律二：RTT 比大小换优分支（>120ms / >1.5x / 候选池更低即切）
			// 全部删除；仅出生期度过且连续 10s 完全 0 回包（真死链）才放行。
			if lane.birthProtected(now) {
				// 出生保护：握手/地图加载期 0 回包是正常现象，不是死链。
			} else if lane.noRecvOverdue(now, recvTimeoutMs, degradeCheckIntervalMs) {
				// v6.8：对局 UDP 死链监控——观测窗口内持续无目标响应即判定
				// 劣化，切换备用出口并重建本会话。F3：需连续两个观测周期
				// （间隔 >=3.5s，实际约 13.5s）仍无回包才触发，且 lastRecvAt
				// 经 markRecv 原子合并写——单次竞态误判不再触发切换重建。
				if gamelane.Default().SwitchToBestFallback(lane.snapshotDst()) {
					log.Infoln("[GameRoute] UDP degraded (no-recv), rebuild session %s -> %s", key, lane.dst)
					natTable.Delete(key)
					lane.resetRecv(now)
				}
			}
			return udpQueuesHi[queueNo]
		}
		// v6.6：反查失败会话持续重试注册。首包 findProcessByPort 失败
		// （UDP 表未更新）时置 pendingRetry，后续每包按 500ms 节流重试，
		// 查到游戏进程立即注册并强制重建本会话，不等 flow 打分 8 秒。
		if lane.pendingRetry && time.Now().UnixMilli() >= lane.retryAt {
			tun := listener.GetTunConf().Enable
			if gamelane.Default().RegisterGameTargetIfNeeded(metadata, tun) {
				log.Infoln("[GameRoute] UDP retry-register target: %s", lane.dst)
				// 2026-10-18 v2.2 强制修正一 + v2.3 修改④（抢回权，谷歌拍板）：
				// 先升格 onLane=true（补标记，会话既有 socket 不动）；随后
				// scheduleRetarget 抢回——普通规则节点（HK 03）上的未绑定 /
				// 非对局端口会话被重建到 GameLane 出口（HK 02）；已握手对局流
				// （recv>=1 且非无状态测速端口）由 retargetAllowed 拒绝，
				// 保持原样零重建（绝不掐断，code:house 防回归）。
				lane.onLane = true
				lane.pendingRetry = false
				scheduleRetarget(lane.snapshotDst())
				return udpQueuesHi[queueNo]
			}
			lane.retryAt = time.Now().UnixMilli() + retryRegisterIntervalMs
		}
		return udpQueuesNormal[queueNo]
	}
	// first packet of the session: GameLane 注册表匹配优先，识别即注册兜底。
	// v6.4：TUN 模式下 UDP 流量先查 GameLane 目标注册表（CIDR 匹配），
	// 命中即走快速通道再走普通规则——保证新对局/换服/重连的新会话
	// （同 IP 新端口）首包即被 GameLane 接管，不再依赖本包注册时序。
	dst := dstIPOf(metadata.RemoteAddress())
	if metadata.DstIP.IsValid() {
		// v6.6：优先用解析后的真实 IP 作 lane 远端记录。RemoteAddress 在
		// Host 已填充时返回域名，dstIPOf 解析不出 CIDR 可判定的 IP，
		// 会让后续 collectRetargetKeys 的 dstMatchTargets 永远失配。
		dst = metadata.DstIP.String()
	}
	tun := listener.GetTunConf().Enable
	// ① 注册表优先：目标已在内存态 targets（上一局 flow/auto-register
	// 留存或记忆秒识别）时，首包决策不等待进程反查直接命中快速通道。
	if _, ok := gamelane.Default().Match(metadata, tun); ok {
		now := time.Now().UnixMilli()
		laneCache.Store(key, &laneEntry{onLane: true, dst: dst, dport: metadata.DstPort, lastRecvAt: now, birthAt: now})
		// 铁律一（v2.8）：laneEntry 创建第 0 毫秒即上报活跃并注册出生——
		// 30s 出生保护期内禁止一切 SwitchToBestFallback 换节点（香港02
		// 进场即锁死，HK03 无法抢戏）。
		gamelane.Default().ReportActiveRecv(dst, now)
		gamelane.Default().RegisterBirth(dst, now)
		return udpQueuesHi[queueNo]
	}
	// ①′ v2.3 修改②（谷歌 5 行绝杀）：Fake-IP 游戏域名首包放行——DstIP
	// 命中 fake-ip 段（198.18.0.0/15，含 runtime\cache.db 残留旧映射）且
	// 反查 host 命中内置游戏/云后缀（IsGameDomain，13 条清单）时，无视
	// 排除层 198.18.0.0/15 拦截直接 onLane=true 进快速队列。此时手里只有
	// fake-ip 与 host，绝不拿 198.18.x.x 注册 Target（批复原文）；dial
	// 阶段修改③回填 realIP 后同步注册真实 /32 Target（衔接细节 1）。
	// cache.db 残留映射在重启后池内不存在 → 反查失败 → 走原路径（部署
	// 删 cache.db 兜底）。fakeIPHostLookup 为包级变量，单测可注入。
	if metadata.DstIP.IsValid() && resolver.IsFakeIP(metadata.DstIP) {
		if host, ok := fakeIPHostLookup(metadata.DstIP); ok && gamelane.Default().IsGameDomain(host) {
			now := time.Now().UnixMilli()
			laneCache.Store(key, &laneEntry{onLane: true, dst: dst, dport: metadata.DstPort, lastRecvAt: now, birthAt: now})
			// 铁律一（v2.8）：laneEntry 创建第 0 毫秒即上报活跃并注册出生——
			// 30s 出生保护期内禁止一切 SwitchToBestFallback 换节点（香港02
			// 进场即锁死，HK03 无法抢戏）。
			gamelane.Default().ReportActiveRecv(dst, now)
			gamelane.Default().RegisterBirth(dst, now)
			log.Infoln("[GameRoute] fake-ip game-domain first-packet onLane: %s (%s)", dst, host)
			return udpQueuesHi[queueNo]
		}
	}
	// ①″ v2.4 1.2（游戏进程活跃期秒接管）：gameActiveUntil 活跃期内，
	// 陌生公网 1024+ 非排除端口首包先同步注册（段表/域名 0ms），失败按
	// 游戏候选流 trusted 直接注册（绕黑名单）——绝不让对局首包滑进普通
	// 规则默认出站（进程反查慢半拍不再阻塞首包）。fake-ip 残留形态由
	// RegisterTargetIPTrusted 内部 isExcludedIP 拒绝（198.18.0.0/15 在排除表）。
	if gamelane.Default().GameActive() && metadata.DstIP.IsValid() && metadata.DstPort >= 1024 &&
		!gamelane.IsExcludedAutoRegPort(metadata.DstPort) && metadata.DstIP.Is4() {
		tun := listener.GetTunConf().Enable
		registered := gamelane.Default().RegisterGameTargetIfNeeded(metadata, tun)
		if !registered && metadata.DstIP.IsGlobalUnicast() && !metadata.DstIP.IsPrivate() {
			registered = gamelane.Default().RegisterTargetIPTrusted(metadata.DstIP.String(), true)
		}
		if registered {
			if _, ok := gamelane.Default().Match(metadata, tun); ok {
				now := time.Now().UnixMilli()
				laneCache.Store(key, &laneEntry{onLane: true, dst: dst, dport: metadata.DstPort, lastRecvAt: now, birthAt: now})
				// 铁律一（v2.8）：laneEntry 创建第 0 毫秒即上报活跃并注册出生——
				// 30s 出生保护期内禁止一切 SwitchToBestFallback 换节点（香港02
				// 进场即锁死，HK03 无法抢戏）。
				gamelane.Default().ReportActiveRecv(dst, now)
				gamelane.Default().RegisterBirth(dst, now)
				log.Infoln("[GameRoute] game-active fast-path onLane: %s", dst)
				return udpQueuesHi[queueNo]
			}
		}
	}
	// ② 识别即注册：进程反查（findProcessByPort）+ 目标 IP 判定在首包
	// 决策前完成，确认游戏进程 + 公网 UDP 后立即注册并接管首包
	// （不等待会话建立 / flow 观察期）。注册失败/非游戏流量/已注册
	// 均零影响，随后重匹配决策不受阻塞。
	if gamelane.Default().RegisterGameTargetIfNeeded(metadata, tun) {
		log.Infoln("[GameRoute] UDP first-packet auto-register target: %s", dst)
		// F4：新注册目标精确重建（去抖），使同 IP 的其他在途会话进 lane。
		scheduleRetarget(dst)
		if _, ok := gamelane.Default().Match(metadata, tun); ok {
			now := time.Now().UnixMilli()
			laneCache.Store(key, &laneEntry{onLane: true, dst: dst, dport: metadata.DstPort, lastRecvAt: now, birthAt: now})
			// 铁律一（v2.8）：laneEntry 创建第 0 毫秒即上报活跃并注册出生——
			// 30s 出生保护期内禁止一切 SwitchToBestFallback 换节点（香港02
			// 进场即锁死，HK03 无法抢戏）。
			gamelane.Default().ReportActiveRecv(dst, now)
			gamelane.Default().RegisterBirth(dst, now)
			return udpQueuesHi[queueNo]
		}
	}
	// v6.6：识别失败区分"反查失败可重试"与"明确非游戏不可重试"。
	// 反查失败（UDP 表未更新）的会话标记 pendingRetry，后续包持续重试；
	// 明确非游戏进程/探测端口/排除段等不再反复反查。
	pending := gamelane.Default().RegisterRetryHint(metadata, tun)
	laneCache.Store(key, &laneEntry{onLane: false, dst: dst, dport: metadata.DstPort, pendingRetry: pending, retryAt: time.Now().UnixMilli() + retryRegisterIntervalMs})
	return udpQueuesNormal[queueNo]
}

// dstIPOf 从 "host:port" 中提取 host；无法解析时返回空串。
func dstIPOf(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return ""
}

// dstMatchTargets 判断远端 IP 是否命中任一 gameroute target 的 CIDR。
// udpDstOf 提取出站 UDP 包的目标 (IP, port)（Shadow Forking 扳机用）。
func udpDstOf(metadata *C.Metadata) (netip.Addr, uint16, bool) {
	if metadata == nil || !metadata.DstIP.IsValid() || metadata.DstPort == 0 {
		return netip.Addr{}, 0, false
	}
	return metadata.DstIP.Unmap(), metadata.DstPort, true
}

func dstMatchTargets(dst string, targets []gamelane.Target) bool {
	if dst == "" || len(targets) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(dst)
	if err != nil {
		return false
	}
	for i := range targets {
		for _, p := range targets[i].CIDR {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// collectRetargetKeys 返回应重建的 UDP 会话 key 列表（v6.6 全表扫描版）：
// 遍历 natTable 真实会话，凡 laneCache 记录其远端 IP 命中当前 targets 的
// 一律强制重建——不再依赖 onLane==false 过滤（首包决策时 GameLane 未启用、
// 或 dst 以域名写入导致 CIDR 匹配失败等场景会让 onLane==false 会话漏掉），
// flow/auto-register 注册新目标后下一包即重走 Match 命中 GameLane。
// laneCache 无记录的会话（GameLane 启用前建立）无法判断远端 IP，跳过。
func collectRetargetKeys(cache *xsync.Map[string, *laneEntry], targets []gamelane.Target) []string {
	if len(targets) == 0 {
		return nil
	}
	var keys []string
	natTable.Range(func(key string, _ C.PacketSender) bool {
		info, ok := cache.Load(key)
		if !ok {
			return true
		}
		if dstMatchTargets(info.snapshotDst(), targets) {
			keys = append(keys, key)
		}
		return true
	})
	return keys
}

// retargetAllowed 铁律一/二裁决（2026-10-18 v2.2 批复）：该会话是否允许
// 被 retarget 掐断重建。
//   - 铁律一：重建后节点未变（activeProxy == 目标现行主路 EffectiveProxy）
//     → 短路——重建 = 出口新随机源端口 = 已握手五元组绑定失效，服务器按
//     垃圾包静默 DROP（code:house 根因），绝不自杀。
//   - 铁律二：已握手（recv>=1）且 5s 内有回包的活跃会话 → 保护——
//     auto-register / 赛马赢家进场只服务下一个新建会话；唯一放行 =
//     从未握手或连续 5s 无回包死链（Q-G3：握手成功后保持五元组不断连
//     是最高死命令）。M3 严重劣化走 SessionConn 通道不经此处。
//
// 返回 true = 允许重建。
func retargetAllowed(info *laneEntry, now int64) bool {
	dst := info.snapshotDst()
	newProxy := gamelane.Default().EffectiveProxyForIP(dst)
	if cur := info.snapshotActiveProxy(); newProxy != "" && cur == newProxy {
		log.Debugln("[GameRoute] retarget skip (same-proxy) proxy=%s", cur)
		return false
	}
	// 铁律二（v2.3 Q-H1 反转口径）：只要已握手（recv>=1 且 5s 内活跃）且
	// 不是无状态测速端口（7770/已学习模板端口），一律严禁掐断——APEX 对局
	// 服务器 216.244.12.165:10200 不在 gamePortRanges，"对局端口黑名单"
	// 口径会把它放行掐断 → code:house 复发（批复铁证）。新节点只服务
	// 下一个新建会话或死链抢救（Q-G3）。
	dport := info.snapshotDport()
	if info.handshakeProtected(now) && !gamelane.Default().IsStatelessProbePort(dstAddrOf(dst), dport) {
		log.Debugln("[GameRoute] retarget skip (protected) proxy=%s dport=%d", info.snapshotActiveProxy(), dport)
		return false
	}
	return true
}

// dstAddrOf 会话远端 IP 解析（IsStatelessProbePort 模板查表用；解析失败返回
// 零值 Addr，7770 判定不受影响）。
func dstAddrOf(dst string) netip.Addr {
	addr, _ := netip.ParseAddr(dst)
	return addr
}

// RetargetUDPFor 按“新注册的目标 IP”精确重建会话（F4 注册重建收窄）：
// 只删除 dst==该 IP 的 lane 会话，不再全表匹配——APEX 数据中心测速阶段
// 连续注册几十个 IP 时，原全表重建会把先前数据中心的测速会话连环打断
// （诊断 RC4：全部 -1ms/100% 丢包的直接根因）。返回重建的会话数。
// 2026-10-18 v2.2：铁律一（同节点短路）+ 铁律二（已握手活跃会话保护）
// 把守，auto-register / 赢家进场不再掐断活跃对局会话（code:house 根因）。
func RetargetUDPFor(ip string) int {
	if ip == "" {
		return 0
	}
	now := time.Now().UnixMilli()
	var keys []string
	skipped := 0
	laneCache.Range(func(key string, info *laneEntry) bool {
		if info.snapshotDst() != ip {
			return true
		}
		if !retargetAllowed(info, now) {
			skipped++
			return true
		}
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		natTable.Delete(key)
		laneCache.Delete(key)
	}
	if len(keys) > 0 {
		log.Infoln("[GameRoute] retarget UDP sessions for %s: %d", ip, len(keys))
	}
	if skipped > 0 {
		log.Debugln("[GameRoute] retarget protected sessions for %s: %d", ip, skipped)
	}
	return len(keys)
}

// retarget 去抖（F4）：连续注册在 retargetDebounceMs 内合并为一次批量重建。
const retargetDebounceMs = 400

var (
	retargetMu    sync.Mutex
	retargetQueue []string
	retargetTimer *time.Timer
)

// scheduleRetarget 排队一个待重建目标 IP，retargetDebounceMs 后批量执行。
func scheduleRetarget(ip string) {
	if ip == "" {
		return
	}
	retargetMu.Lock()
	defer retargetMu.Unlock()
	retargetQueue = append(retargetQueue, ip)
	if retargetTimer != nil {
		return
	}
	retargetTimer = time.AfterFunc(retargetDebounceMs*time.Millisecond, func() {
		retargetMu.Lock()
		ips := retargetQueue
		retargetQueue = nil
		retargetTimer = nil
		retargetMu.Unlock()
		seen := make(map[string]bool, len(ips))
		total := 0
		for _, target := range ips {
			if seen[target] {
				continue
			}
			seen[target] = true
			total += RetargetUDPFor(target)
		}
		if total > 0 {
			log.Infoln("[GameRoute] retarget (narrowed) total sessions rebuilt: %d", total)
		}
	})
}

// RetargetUDP 在 gameroute targets 更新后调用，重评估已建立的 UDP 会话：
// 目标命中新 targets 但首包未进 lane 的会话会被重建，使后续包命中 GameLane；
// targets 被整体清空（一键清空）时，所有已进 lane 的会话一并重建，
// 回到普通规则路径，保证"清空后重新识别"彻底生效。
func RetargetUDP() {
	targets := gamelane.Default().GetTargets()
	if len(targets) == 0 {
		var keys []string
		laneCache.Range(func(key string, info *laneEntry) bool {
			keys = append(keys, key)
			return true
		})
		for _, key := range keys {
			natTable.Delete(key)
			laneCache.Delete(key)
		}
		if len(keys) > 0 {
			log.Infoln("[GameRoute] reset UDP lane sessions: %d", len(keys))
		}
		return
	}
	keys := collectRetargetKeys(&laneCache, targets)
	// 2026-10-18 v2.2：全局重评估同样受铁律一/二保护——同节点/已握手
	// 活跃会话不得因 targets 更新被掐断（一键清空分支除外，见上）。
	now := time.Now().UnixMilli()
	var allowed []string
	for _, key := range keys {
		if info, ok := laneCache.Load(key); ok && !retargetAllowed(info, now) {
			continue
		}
		allowed = append(allowed, key)
	}
	for _, key := range allowed {
		natTable.Delete(key)
		laneCache.Delete(key)
	}
	if len(allowed) > 0 {
		log.Infoln("[GameRoute] retarget UDP sessions: %d", len(allowed))
	}
}

func (t tunnel) NatTable() C.NatTable {
	return natTable
}

func (t tunnel) Proxies() map[string]C.Proxy {
	return proxies
}

func (t tunnel) Providers() map[string]P.ProxyProvider {
	return providers
}

func (t tunnel) RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

func (t tunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return ruleUpdateCallback
}

func OnSuspend() {
	status.Store(Suspend)
}

func OnInnerLoading() {
	status.Store(Inner)
}

func OnRunning() {
	status.Store(Running)
}

func Status() TunnelStatus {
	return status.Load()
}

func SetSniffing(b bool) {
	if snifferDispatcher.Enable() {
		configMux.Lock()
		sniffingEnable = b
		configMux.Unlock()
	}
}

func IsSniffing() bool {
	return sniffingEnable
}

// TCPIn return fan-in queue
// Deprecated: using Tunnel instead
func TCPIn() chan<- C.ConnContext {
	tcpInOnce.Do(func() {
		tcpQueue = make(chan C.ConnContext, queueCapacity)
		go func() {
			for connCtx := range tcpQueue {
				go handleTCPConn(connCtx)
			}
		}()
	})
	return tcpQueue
}

// UDPIn return fan-in udp queue
// Deprecated: using Tunnel instead
func UDPIn() chan<- C.PacketAdapter {
	udpInOnce.Do(func() {
		udpQueue = make(chan C.PacketAdapter, queueCapacity)
		go func() {
			for packet := range udpQueue {
				Tunnel.HandleUDPPacket(packet, packet.Metadata())
			}
		}()
	})
	return udpQueue
}

// NatTable return nat table
func NatTable() C.NatTable {
	return natTable
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

func Listeners() map[string]C.InboundListener {
	return listeners
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule, newSubRule map[string][]C.Rule, rp map[string]P.RuleProvider) {
	configMux.Lock()
	rules = newRules
	ruleProviders = rp
	subRules = newSubRule
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[string]P.ProxyProvider {
	return providers
}

// RuleProviders return all loaded rule providers
func RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]P.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

func UpdateListeners(newListeners map[string]C.InboundListener) {
	configMux.Lock()
	defer configMux.Unlock()
	listeners = newListeners
}

func UpdateSniffer(dispatcher *sniffer.Dispatcher) {
	configMux.Lock()
	snifferDispatcher = dispatcher
	sniffingEnable = dispatcher.Enable()
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

func FindProcessMode() process.FindProcessMode {
	return findProcessMode.Load()
}

// SetFindProcessMode replace SetAlwaysFindProcess
// always find process info if legacyAlways = true or mode.Always() = true, may be increase many memory
func SetFindProcessMode(mode process.FindProcessMode) {
	findProcessMode.Store(mode)
}

func isHandle(t C.Type) bool {
	status := status.Load()
	return status == Running || (status == Inner && t == C.INNER)
}

func fixMetadata(metadata *C.Metadata) {
	// first unmap dstIP
	metadata.DstIP = metadata.DstIP.Unmap()
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip.Unmap()
		metadata.Host = ""
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
			if resolver.IsFakeIP(metadata.DstIP) {
				// only clear dstIP if it is confirmed to be a fake IP
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else if node, ok := resolver.DefaultHosts.Search(host, false); ok {
				// redir-host should lookup the hosts
				metadata.DstIP, _ = node.RandIP()
			} else if node != nil && node.IsDomain {
				metadata.Host = node.Domain
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	} else if node, ok := resolver.DefaultHosts.Search(metadata.Host, true); ok {
		// try use domain mapping
		metadata.Host = node.Domain
	}

	return nil
}

func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	if metadata.SpecialProxy != "" {
		var exist bool
		proxy, exist = proxies[metadata.SpecialProxy]
		if !exist {
			err = fmt.Errorf("proxy %s not found", metadata.SpecialProxy)
		}
		return
	}
	var (
		resolved             bool
		attemptProcessLookup = metadata.Type != C.INNER
	)

	if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
		metadata.DstIP, _ = node.RandIP()
		resolved = true
	}

	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			if !resolved && metadata.Host != "" && !metadata.Resolved() {
				ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
				defer cancel()
				ip, err := resolver.ResolveIP(ctx, metadata.Host)
				if err != nil {
					log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				} else {
					log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
					metadata.DstIP = ip
				}
				resolved = true
			}
		},
		FindProcess: func() {
			if attemptProcessLookup {
				attemptProcessLookup = false
				if !features.CMFA {
					// normal check for process
					uid, path, err := process.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(metadata.SrcPort))
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = filepath.Base(path)
						metadata.ProcessPath = path
						metadata.Uid = uid

						if pkg, err := process.FindPackageName(metadata); err == nil { // for android (not CMFA) package names
							metadata.Process = pkg
						}
					}
				} else {
					// check package names
					pkg, err := process.FindPackageName(metadata)
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = pkg
					}
				}
			}
		},
		CheckPassRule: func(adapterName string) bool {
			adapter, ok := proxies[adapterName]
			if !ok {
				return false
			}
			for a := adapter; a != nil; a = a.Unwrap(metadata, false) {
				if a.Type() == C.PassRule {
					return true
				}
			}
			return false
		},
	}

	switch FindProcessMode() {
	case process.FindProcessAlways:
		helper.FindProcess()
		helper.FindProcess = nil
	case process.FindProcessOff:
		helper.FindProcess = nil
	}

	switch mode {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	// Rule
	default:
		proxy, rule, err = match(metadata, helper)
	}
	return
}

// processUDP starts a loop to handle udp packet from both queues.
// High-priority packets are served first; after hiBurstLimit(3) consecutive
// high-priority packets one normal packet is drained (3:1 round-robin) so
// normal traffic can never be starved. Scheduling only happens between
// sessions: packets of one session stay in the same queue and are consumed
// in order.
func processUDP(hi, normal chan C.PacketAdapter) {
	hiBurst := 0
	for {
		var packet C.PacketAdapter
		if hiBurst >= hiBurstLimit {
			// burst limit reached: drain a normal packet first; fall back to
			// high-priority only when the normal queue is empty
			select {
			case packet = <-normal:
				hiBurst = 0
				handleUDPConn(packet)
				continue
			default:
				hiBurst = 0
			}
		}
		// high-priority first: peek hi without blocking
		select {
		case packet = <-hi:
			hiBurst++
			handleUDPConn(packet)
			continue
		default:
		}
		// hi empty: block on normal, also accept late hi packets
		select {
		case packet = <-normal:
			hiBurst = 0
		case packet = <-hi:
			hiBurst++
		}
		handleUDPConn(packet)
	}
}

func handleUDPConn(packet C.PacketAdapter) {
	if !isHandle(packet.Metadata().Type) {
		packet.Drop()
		return
	}

	metadata := packet.Metadata()
	if !metadata.Valid() {
		packet.Drop()
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	if err := preHandleMetadata(metadata.Clone()); err != nil { // precheck without modify metadata
		packet.Drop()
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	key := packet.Key()
	sender, loaded := natTable.GetOrCreate(key, func() C.PacketSender {
		sender := newPacketSender()
		if sniffingEnable && snifferDispatcher.Enable() {
			return snifferDispatcher.UDPSniff(packet, sender)
		}
		return sender
	})
	if !loaded {
		dial := func() (C.PacketConn, C.WriteBackProxy, error) {
			originMetadata := metadata  // save origin metadata
			metadata = metadata.Clone() // don't modify PacketAdapter's metadata

			if err := sender.DoSniff(metadata); err != nil {
				log.Warnln("[UDP] DoSniff error: %s", err.Error())
				return nil, nil, err
			}

			_ = preHandleMetadata(metadata) // error was pre-checked

			// v2.6 第二刀（2026-10-19 终批复修正三）：主路由不再本地
			// resolver.ResolveIP 回填 DstIP——本地 DoH 解析出新加坡/东京 IP
			// 会把目标定成海外对局服务器（HK02 绕路 75ms 根因）。fake-ip 会话
			// 保留域名形态交出口（Trojan/SS 原生支持按域名转发），HK02 落地机
			// 在香港本地解析 → Geo-DNS 返回香港服务器（1ms）。真实 IP 只在
			// 赛马旁路解析（StartShadowForkingForFakeHost，主路与旁路解耦）。
			// 仅保留 FindHostByIP 补 Host（终批复裁决：纯内存纳秒级查表，
			// 无网络开销、不污染 DstIP——救回 preHandleMetadata 漏填 Host 的
			// cache.db 残留边界，交 gamelane 联动 A 域名分发）。
			if resolver.MappingEnabled() && (metadata.DNSMode == C.DNSFakeIP || resolver.IsFakeIP(metadata.DstIP)) {
				if metadata.Host == "" && metadata.DstIP.IsValid() {
					if h, ok := resolver.FindHostByIP(metadata.DstIP); ok {
						metadata.Host = h
					}
				}
			}

			var proxy C.Proxy
			var rule C.Rule
			var err error
			// F9（红线 9 落地，2026-10-16 用户确认方案 A）：撤销 v6.13
			// "端口 53 强制 DIRECT"——明文 UDP 53 直连正是用户明确拒绝的
			// DNS 裸直连；TUN 已配置 dns-hijack(any:53)，主机明文 DNS 由
			// DNS 模块接管，此处流量按规则匹配（DNS 上游已全部加密 DoH）。
			if proxyName, ok := gamelane.Default().Match(metadata, listener.GetTunConf().Enable); ok {
				p, exist := proxies[proxyName]
				if !exist {
					log.Warnln("[GameRoute] proxy %s not found, fallback to rules", proxyName)
					proxy, rule, err = resolveMetadata(metadata)
				} else {
					proxy = p
					log.Infoln("[GameRoute] UDP %s --> %s via %s", metadata.SourceDetail(), metadata.RemoteAddress(), proxyName)
				}
			} else {
				proxy, rule, err = resolveMetadata(metadata)
			}
			if err != nil {
				log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
				return nil, nil, err
			}

			// 铁律一数据基座（2026-10-18 v2.2）：记录本会话实际拨号节点
			// （含规则路径出口），供 RetargetUDPFor 同节点短路比较（重建
			// = 换 NAT 源端口 = 已握手五元组绑定失效）。lane 无条目时跳过。
			if e, ok := laneCache.Load(key); ok {
				e.setActiveProxy(proxy.Name())
			}

			dialMetadata := metadata.Pure()
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
			defer cancel()
			rawPc, err := retry(ctx, func(ctx context.Context) (C.PacketConn, error) {
				return proxy.ListenPacketContext(ctx, dialMetadata)
			}, func(err error) {
				logMetadataErr(metadata, rule, proxy, err)
			})
			if err != nil {
				return nil, nil, err
			}
			logMetadata(metadata, rule, rawPc)

			var pc C.PacketConn = statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule, 0, 0, true)

			// M3 预测式切换：gamelane 命中且配置备用出口时，用观测包装层包裹
			// PacketConn，质量恶化时原子切换到备用出口（新建 PacketConn →
			// 迁移读路径 → 关闭旧连接）。M3 子开关关闭时不创建切换包装层，
			// 游戏仍走快速通道（M1）但不会自动切节点。
			// v2.8 第二刀：M3PredictiveSwitchingEnabled() 总闸强制关闭——
			// 游戏对局 UDP 会话不支持局中无缝换出口（一换必 recv=0 掉线），
			// 已建连会话绝不创建会自主换节点的 SessionConn 切换包装。
			if t, ok := gamelane.Default().MatchTarget(metadata, listener.GetTunConf().Enable); ok && len(t.Fallbacks) > 0 && gamelane.M3Enabled() && gamelane.M3PredictiveSwitchingEnabled() {
				// P2：QUIC 判定接线——sender 经 QUIC sniff 包装后暴露 IsQUIC，
				// 判定为 QUIC 的会话传入 isQUIC=true（抖动维度参与评分）。
				isQUIC := false
				if q, ok := sender.(interface{ IsQUIC() bool }); ok {
					isQUIC = q.IsQUIC()
				}
				var sc *gamelane.SessionConn
				sc = gamelane.NewSessionConn(pc, key, isQUIC, gamelane.DefaultConfig(), func(toPrimary bool) error {
					if !toPrimary {
						// 死六四②：M3 劣化切换 = 解锁重赛条件②（旧条目入
						// stale，重赛防抖动裁决见 lockSegment）。fake-ip 模式
						// DstIP 被 preHandleMetadata 清空 → 按 Host 解锁。
						if metadata.DstIP.IsValid() {
							gamelane.Default().UnlockSegmentForRerace(metadata.DstIP.String(), "m3-switch")
						} else if metadata.Host != "" {
							gamelane.Default().UnlockSegmentForReraceByHost(metadata.Host, "m3-switch")
						}
					}
					if metadata.DstIP.IsValid() {
						// 铁令 B（v2.4）：[obs] 行目标现形（dstIP:dport）
						sc.SetObsDst(netip.AddrPortFrom(metadata.DstIP, metadata.DstPort).String())
					}
					name := t.EffectiveProxy() // autoPrimary 模式取当前实际主节点，配置优先
					if !toPrimary {
						name = sc.SelectedFallback()
						if name == "" {
							// 无可用候选（探测未完成/全部失败）：保持当前节点，
							// 不做无意义切换。
							log.Infoln("[GameRoute] no healthy candidate, keep current (key=%s)", key)
							return nil
						}
					}
					p, exist := proxies[name]
					if !exist {
						return fmt.Errorf("[GameRoute] switch proxy %s not found", name)
					}
					dialMetadata := metadata.Pure()
					ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
					defer cancel()
					newPc, err := p.ListenPacketContext(ctx, dialMetadata)
					if err != nil {
						return err
					}
					log.Infoln("[GameRoute] switch UDP %s to %s", metadata.RemoteAddress(), name)
					sc.Switch(newPc)
					// S1：Auto-Pick 换优为静默切换（current_proxy 已由
					// SetPrimaryObserver 回报刷新），不计 switch_count /
					// last_switch_at / loss_rate；仅故障切换记录 M3 全局状态。
					if !sc.SwitchSilent() {
						gamelane.RecordM3Switch(toPrimary, name, sc.LastSettledLossRate())
					}
					return nil
				})
				// M3 二期：注入备用候选池与候选体检建连工厂，劣化切换前
				// 对候选逐个探测评分选最优出口（单候选保持旧行为）。
				sc.SetFallbacks(t.Fallbacks)
				sc.SetCandidateDialer(func(name string) (C.PacketConn, error) {
					p, exist := proxies[name]
					if !exist {
						return nil, fmt.Errorf("[GameRoute] candidate proxy %s not found", name)
					}
					dialMetadata := metadata.Pure()
					ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
					defer cancel()
					return p.ListenPacketContext(ctx, dialMetadata)
				})
				// F1④/F6：注入会话实测 RTT 回写与候选探测结果回写（与 Manager
				// 同一张 rttTable、同一套平滑/判死策略）。
				sc.SetRTTReporter(gamelane.Default().RecordSessionRTT)
				sc.SetProbeResultSink(gamelane.Default().MergeProbeResult)
				// v2 Auto-Pick Primary（先进游戏，后测后换）：命中时 Proxy 未显式
				// 配置（为空/"auto"）已由 Manager 选出临时主节点进场；此处标记
				// 会话首次上行后自动对候选池体检，探测完成选最优自动切换并回报
				// Manager（GET /gameroute/targets 输出当前实际主节点名）。
				if t.IsAutoPrimary() {
					sc.SetAutoPick(true)
					sc.SetCurrentPrimary(t.EffectiveProxy())
					sc.SetPrimaryObserver(func(name string) {
						t.SetCurrentPrimary(name)
					})
					// 注册即探测：目标注册（auto-register / memory-hit /
					// flow-score）成功、会话建立后立即对候选池发起体检，
					// 不再等首次上行；60s 冷却仅约束重复探测。
					sc.BeginAutoPickProbe()
				}
				pc = sc
			}

			sender.AddMapping(originMetadata, dialMetadata)
			oAddrPort := dialMetadata.AddrPort()
			writeBackProxy := nat.NewWriteBackProxy(packet)

			go handleUDPToLocal(writeBackProxy, pc, sender, key, oAddrPort)
			return pc, writeBackProxy, nil
		}

		go func() {
			pc, proxy, err := dial()
			if err != nil {
				sender.Close()
				natTable.Delete(key)
				laneCache.Delete(key)
				return
			}
			sender.Process(pc, proxy)
		}()
	}
	sender.Send(packet) // nonblocking
}

func handleTCPConn(connCtx C.ConnContext) {
	if !isHandle(connCtx.Metadata().Type) {
		_ = connCtx.Conn().Close()
		return
	}

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(connCtx.Conn())

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	preHandleFailed := false
	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		preHandleFailed = true
	}

	conn := connCtx.Conn()
	conn.ResetPeeked() // reset before sniffer
	if sniffingEnable && snifferDispatcher.Enable() {
		// Try to sniff a domain when `preHandleMetadata` failed, this is usually
		// caused by a "Fake DNS record missing" error when enhanced-mode is fake-ip.
		if snifferDispatcher.TCPSniff(conn, metadata) {
			// we now have a domain name
			preHandleFailed = false
		}
	}

	// If both trials have failed, we can do nothing but give up
	if preHandleFailed {
		log.Debugln("[Metadata PreHandle] failed to sniff a domain for connection %s --> %s, give up",
			metadata.SourceDetail(), metadata.RemoteAddress())
		return
	}

	peekMutex := sync.Mutex{}
	if !conn.Peeked() {
		peekMutex.Lock()
		go func() {
			defer peekMutex.Unlock()
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	var proxy C.Proxy
	var rule C.Rule
	var err error
	// gameroute 固定快速通道（TCP）：PUBG 大厅/登录等仅 TCP 流量阶段，
	// 命中 CIDR/进程目标时走当前固定出口（auto 目标取进场主节点快照，
	// 显式目标取配置 Proxy），让大厅阶段面板有真实出口展示。
	// TCP 只走固定通道，绝不参与 UDP 的预测式切换/劣化自动切换；
	// 命中但出口为空（DIRECT）或代理不存在时回退常规 rules。
	// F9（红线 9 落地，2026-10-16 用户确认方案 A）：撤销 v6.13 "端口 53
	// 强制 DIRECT"——明文 DNS 直连违背红线 9；DNS over TCP 与 UDP 一样
	// 交回 DNS 模块/规则处理（上游已全部加密 DoH + 固定港台出口）。
	if proxyName, ok := gamelane.Default().MatchTCP(metadata, listener.GetTunConf().Enable); ok {
		// 临时主节点进场后 proxyName 可能为具体节点名；
		// DIRECT 仅当所有代理不可达时兜底（不 fallback）。
		p, exist := proxies[proxyName]
		if !exist && proxyName != "DIRECT" {
			log.Warnln("[GameRoute] proxy %s not found, fallback to rules", proxyName)
			proxy, rule, err = resolveMetadata(metadata)
		} else {
			proxy = p
			log.Infoln("[GameRoute] TCP %s --> %s via %s", metadata.SourceDetail(), metadata.RemoteAddress(), proxyName)
		}
	} else {
		proxy, rule, err = resolveMetadata(metadata)
	}
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	dialMetadata := metadata
	if len(metadata.Host) > 0 {
		if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
			if dstIp, _ := node.RandIP(); !resolver.IsFakeIP(dstIp) {
				dialMetadata.DstIP = dstIp
				dialMetadata.DNSMode = C.DNSHosts
				dialMetadata = dialMetadata.Pure()
			}
		}
	}

	var peekBytes []byte
	var peekLen int

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := retry(ctx, func(ctx context.Context) (remoteConn C.Conn, err error) {
		remoteConn, err = proxy.DialContext(ctx, dialMetadata)
		if err != nil {
			return
		}

		if N.NeedHandshake(remoteConn) {
			defer func() {
				if err != nil {
					_ = remoteConn.Close()
					for _, chain := range remoteConn.Chains() {
						if chain == "REJECT" {
							err = nil
							return
						}
					}
					remoteConn = nil
				}
			}()
			peekMutex.Lock()
			defer peekMutex.Unlock()
			peekBytes, _ = conn.Peek(conn.Buffered())
			_, err = remoteConn.Write(peekBytes)
			if err != nil {
				return
			}
			if peekLen = len(peekBytes); peekLen > 0 {
				_, _ = conn.Discard(peekLen)
			}
		}
		return
	}, func(err error) {
		logMetadataErr(metadata, rule, proxy, err)
	})
	if err != nil {
		return
	}
	logMetadata(metadata, rule, remoteConn)

	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule, int64(peekLen), 0, true)
	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	_ = conn.SetReadDeadline(time.Now()) // stop unfinished peek
	peekMutex.Lock()
	defer peekMutex.Unlock()
	_ = conn.SetReadDeadline(time.Time{}) // reset
	handleSocket(conn, remoteConn)
}

func logMetadataErr(metadata *C.Metadata, rule C.Rule, proxy C.ProxyAdapter, err error) {
	if rule == nil {
		log.Warnln("[%s] dial %s %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	} else {
		log.Warnln("[%s] dial %s (match %s/%s) %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	}
}

func logMetadata(metadata *C.Metadata, rule C.Rule, remoteConn C.Connection) {
	switch {
	case metadata.SpecialProxy != "":
		log.Infoln("[%s] %s --> %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String())
	case rule != nil:
		if rule.Payload() != "" {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload()), remoteConn.Chains().String())
		} else {
			log.Infoln("[%s] %s --> %s match %s using %s dst=%v:%d", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), rule.RuleType().String(), remoteConn.Chains().String(), metadata.DstIP, metadata.DstPort)
		}
	case mode == Global:
		log.Infoln("[%s] %s --> %s using GLOBAL", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	case mode == Direct:
		log.Infoln("[%s] %s --> %s using DIRECT", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	default:
		log.Infoln("[%s] %s --> %s doesn't match any rule using %s dst=%v:%d", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String(), metadata.DstIP, metadata.DstPort)
	}
}

func match(metadata *C.Metadata, helper C.RuleMatchHelper) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	var rematchChain []string
	for {
		var rematchProxy C.Proxy
		var rematchRule C.Rule
	GetRules:
		for _, rule := range getRules(metadata) {
			if matched, ada := rule.Match(metadata, helper); matched {
				adapter, ok := proxies[ada]
				if !ok {
					continue
				}

				// parse multi-layer nesting
				for adapter := adapter; adapter != nil; adapter = adapter.Unwrap(metadata, false) {
					if adapter.Type() == C.Pass {
						log.Debugln("%s match Pass rule", adapter.Name())
						continue GetRules
					}
					if adapter.Type() == C.Rematch {
						log.Debugln("%s match Rematch rule", adapter.Name())
						rematchProxy = adapter
						rematchRule = rule
						break GetRules
					}
				}

				if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
					log.Debugln("%s UDP is not supported", adapter.Name())
					continue
				}

				return adapter, rule, nil
			}
		}
		if rematchProxy != nil {
			if slices.Contains(rematchChain, rematchProxy.Name()) {
				log.Warnln("[Rule] rematch cycle detected on %s", rematchProxy.Name())
				return rematchProxy, rematchRule, nil
			}
			rematchChain = append(rematchChain, rematchProxy.Name())
			conn, err := rematchProxy.DialContext(context.Background(), metadata) // not a real connection, just for metadata update
			if conn != nil {
				_ = conn.Close()
			}
			if err != nil {
				log.Warnln("[Rule] rematch proxy %s failed to update metadata: %s", rematchProxy.Name(), err)
				return rematchProxy, rematchRule, nil
			}
			log.Debugln("[Rule] rematch proxy %s update metadata to rematch-name=%q sub-rule=%q", rematchProxy.Name(), metadata.InName, metadata.SpecialRules)
			continue
		}
		return proxies["DIRECT"], nil, nil
	}
}

func getRules(metadata *C.Metadata) []C.Rule {
	if sr, ok := subRules[metadata.SpecialRules]; ok {
		log.Debugln("[Rule] use %s rules", metadata.SpecialRules)
		return sr
	} else {
		log.Debugln("[Rule] use default rules")
		return rules
	}
}

func shouldStopRetry(err error) bool {
	if errors.Is(err, resolver.ErrIPNotFound) {
		return true
	}
	if errors.Is(err, resolver.ErrIPVersion) {
		return true
	}
	if errors.Is(err, resolver.ErrIPv6Disabled) {
		return true
	}
	if errors.Is(err, loopback.ErrReject) {
		return true
	}
	return false
}

func retry[T any](ctx context.Context, ft func(context.Context) (T, error), fe func(err error)) (t T, err error) {
	s := slowdown.New()
	for i := 0; i < 10; i++ {
		t, err = ft(ctx)
		if err != nil {
			if fe != nil {
				fe(err)
			}
			if shouldStopRetry(err) {
				return
			}
			if s.Wait(ctx) == nil {
				continue
			} else {
				return
			}
		} else {
			break
		}
	}
	return
}
