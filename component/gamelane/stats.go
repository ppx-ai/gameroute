package gamelane

import (
	"math"
	"sync/atomic"
	"time"
)

// M3Snapshot 是 M3 预测式切换的全局状态快照（REST GET /gameroute/status 的 m3 子对象）。
// 字段语义：
//   - Enabled:        M3 预测式切换子开关（关闭时即使目标带 Fallback 也不自动切换）
//   - SwitchCount:    累计自动切换次数（切 fallback 与回切 primary 均计数）
//   - LastSwitchAt:   最近一次自动切换的发生时刻（零值表示从未切换）
//   - CurrentProxy:   最近一次切换后的当前出口节点名（未切换过为空串）
//   - LossRate:       最近一次触发切换的坏窗口下行丢包率（0~1；从未切换为 0）
type M3Snapshot struct {
	Enabled      bool      `json:"enabled"`
	SwitchCount  uint64    `json:"switch_count"`
	LastSwitchAt time.Time `json:"last_switch_at"`
	CurrentProxy string    `json:"current_proxy"`
	LossRate     float64   `json:"loss_rate"`
}

// M3Stats 是 M3 预测式切换的全局统计聚合器（单例）：
// 切换挂点（tunnel 层 switchFn）在每次原子切换成功后调用 RecordM3Switch 更新；
// REST 层通过 Snapshot 读取。并发安全，对未启用 M3 的路径零影响。
type M3Stats struct {
	enabled      atomic.Bool
	switchCount  atomic.Uint64
	lastSwitchAt atomic.Int64 // UnixNano；0 表示从未切换
	currentProxy atomic.Value // string
	lossRateBits atomic.Uint64 // float64 位模式
}

var defaultM3Stats = &M3Stats{}

func init() {
	defaultM3Stats.currentProxy.Store("")
}

// M3Default 返回全局 M3 状态聚合器单例。
func M3Default() *M3Stats {
	return defaultM3Stats
}

// SetM3Enabled 开关 M3 预测式切换（REST PUT /gameroute/targets 的 enable_m3）。
func (s *M3Stats) SetM3Enabled(b bool) {
	s.enabled.Store(b)
	recordDiag("config_update", "kind=m3_enabled value=%v", b)
}

// M3Enabled 返回 M3 预测式切换当前是否启用。
func (s *M3Stats) M3Enabled() bool {
	return s.enabled.Load()
}

// RecordM3Switch 记录一次自动切换：
// toPrimary=true 表示回切快速通道主出口，false 表示切到备用出口；
// proxy 为切换后的出口节点名；lossRate 为触发切换的坏窗口丢包率。
func (s *M3Stats) RecordM3Switch(toPrimary bool, proxy string, lossRate float64) {
	s.switchCount.Add(1)
	s.lastSwitchAt.Store(time.Now().UnixNano())
	s.currentProxy.Store(proxy)
	s.lossRateBits.Store(atomicFloat64Bits(lossRate))
}

// RecordM3Active 同步 Auto-Pick Primary 的当前实际主节点（进场临时节点或
// 候选探测后选中的最优出口）。与 RecordM3Switch 的区别：选路/换优不是故障
// 切换，不计 switch_count、不写 last_switch_at、不改 loss_rate，仅刷新
// current_proxy，让 REST /gameroute/status 的 m3.current_proxy 始终反映
// 当前出口节点（否则未发生切换前该字段恒为空，前端无法展示）。
func (s *M3Stats) RecordM3Active(proxy string) {
	if proxy == "" {
		return
	}
	s.currentProxy.Store(proxy)
}

// Snapshot 返回当前 M3 状态快照。
func (s *M3Stats) Snapshot() M3Snapshot {
	last := s.lastSwitchAt.Load()
	lastAt := time.Time{}
	if last > 0 {
		lastAt = time.Unix(0, last)
	}
	proxy, _ := s.currentProxy.Load().(string)
	return M3Snapshot{
		Enabled:      s.enabled.Load(),
		SwitchCount:  s.switchCount.Load(),
		LastSwitchAt: lastAt,
		CurrentProxy: proxy,
		LossRate:     atomicFloat64FromBits(s.lossRateBits.Load()),
	}
}

// ResetM3Stats 清零 M3 全局状态（测试与配置重载使用）。
func (s *M3Stats) ResetM3Stats() {
	s.enabled.Store(false)
	s.switchCount.Store(0)
	s.lastSwitchAt.Store(0)
	s.currentProxy.Store("")
	s.lossRateBits.Store(0)
}

// 包级便捷函数：route/tunnel 层直接调用，避免每个调用点持有单例引用。

// SetM3Enabled 见 M3Stats.SetM3Enabled。
func SetM3Enabled(b bool) {
	M3Default().SetM3Enabled(b)
}

// M3Enabled 见 M3Stats.M3Enabled。
func M3Enabled() bool {
	return M3Default().M3Enabled()
}

// M3PredictiveSwitchingEnabled 会话级预测式切换总闸（v2.8 第二刀）：
// 默认强制关闭——游戏对局 UDP 会话物理上不支持局中无缝换出口 IP/端口
// （APEX 服务器一旦被 rebuild session 换 NAT 源端口，立即拒收后续所有
// 包：2026-10-19 17:23:14 sent=2001 recv=0 彻底断流实锤）。对局会话必须
// 从第 1 秒到游戏结束死死钉在进场选定的那一个节点上，全程 0 次 rebuild
// session。REST PUT /gameroute/targets 的 enable_m3 仍可置位（面板状态
// 展示），但 handleUDPConn 不再因此创建会自主换节点的 SessionConn 切换
// 包装——已建连会话绝无 M3 干预路径。
func M3PredictiveSwitchingEnabled() bool { return false }

// RecordM3Switch 见 M3Stats.RecordM3Switch。
func RecordM3Switch(toPrimary bool, proxy string, lossRate float64) {
	M3Default().RecordM3Switch(toPrimary, proxy, lossRate)
}

// RecordM3Active 见 M3Stats.RecordM3Active。
func RecordM3Active(proxy string) {
	M3Default().RecordM3Active(proxy)
}

// GetM3Snapshot 返回 M3 全局状态快照（见 M3Stats.Snapshot）。
func GetM3Snapshot() M3Snapshot {
	return M3Default().Snapshot()
}

// ResetM3Stats 见 M3Stats.ResetM3Stats。
func ResetM3Stats() {
	M3Default().ResetM3Stats()
}

func atomicFloat64Bits(f float64) uint64 {
	return math.Float64bits(f)
}

func atomicFloat64FromBits(bits uint64) float64 {
	return math.Float64frombits(bits)
}
