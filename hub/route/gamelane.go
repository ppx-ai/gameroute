package route

import (
	"net/netip"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/mihomo/component/gamelane"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// gameLaneTarget 是 /gameroute 对外暴露的目标 DTO：
// process_name 与 cidr 至少填一个，proxy 必填；fallback 可选（M3 备用出口，
// fallbacks 为候选池列表，fallback 单值兼容读取/输出）。
type gameLaneTarget struct {
	ProcessName string   `json:"process_name,omitempty"`
	CIDR        []string `json:"cidr,omitempty"`
	Proxy       string   `json:"proxy"`
	Fallback    string   `json:"fallback,omitempty"`
	Fallbacks   []string `json:"fallbacks,omitempty"`

	// 扩展字段：region/current_proxy/current_region/rtt/packets/last_seen
	Region        string  `json:"region,omitempty"`
	CurrentProxy  *string `json:"current_proxy,omitempty"`
	CurrentRegion *string `json:"current_region,omitempty"`
	RTT           *int    `json:"rtt,omitempty"`
	Packets       int     `json:"packets"`
	LastSeen      *string `json:"last_seen,omitempty"`
}

// putGameLaneTargetsBody 是 PUT /gameroute/targets 的请求体：
// enable 可选（缺省保持当前开关状态），enable_m3 可选（M3 子开关，缺省保持），
// targets 必填（整体替换，空数组即清空）。
type putGameLaneTargetsBody struct {
	Enable   *bool            `json:"enable,omitempty"`
	EnableM3 *bool            `json:"enable_m3,omitempty"`
	Targets  []gameLaneTarget `json:"targets"`
}

func gameLaneRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/status", getGameLaneStatus)
	r.Get("/targets", getGameLaneTargets)
	r.Put("/targets", putGameLaneTargets)
	r.Get("/memory", getGameLaneMemory)
	r.Delete("/memory", clearGameLaneMemory)
	r.Delete("/memory/{ip}", forgetGameLaneMemory)
	r.Get("/diag/events", getGameLaneDiagEvents)
	r.Get("/diag/metrics", getGameLaneDiagMetrics)
	r.Get("/diag/dump", getGameLaneDiagDump)
	r.Get("/diag/miss", getGameLaneDiagMiss)
	return r
}

// getGameLaneDiagMiss 未命中聚合清单（GET /gameroute/diag/miss）：
// 返回"被拒绝注册的进程流量"聚合明细（谁、原因、目标样本、目录 DLL 采样），
// 供发布后 curl 直接定位"某游戏为什么没被加速"。
// 只读端点：TTL 惰性清理发生在本次快照构建时，无其它副作用。
func getGameLaneDiagMiss(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, gamelane.MissSnapshot())
}

// getGameLaneDiagEvents 增量拉取诊断事件（GET /gameroute/diag/events）：
// 返回按时间升序的环形缓冲事件 + 容量 + 已用数 + 最新序号，供诊断工具/面板
// 秒级对齐会话级时间线。
//
// v2.10 P1 查询参数（全部可选）：
//   - since：只返回 seq > since 的事件（增量游标，响应里的 head 即新游标）；
//   - kinds：逗号分隔的 kind 白名单（如 switch_done,recv_stall）；
//   - limit：只保留最新 N 条（尾部截断）。
func getGameLaneDiagEvents(w http.ResponseWriter, r *http.Request) {
	since := uint64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			since = n
		}
	}
	kinds := r.URL.Query().Get("kinds")
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events, capacity, used, head, dropped := gamelane.DiagEventsSince(since, kinds, limit)
	render.JSON(w, r, render.M{
		"events":   events,
		"capacity": capacity,
		"used":     used,
		"head":     head,
		"since":    since,
		"dropped":  dropped,
	})
}

// getGameLaneDiagMetrics 计数器快照（GET /gameroute/diag/metrics）：
// v2.9 扩容名单/端口/段/魔数/后缀的命中分布与各道闸门的拦截次数，
// 全部为单调累计值，前端按两次采样差值算速率。
func getGameLaneDiagMetrics(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, gamelane.DiagMetricsSnapshot())
}

// gameLaneDiagSchemaVersion 诊断快照结构版本：字段增删必须递增，
// 面板/外部工具据此判断可读字段集合（v2 = 2026-10-19 补全 RTT/丢事件/
// 熔断/冷却/保护期/会话明细/快照元信息）。
const gameLaneDiagSchemaVersion = "gameroute-diag/v2"

// getGameLaneDiagDump 一键冻结导出诊断现场（GET /gameroute/diag/dump）：
// 事件时间线 + 当前主出口/region 快照 + 切换历史 + 会话统计，一次拉全，
// 无需拼多个接口。v2 起额外包含 RTT 表、事件丢弃量、熔断/冷却/保护期、
// 会话明细、targets/m3 与快照元信息。
func getGameLaneDiagDump(w http.ResponseWriter, r *http.Request) {
	m := gamelane.Default()
	events, capacity := gamelane.DiagSnapshot()
	managed, udp := tunnel.GameLaneSessionStats()
	st := m.Status(managed, udp)
	state := m.DiagStateSnapshot()
	sessions := tunnel.GameLaneSessionDetails()
	onLane := 0
	for _, s := range sessions {
		if s.OnLane {
			onLane++
		}
	}

	// 既有字段（events/capacity/used/head/metrics/primary/region_actual/
	// last_switch/switch_history/stats）原样保留，只做追加，保证旧消费者
	// 与历史快照对比不受影响；新增字段全部为只读快照派生物。
	render.JSON(w, r, render.M{
		// ---- 快照元信息（v2 新增）----
		"schema_version": gameLaneDiagSchemaVersion,
		"exported_at":    time.Now().UnixMilli(),
		"kernel_version": C.Version,
		"kernel_meta":    C.Meta,
		"uptime_ms":      state.UptimeMs,
		"proc_start_at":  state.ProcStartAt,

		// ---- 事件流（既有）----
		"events":   events,
		"capacity": capacity,
		"used":     gamelane.DiagRingUsed(),
		"head":     gamelane.DiagHeadSeq(),
		"metrics":  gamelane.DiagMetricsSnapshot(),

		// ---- 事件流补全（v2 新增）----
		"dropped":   gamelane.DiagDroppedTotal(),
		"seq_total": gamelane.DiagSeqTotal(),

		// ---- 选路状态（既有）----
		"primary":        st.Primary,
		"region_actual":  st.RegionActual,
		"last_switch":    st.LastSwitch,
		"switch_history": st.SwitchHistory,
		"stats":          st.Stats,

		// ---- 选路状态补全（v2 新增）----
		"enabled": st.Enabled,
		// tunnel_enabled 报告内核 TUN 实际启用态：GameLane 只在 TUN 模式下可用，
		// 关闭 TUN 后 enabled 必为 false，dump 排查时可区分「用户关闭模块」与「TUN 未开导致自动失效」。
		"tunnel_enabled":   listener.IsTunEnabled(),
		"m3":               gamelane.GetM3Snapshot(),
		"targets":          toGameLaneTargetDTOs(m.GetTargets()),
		"target_count":     st.Targets,
		"candidate_pool":   st.CandidatePool,
		"probe_last_ok_at": st.ProbeLastOKAt,

		// ---- RTT / 熔断 / 冷却 / 保护期（v2 新增）----
		"rtt":           m.SnapshotRTT(),
		"rtt_table":     state.RTTTable,
		"bad_nodes":     state.BadNodes,
		"cooldowns":     state.Cooldowns,
		"session_gates": state.SessionGates,
		"segment_locks": state.SegmentLocks,
		"thresholds": render.M{
			"switch_cooldown_ms":   state.SwitchCooldownMs,
			"birth_grace_ms":       state.BirthGraceMs,
			"active_grace_ms":      state.ActiveGraceMs,
			"bad_node_penalty_ms":  state.BadNodePenaltyMs,
			"bad_node_rtt_penalty": state.BadNodeRttPenalty,
		},

		// ---- 会话明细（v2 新增）----
		"sessions": sessions,
		"sessions_summary": render.M{
			"udp_total":   len(sessions),
			"on_lane":     onLane,
			"off_lane":    len(sessions) - onLane,
			"managed":     managed,
			"udp_packets": udp,
		},
	})
}

func getGameLaneStatus(w http.ResponseWriter, r *http.Request) {
	m := gamelane.Default()
	// 旧字段（enabled/targets/m3）原样输出，面板轮询兼容；
	// 新字段（primary/region_actual/candidate_pool/last_switch/stats）
	// 从现有内存结构锁内快照读取，target_count 为 targets 数组长度。
	managed, udp := tunnel.GameLaneSessionStats()
	st := m.Status(managed, udp)
	render.JSON(w, r, render.M{
		"enabled": st.Enabled,
		// tunnel_enabled 报告内核 TUN 实际启用态：GameLane 只在 TUN 模式下可用，
		// 关闭 TUN 后 enabled 必为 false，面板据此解释「系统代理模式已自动关闭」。
		"tunnel_enabled": listener.IsTunEnabled(),
		"targets":        toGameLaneTargetDTOs(m.GetTargets()),
		"target_count":   st.Targets,
		"m3":             gamelane.GetM3Snapshot(),
		"primary":        st.Primary,
		"region_actual":  st.RegionActual,
		"candidate_pool": st.CandidatePool,
		"last_switch":    st.LastSwitch,
		"switch_history": st.SwitchHistory,
		"stats":          st.Stats,
	})
}

func getGameLaneTargets(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{
		"targets": toGameLaneTargetDTOs(gamelane.Default().GetTargets()),
	})
}

func putGameLaneTargets(w http.ResponseWriter, r *http.Request) {
	var body putGameLaneTargetsBody
	if err := render.DecodeJSON(r.Body, &body); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if body.Targets == nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	targets, err := fromGameLaneTargetDTOs(body.Targets)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	m := gamelane.Default()
	// TUN 门控（内核本体硬约束）：GameLane 依赖 TUN 接管游戏 TCP/UDP 归属，
	// 系统代理模式下无全局流量入口，一律拒绝开启并强制保持关闭。
	tunOn := listener.IsTunEnabled()
	if body.Enable != nil && *body.Enable && !tunOn {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, render.M{
			"message": "GameRoute requires TUN mode: enable tun first, system-proxy mode is not supported",
		})
		return
	}
	if body.Enable != nil {
		m.SetEnabled(*body.Enable && tunOn)
	} else if !tunOn && m.Enabled() {
		// 仅更新 targets/m3 时也要保证 TUN 关闭态下不会残留开启
		m.SetEnabled(false)
	}
	if body.EnableM3 != nil {
		gamelane.SetM3Enabled(*body.EnableM3 && tunOn)
	}
	m.SetTargets(targets)
	// targets 更新后重评估已建立的 UDP 会话：命中新目标但首包未进 lane 的
	// 会话将被重建并重新匹配，使补录的对局服务器目标立即进入快速通道。
	tunnel.RetargetUDP()
	render.NoContent(w, r)
}

// toGameLaneTargetDTOs 将内部 Target 转换为对外 DTO（CIDR 前缀转字符串，含扩展字段）。
func toGameLaneTargetDTOs(targets []gamelane.Target) []gameLaneTarget {
	if len(targets) == 0 {
		return []gameLaneTarget{}
	}
	dtos := make([]gameLaneTarget, 0, len(targets))
	for _, t := range targets {
		cidr := make([]string, 0, len(t.CIDR))
		for _, p := range t.CIDR {
			cidr = append(cidr, p.String())
		}
		dto := gameLaneTarget{
			ProcessName: t.ProcessName,
			CIDR:        cidr,
			Proxy:       t.EffectiveProxy(), // autoPrimary 模式输出当前实际主节点名（DIRECT 为空串）
			Fallback:    firstFallback(t.Fallbacks),
			Fallbacks:   t.Fallbacks,
		}
		// 扩展字段
		if t.Region != "" {
			dto.Region = t.Region
		}
		if t.CurrentProxy != "" {
			cp := t.CurrentProxy
			dto.CurrentProxy = &cp
		}
		if t.CurrentRegion != "" {
			cr := t.CurrentRegion
			dto.CurrentRegion = &cr
		}
		if t.RTT > 0 {
			rt := t.RTT
			dto.RTT = &rt
		}
		dto.Packets = t.Packets
		if t.LastSeen != nil {
			ls := t.LastSeen.Format(time.RFC3339)
			dto.LastSeen = &ls
		}
		dtos = append(dtos, dto)
	}
	return dtos
}

// fromGameLaneTargetDTOs 校验并转换 DTO 为内部 Target。
// 规则：proxy 必填；process_name 与 cidr 至少提供一个；cidr 必须可解析。
func fromGameLaneTargetDTOs(dtos []gameLaneTarget) ([]gamelane.Target, error) {
	targets := make([]gamelane.Target, 0, len(dtos))
	for _, d := range dtos {
		// 红线：游戏加速禁止直连——DIRECT 目标接收即丢弃（双层保险之二）
		if d.Proxy == "DIRECT" {
			continue
		}
		if d.Proxy == "" {
			// auto 目标：Proxy 为空字符串 → 表示 auto 模式（临时主节点进场 + M3 预测式切换）
			// DIRECT 仅在所有代理不可达时作为最终兜底
		}
		if d.ProcessName == "" && len(d.CIDR) == 0 {
			return nil, errGameLaneInvalid
		}
		t := gamelane.Target{
			ProcessName: d.ProcessName,
			Proxy:       d.Proxy,
			Region:      d.Region,
		}
		seen := make(map[string]bool, len(d.Fallbacks)+1)
		add := func(name string) {
			if name == "" || seen[name] {
				return
			}
			seen[name] = true
			t.Fallbacks = append(t.Fallbacks, name)
		}
		add(d.Fallback)
		for _, fb := range d.Fallbacks {
			add(fb)
		}
		for _, c := range d.CIDR {
			prefix, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, errGameLaneInvalid
			}
			t.CIDR = append(t.CIDR, prefix)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

var errGameLaneInvalid = &HTTPError{Message: "Invalid gameroute target"}

// firstFallback 返回候选池首个元素，空池返回空串（兼容旧单 fallback 输出）。
func firstFallback(fallbacks []string) string {
	if len(fallbacks) == 0 {
		return ""
	}
	return fallbacks[0]
}

// getGameLaneMemory 返回自学习记忆快照（GET /gameroute/memory）。
func getGameLaneMemory(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{
		"entries": gamelane.Default().MemorySnapshot(),
	})
}

// clearGameLaneMemory 清空全部自学习记忆并删除记忆文件（DELETE /gameroute/memory）。
func clearGameLaneMemory(w http.ResponseWriter, r *http.Request) {
	gamelane.Default().ClearMemory()
	render.NoContent(w, r)
}

// forgetGameLaneMemory 删除指定 IP 的自学习记忆（DELETE /gameroute/memory/{ip}）。
func forgetGameLaneMemory(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if !gamelane.Default().ForgetMemoryIP(ip) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, render.M{"message": "no memory for ip"})
		return
	}
	render.NoContent(w, r)
}
