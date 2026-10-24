# gameroute API 文档

**适用版本**：v2.13（2026-10 发布快照；诊断 dump 结构版本 `gameroute-diag/v2`）

gameroute 是 mihomo fork 内嵌的游戏 UDP 自动选路模块。本文档覆盖其全部对外接口面：HTTP API、config.yaml 配置节、运行时数据文件。

## 基础信息

- **Base URL**：`http://127.0.0.1:9090`（即 mihomo `external-controller`，改配置即变）
- **认证**：所有请求带 `Authorization: Bearer <secret>`，secret 取 `config.yaml` 的 `secret` 字段
- **前缀**：HTTP API 全部挂在 `/gameroute` 下
- **依赖**：gameroute 仅在 **TUN 模式**下可用；系统代理模式下开启会被拒绝（400）

---

## 一、HTTP API（/gameroute）

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/gameroute/status` | 总体状态快照（含 TUN 态、M3、当前主出口） |
| GET | `/gameroute/targets` | 已注册游戏目标列表 |
| PUT | `/gameroute/targets` | 增改目标 / 开关 gameroute 与 M3 |
| GET | `/gameroute/memory` | 自学习记忆内容 |
| DELETE | `/gameroute/memory` | 清空全部记忆 |
| DELETE | `/gameroute/memory/{ip}` | 忘记单个目标的记忆 |
| GET | `/gameroute/diag/events` | 诊断事件增量拉取（毫秒级因果链） |
| GET | `/gameroute/diag/metrics` | 扳机/闸门原子计数器快照 |
| GET | `/gameroute/diag/dump` | 一键冻结导出（事件+选路+会话，schema v2） |
| GET | `/gameroute/diag/miss` | 未命中明细（"为什么没被加速"） |

### GET /gameroute/status

返回字段：

- `enabled`：gameroute 总开关（TUN 关闭时必为 false）
- `tunnel_enabled`：内核 TUN 实际启用态（面板据此解释"系统代理模式不支持"）
- `targets`：目标 DTO 列表；`target_count`：条数
- `m3`：M3 预测式切换子对象（`enabled`/`switch_count`/`last_switch_at`/`current_proxy`/`loss_rate`）
- `primary`：当前主出口节点名
- `region_actual`：当前实际生效地区（节点名解析结果）
- `candidate_pool`：当前候选池（节点列表）
- `last_switch`：最近一次切换信息（from/to/region/reason/rtt）
- `switch_history`：切换历史（按时间序）
- `stats`：会话统计（managed_sessions / udp_packets 等）

响应样本（v0.1.0，无 TUN 空态，`Authorization: Bearer <secret>`）：

```json
{
  "enabled": false,
  "tunnel_enabled": false,
  "targets": [],
  "target_count": 0,
  "m3": {
    "enabled": false,
    "switch_count": 0,
    "last_switch_at": "0001-01-01T00:00:00Z",
    "current_proxy": "",
    "loss_rate": 0
  },
  "primary": null,
  "region_actual": null,
  "candidate_pool": [],
  "last_switch": null,
  "switch_history": [],
  "stats": {"udp_packets": 0, "managed_sessions": 0, "switch_count": 0}
}
```

空值形态注意（面板取类型时按此写，别按"空字符串"处理）：

| 字段 | 无值时形态 | 说明 |
|---|---|---|
| `primary` / `region_actual` | `null` | 指针类型，不是 `""` |
| `last_switch` | `null` | 从未切换过 |
| `candidate_pool` / `switch_history` / `targets` | `[]` | 切片类型，不是 `null` |
| `m3.last_switch_at` | `"0001-01-01T00:00:00Z"` | **Go time 零值，不是 `null` 也不是 `""`**，前端需自行判零 |
| `m3.current_proxy` | `""` | 字符串零值 |

### GET /gameroute/targets

返回 `{"targets": [gameLaneTarget, ...]}`。单条目标字段：

- `process_name`：进程名（识别即注册）
- `cidr`：CIDR 列表
- `proxy`：当前实际出口（auto 模式为实时主节点名）
- `fallback` / `fallbacks`：兜底节点列表
- `region`：目标地区（可选）
- `current_proxy` / `current_region` / `rtt` / `packets` / `last_seen`：运行态扩展字段

### PUT /gameroute/targets

请求体：

```json
{
  "enable": true,
  "enable_m3": true,
  "targets": [
    {"process_name": "game.exe", "proxy": "HK 01"},
    {"cidr": ["1.2.3.0/24"], "proxy": "TW 02", "fallbacks": ["TW 03", "HK 06"]}
  ]
}
```

- `enable` / `enable_m3` 可选：只传 `targets` 时仅更新目标列表
- 更新成功后自动 `RetargetUDP()`：已建立但未进 lane 的 UDP 会话会重建并重新匹配，补录目标立即生效
- 成功返回 204

**400 错误码语义**（四种来源，响应均为标准错误 JSON）：

| 触发条件 | 说明 |
|---|---|
| 请求体不是合法 JSON | `render.DecodeJSON` 解析失败 |
| `targets` 字段为 null | 请求体缺少 `targets` |
| 目标字段非法 | 非法 CIDR / 空 target（无 process_name 且无 cidr）→ 返回 `{"message":"Invalid gameroute target"}` |
| `enable=true` 但 TUN 未开 | 返回 `{"message":"GameRoute requires TUN mode: enable tun first, system-proxy mode is not supported"}` |

另注意：TUN 关闭时即使只更新 targets，也会强制保持/置为关闭。

### GET /gameroute/memory

返回 `{"entries": [...]}`，自学习记忆内容（目标 IP → 优选节点/region，重启后"第二次秒识别"依据）。

### DELETE /gameroute/memory

清空全部记忆。

### DELETE /gameroute/memory/{ip}

忘记单个目标记忆；目标不存在返回 404 `{"message":"no memory for ip"}`。

### GET /gameroute/diag/events

诊断事件增量拉取，全部参数可选：

| 参数 | 含义 |
|---|---|
| `since` | 只返回 `seq > since` 的事件（增量游标）；响应里的 `head` 即下一次的 `since` |
| `kinds` | 逗号分隔的 kind 白名单，如 `switch_done,recv_stall,temp_primary` |
| `limit` | 只保留最新 N 条（尾部截断） |

返回：`{"events": [...], "capacity": 2048, "used": n, "head": seq, "since": n, "dropped": n}`。

响应样本（v0.1.0 启动后首次拉取，`limit=40`）：

```json
{
  "events": [
    {"seq": 1, "at": 1792834030461, "kind": "config_update", "msg": "kind=enabled value=false targets=0"},
    {"seq": 2, "at": 1792834030461, "kind": "config_update", "msg": "kind=targets enabled=false targets=0"}
  ],
  "capacity": 2048,
  "used": 2,
  "head": 2,
  "since": 0,
  "dropped": 0
}
```

字段形态要点：

- `at` 是**毫秒级 Unix 时间戳（int64）**，不是 RFC3339 字符串——与 `status.m3.last_switch_at` 的 RFC3339 格式不同，两处别用同一个解析器。
- `msg` 是自由文本，**不保证结构化**：不同 kind 的 msg 前缀不同（如 `config_update` 为 `kind=... value=... targets=...`），需要程序化消费时请按 `kind` 分支，不要用 `msg` 正则解析。
- 增量拉取用法：拿上次响应的 `head` 作为下次的 `since`；`dropped > 0` 表示环已溢出、中间有事件丢失，此时应改拉 `/diag/dump` 全量。
- 冷启动即会写入 `config_update` 事件（2 条），因此 `used` 在无任何游戏流量时也不为 0。

事件示例 kind：`target_match`（命中接管）、`temp_primary`（选临时主节点）、`switch_done`（切换完成）、`recv_stall`（断流）、`domestic_direct`（国内直连跳过）、`holding`（无可用出口）。全部 kind 共 38 个，其余还包括：`reg_proc` / `reg_domain` / `reg_segment`（注册命中来源，带结构化 dst/port/note）、`probe_trigger`（赛马扳机命中）、`m3_action` / `m3_apply` / `m3_blocked`（M3 决策/应用/保护期拦截）、`degrade_blocked`（劣化切换被保护期拦截）、`probe_settled` / `probe_skipped` / `probe_switch` / `probe_bootstrap`（赛马探测生命周期）、`cand_probe_batch` / `cand_probe_node` / `cand_probe_settled` / `probe_batch` / `probe_node`（候选批量探测）、`best_race_stale_bad` / `best_race_stale_reuse`（赛马冠军过期）、`bad_mark` / `bad_dethrone` / `dethrone_no_switch`（劣化治理）、`birth_protected` / `session_locked` / `session_open` / `cooldown_arm` / `cooldown_skip`（门控）、`fakecn_observe` / `fakecn_override`（反悔接管）、`stun_refresh`、`config_update`、`recv_resume`。

注意：`m3_blocked` / `degrade_blocked` / `session_locked` 走 `logBlockedThrottled` 节流（同一会话 5 秒只记一条，session.go:276-285），"保护期拦截"类事件在事件环里天然稀疏，不是丢事件。

`temp_primary` 的 `reason` 枚举（排障按字符串匹配请用完整值）：

| reason | 含义 |
|---|---|
| `segment-lock` | /24 段锁命中（复用同段已锁定出口） |
| `memory-preferred` | 记忆条目直接指定出口（最高优先） |
| `memory-region-rtt` | 记忆区池内实测 RTT 最低 |
| `memory-region-no-measured` | 记忆区池无实测节点，下探 GeoIP 区选/第 5 档/退避链 |
| `geoip-rtt-lowest` | 服务器 GeoIP 亚洲信任区实测 RTT 最低 |
| `geoip-no-measured` | GeoIP 区池无实测节点，下探第 5 档/退避链 |
| `asia-low-latency` | GeoIP 区池为空或区内全无实测，退到亚洲池（HK/SG/TW）实测 RTT 最低 |
| `asia-no-measured` | 亚洲池同样无实测节点，下探第 5 档/退避链 |
| `urltest-lowest` | 第 5 档港台 urltest 兜底——三个条件**同时**成立才走：① race 表全无任何实测（≥1 条即被第 6 档 race 全局最低接棒）；② 玩家在亚洲或玩家定位未完成；③ 港台区实测 RTT 最低且 <80ms |
| `rtt-lowest` | 全局 RTT 最低（只认实测值 >0） |
| `best-race-winner` | 捕获式赛马冠军锁定 |
| `no-measured-node` | 全表无任何实测节点，defer=probe-first 先测再进（禁盲选） |

### GET /gameroute/diag/metrics

扳机分桶命中与闸门拦截计数器（全部单调累计，前端按两次采样差值算速率）。包含：识别命中分布（进程/段表/域名/流特征）、赛马扳机命中（0xffffffff / STUN / RakNet）、守卫拦截、注册拒绝原因分桶。

### GET /gameroute/diag/dump

一键冻结导出，`schema_version = "gameroute-diag/v2"`。一次拉全以下分组：

- **快照元信息**：`schema_version` / `exported_at` / `kernel_version` / `kernel_meta`（布尔，指示本次导出是否含内核元信息）/ `uptime_ms` / `proc_start_at`
- **事件流与计数**：`events`（单条：`seq` 序号 / `at` 毫秒时间戳 / `kind` 类型 / `msg` 消息）/ `capacity` / `used` / `head` / `dropped` / `seq_total` / `metrics`（顶层，扳机分桶计数器，完整键集合与 `/diag/metrics` 一致）
- **选路状态**：`enabled`（模块开关）/ `tunnel_enabled`（TUN 真实启用态——TUN 未开时 `enabled` 必为 false，区分「用户关闭模块」与「TUN 未开导致自动失效」）/ `primary` / `region_actual` / `last_switch`（**无切换时为 null**）/ `switch_history` / `stats`（`managed_sessions`/`switch_count`/`udp_packets`）/ `candidate_pool` / `probe_last_ok_at` / `targets` / `target_count` / `m3`
- **RTT 与熔断**：`rtt` / `rtt_table` / `bad_nodes`（150ms 触发 + 30min 惩罚）/ `cooldowns`（30s 切换冷却）/ `session_gates`（10s 有回包宽限）/ `segment_locks`（/24 锁死）/ `thresholds`（`switch_cooldown_ms`/`bad_node_penalty_ms`/`bad_node_rtt_penalty`/`birth_grace_ms`/`active_grace_ms`）
- **会话明细**：`sessions`（单条：`key`/`dst`/`dport`/`on_lane`/`active_proxy`/`recv_count`/`birth_grace`/`pending_retry`/`retry_at`；另有 `last_recv_at`/`last_recv_ago_ms`/`birth_at`/`age_ms`/`birth_remain_ms` 等 omitempty 字段，值非零时才出现——结构定义见 `tunnel/gamelane_diag.go` 的 `GameLaneSessionDetail`）+ `sessions_summary`（`managed`/`on_lane`/`off_lane`/`udp_packets`/`udp_total`）

典型用法：卡顿/高延迟复现后立刻拉 dump，按事件 Seq 对齐"识别→选路→劣化→切换→断流"因果链。

响应样本（v0.1.0，无 TUN 空态，34 个顶层键全量；数值均为空态的 0 值，形态与有流量时一致）：

```json
{
  "schema_version": "gameroute-diag/v2",
  "exported_at": 1792834033639,
  "kernel_version": "v0.1.0",
  "kernel_meta": true,
  "proc_start_at": 1792834030447,
  "uptime_ms": 3192,
  "enabled": false,
  "tunnel_enabled": false,
  "events": [
    {"seq": 1, "at": 1792834030461, "kind": "config_update", "msg": "kind=enabled value=false targets=0"},
    {"seq": 2, "at": 1792834030461, "kind": "config_update", "msg": "kind=targets enabled=false targets=0"}
  ],
  "capacity": 2048,
  "used": 2,
  "head": 2,
  "dropped": 0,
  "seq_total": 2,
  "metrics": {
    "proc_keyword_hit": 0, "proc_code_excluded": 0,
    "reg_segment_hit": 0, "reg_domain_hit": 0, "reg_proc_hit": 0,
    "reg_block_port": 0, "reg_block_fakeip": 0, "reg_block_excluded": 0,
    "reg_block_notgame": 0, "reg_block_unknown_pid": 0,
    "probe_magic_hit": 0, "probe_stun_hit": 0, "probe_raknet_hit": 0,
    "probe_guard_block": 0, "known_port_hit": 0, "match_server_port_hit": 0,
    "cloud_seg_hit": 0, "domain_table_hit": 0, "suffix_hit": 0,
    "memory_proc_validated": 0, "memory_loaded": 0, "memory_reload_skipped": 0,
    "observed_flow_total": 0, "registered_total": 0
  },
  "primary": null,
  "region_actual": null,
  "candidate_pool": [],
  "last_switch": null,
  "switch_history": [],
  "stats": {"udp_packets": 0, "managed_sessions": 0, "switch_count": 0},
  "m3": {
    "enabled": false, "switch_count": 0,
    "last_switch_at": "0001-01-01T00:00:00Z", "current_proxy": "", "loss_rate": 0
  },
  "targets": [],
  "target_count": 0,
  "probe_last_ok_at": 0,
  "rtt": {},
  "rtt_table": [],
  "bad_nodes": [],
  "cooldowns": [],
  "session_gates": [],
  "segment_locks": [],
  "thresholds": {
    "switch_cooldown_ms": 30000,
    "bad_node_penalty_ms": 1800000,
    "bad_node_rtt_penalty": 200,
    "birth_grace_ms": 30000,
    "active_grace_ms": 10000
  },
  "sessions": [],
  "sessions_summary": {"managed": 0, "on_lane": 0, "off_lane": 0, "udp_packets": 0, "udp_total": 0}
}
```

形态要点（比对样例与真实返回时先看这几处）：

- `probe_last_ok_at` 为 **0** 表示「本次进程生命周期内从未探测成功」，不是「1970 年」。
- `rtt` 是 **map**（`{}`），`rtt_table` 是**数组**（`[]`）——两者不是同一结构，别混用。
- `last_switch` / `primary` / `region_actual` 无值是 `null`；`thresholds` 五项**恒存在**，不随配置变化（值来自编译期常量）。
- `sessions[]` 内的 `last_recv_at` / `last_recv_ago_ms` / `birth_at` / `age_ms` / `birth_remain_ms` 带 omitempty，**值为 0 时键会整体消失**，解析时不要假定键一定存在。
- `kernel_meta` 为 false 时 `kernel_version` 可能缺失，此时 `schema_version` 仍应存在——判版本以 `schema_version` 为准。

### GET /gameroute/diag/miss

未命中聚合清单（"为什么没被加速"），TTL 惰性清理，只读。响应：

```json
{"capacity": 256, "ttl_sec": 600, "total": 3,
 "observed_total": 0, "registered_total": 0,
 "entries": [ {"process_path": "...", "exe_name": "cs2.exe",
   "hit_count": 42, "first_seen": 0, "last_seen": 0,
   "reasons": {"reg_block_port": 40, "reg_block_notgame": 2},
   "sample_dsts": ["1.2.3.4:27015"], "priority": 5} ]}
```

字段说明：

- `capacity` 环形容量 / `ttl_sec` 惰性清理秒数 / `total` 当前条目数
- `capacity` 与 `ttl_sec` 为**编译期常量，不随配置变化**：`MissTableCapacity = 256`（`component/gamelane/miss.go:37`）、`MissTTLSec = 600`（同文件 `:39`，对应 `missTTL = 10 * time.Minute`）。拉到的响应里这两个值恒为 256 / 600，可用来校验内核版本是否为预期构建。
- `observed_total` / `registered_total`：观测流总数 / 已注册目标总数
- 每条 `entries[]`：`process_path`（进程完整路径，用户名已脱敏）/ `exe_name`（进程名——**用进程名识别是哪个游戏**）/ `hit_count`（聚合次数）/ `first_seen` / `last_seen` / `reasons`（拒绝原因 → 计数，如 `reg_block_port` 端口被排除表挡、`reg_block_notgame` 判定非游戏、`reg_block_excluded` 排除层、`reg_block_fakeip`、`reg_block_unknown_pid`）/ `sample_dsts`（最多 5 个 `ip:port` 目标样本——**适配时拿服务器地址**）/ `checked_dir` / `dir_files`（嗅探目录与 DLL 采样）/ `priority` / `flow_score` / `flow_threshold`（流特征未达标时的分数与阈值）

---

## 二、config.yaml 配置节

```yaml
gameroute:
  enable: true                 # 必填；缺省 false 整个模块不启用
  targets:
    - process-name: game.exe   # 进程名命中（优先）或 cidr 命中，二者至少一个
      # cidr: ["1.2.3.0/24"]
      proxy: "HK 01"           # 指定出口；留空或写 auto = 自动圈选
      fallback: "TW 02"        # 可选，单兜底
      fallbacks: ["TW 02", "SG 01"]  # 可选，多兜底
```

- **字段名注意**：配置节用 kebab-case `process-name`（`config.go` 的 yaml tag），**不是** HTTP API 里的 `process_name`（JSON tag）——两套 tag 不同，写错会被静默忽略
- `enable: true` 必须显式写：缺省 false 时整模块不启用（TUN 关闭时也会被强制置 false）
- 配置节**没有** `region` 字段：region 只存在于 HTTP API 的目标 DTO（`GET/PUT /gameroute/targets`），把 API 字段当配置字段写是无效的
- 进程名与 CIDR 命中其一即生效（进程名优先）
- `proxy` 留空时进入 Auto-Pick Primary：内核自动构建候选池、探测、选路（推荐）
- **`proxy` / `fallback` / `fallbacks` 必须是当前配置中已存在的节点名**：proxy 名字不存在时该条目标整体跳过，兜底名字不存在时该兜底被丢弃（日志 `[GameRoute] proxy xxx not found, skip target` / 兜底同源校验），配错名字表现为"配了但没生效，除该条 warn 日志外无其他提示"
- 未配置任何目标时 gameroute 以零配置运行：免词表自动识别仍生效（进程关键词 / UDP 流特征 / 内置段表 / 域名树）

## 三、运行时数据文件

gameroute 会在 HomeDir（`-d` 指定目录，或 `runtime/` 部署形态）下自动读写以下文件，**全部免重新编译**；注意表中标注"需重启"的文件是进程内一次性加载：

| 文件 | 说明 |
|---|---|
| `game_udp_sysports.json` | 系统服务 UDP 端口排除表。内置兜底 7 条（53/123/443/1900/5353/8081/8125，**不含 3478**）；文件存在则合并。**查找顺序三路**：`<HomeDir>/` → `<HomeDir>/runtime/` → `<exe>/../runtime/`（覆盖面板 `-d runtime` 与常规部署两种形态），重启生效 |
| `game_probe_templates.json` | v2.13 预热测速模板（首次捕获测速包自动学习落盘，重启复用，不重复观察） |
| `fakecn_override.json` | 反悔接管持久标记（大陆路由表漏判又被证实为海外对局服的 IP 记录，跨重启有效） |
| `game_lane_state.json` | 每个游戏目标上一次有效出口（退避链"上一出口"来源，重启恢复） |
| `china_ip.txt` | 大陆 IPv4 路由表运行时覆盖（存在且解析出 ≥100 条有效 CIDR 时整体替换内置表；内置 chnroutes 为编译期 embed 兜底）。**需重启生效**（sync.Once 进程内一次性加载）；**仅前两路查找**：`<HomeDir>/` → `<HomeDir>/runtime/`，无 `<exe>/../runtime/` 兜底 |
| `game_segments.json` | 游戏服务器段表缓存（启动异步拉取 blackmatrix7/MetaCubeX 规则集失败时的兜底） |
| `game_memory.json` | 自学习记忆持久化（目标 IP → 优选节点/region，相对 HomeDir，自动读写无需干预） |

## 运行时常量（固定值，非配置项）

以下数值**编译期写死**，不参与配置；排障时对照理解行为（如"为什么流没了/为什么记忆没了/赛马为什么等 3 秒"）：

| 常量 | 值 | 含义 | 定义处 |
|---|---|---|---|
| `memActiveTTLMs` | 24h | 记忆 active 状态 24 小时未命中 → 降级 decay | memory.go:33 |
| `memDecayTTLMs` | 72h | 记忆 decay 状态 72 小时未命中 → 删除 | memory.go:34 |
| `memFlowSessionMs` | 5min | 判定"不同游戏会话"的最小间隔（流命中计数的会话切分） | memory.go:39 |
| `watchCleanAfterMs` | 3min | 无进程名来源目标：3 分钟无对局特征流量 → 自动清理 | watch.go:26 |
| `watchDeadAfterMs` | 3min | 双向流量均停止超 3 分钟 → 视为会话死亡，移除注册 | watch.go:29 |
| `raceTimeoutMs` | 3s | 捕获式赛马旁路探测超时（3 秒无回包判该候选失败） | race.go:23 |
| `fakeCNWindowMs` | 3s | 反悔接管观察窗最短时长（覆盖 2s 静默判据） | fakecn.go:39 |
| `flowObserveMaxIdleMs` | 15s | 流观察条目空闲超 15 秒 → 视为流结束并清理 | flow.go:27 |
| `flowMaxEntries` | 10000 | 流观察表条目上限，超出按空闲时间清理防内存膨胀 | flow.go:34 |

## 排障速查

1. `GET /gameroute/diag/dump` 一键拉全现场；
2. 未命中 → `GET /gameroute/diag/miss` 看细分原因；
3. 命中但慢 → `GET /gameroute/diag/events?kinds=switch_done,recv_stall` 看是否劣化切换/断流；
4. 扳机异常（如 STUN 命中暴涨）→ `GET /gameroute/diag/metrics` 看分桶计数。
