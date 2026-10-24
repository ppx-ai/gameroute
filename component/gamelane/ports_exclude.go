package gamelane

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/log"
)

// 系统服务 UDP 端口排除表（v2.12 清单3，2026-10-22）。
//
// 原实现把排除端口写死在 skipAutoRegPorts 里，且把 3478(STUN) 也排除了——
// 但 Epic/多数对局服务器的对局端口本身就在 3478，排除它等于把整场对局挡在
// GameLane 之外。本改造把"系统服务端口"外置为 JSON 数据文件：
//   - 内置兜底仅 7 条（53/123/443/1900/5353/8081/8125），**不含 3478**；
//   - runtime/game_udp_sysports.json 存在则解析并合并（用户可自行增删，
//     重启内核生效，无需重新编译）；
//   - 文件缺失/解析失败 → 静默按兜底 7 条运行（降级不阻断启动）。
//
// 数据由 IANA Service Name and Transport Protocol Port Number Registry 的
// UDP 记录筛选生成（仅保留确定无游戏使用的标准系统服务端口），生成脚本与
// 数据说明随部署包附在 runtime/game_udp_sysports.json 内（source/license 字段）。
const udpSysPortsFileName = "game_udp_sysports.json"

// udpSysPortsFile JSON 结构（version/updated/source/license 字段仅供审计，
// 解析时忽略；ports 为 "port" 整数数组或带 service/description 的对象数组）。
type udpSysPortsFile struct {
	Version string           `json:"version"`
	Updated string           `json:"updated"`
	Source  string           `json:"source"`
	License string           `json:"license"`
	Note    string           `json:"note"`
	Ports   []udpSysPortItem `json:"ports"`
}

type udpSysPortItem struct {
	Port        int    `json:"port"`
	Service     string `json:"service"`
	Description string `json:"description"`
}

// udpSysPortsResolve 解析端口表文件路径：优先 HomeDir 根（面板以 -d runtime
// 启动时 runtime 目录即 HomeDir），再试 HomeDir/runtime/，最后试可执行文件
// 同级 ../runtime/——三种部署形态都能命中，且不改变现有 game_segments.json
// 的路径语义。
func udpSysPortsResolve(candidates ...string) string {
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// LoadUDPExcludePorts 读取并合并系统服务 UDP 端口排除表。
// 返回合并成功的端口数（含文件内全部合法端口）；文件不可用返回 0 且不改表。
// 仅允许 1..65535 的端口；非法条目跳过。3478 即使出现在文件里也忽略
// （零冲突清单：对局端口，绝不可排除）。
func LoadUDPExcludePorts(path string) int {
	if path == "" {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Infoln("[GameRoute] udp sys ports skip (%v), use builtin 7 ports", err)
		return 0
	}
	var f udpSysPortsFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Warnln("[GameRoute] udp sys ports parse failed (%v), use builtin 7 ports", err)
		return 0
	}
	added := 0
	for _, it := range f.Ports {
		if it.Port <= 0 || it.Port > 65535 {
			continue
		}
		if it.Port == stunPort3478 {
			log.Warnln("[GameRoute] refuse to exclude 3478 (game port), ignored from %s", filepath.Base(path))
			continue
		}
		port := uint16(it.Port)
		skipPortsMu.Lock()
		skipAutoRegPorts[port] = true
		skipPortsMu.Unlock()
		added++
	}
	log.Infoln("[GameRoute] udp sys ports merged: %d from %s", added, filepath.Base(path))
	return added
}

// LoadUDPExcludePortsAuto 按部署形态自动定位端口表并合并：依次尝试
// <home>/game_udp_sysports.json、<home>/runtime/game_udp_sysports.json、
// <exe>/../runtime/game_udp_sysports.json。找不到则保持兜底 7 端口。
func LoadUDPExcludePortsAuto(homeDir string) int {
	cands := make([]string, 0, 3)
	if homeDir != "" {
		cands = append(cands,
			filepath.Join(homeDir, udpSysPortsFileName),
			filepath.Join(homeDir, "runtime", udpSysPortsFileName),
		)
	}
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(filepath.Dir(exe)), "runtime", udpSysPortsFileName))
	}
	p := udpSysPortsResolve(cands...)
	if p == "" {
		log.Infoln("[GameRoute] udp sys ports file not found, use builtin 7 ports")
		return 0
	}
	return LoadUDPExcludePorts(p)
}

// LoadChinaMainlandTableAuto 按部署形态自动定位大陆路由表覆盖文件。
// 依次尝试 <home>/china_ip.txt、<home>/runtime/china_ip.txt。
func LoadChinaMainlandTableAuto(homeDir string) {
	cands := make([]string, 0, 2)
	if homeDir != "" {
		cands = append(cands,
			filepath.Join(homeDir, chinaIPRuntimeFile),
			filepath.Join(homeDir, "runtime", chinaIPRuntimeFile),
		)
	}
	p := udpSysPortsResolve(cands...)
	if p == "" {
		log.Infoln("[GameRoute] china ip override not present, use embedded chnroutes")
		return
	}
	LoadChinaMainlandTable(p)
}

// stunPort3478 对局端口红线（Epic/多数 FPS 对局服务器使用），任何来源
// 都不得把 3478 加入排除表。
const stunPort3478 = 3478
