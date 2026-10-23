package gamelane

import (
	_ "embed"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/mihomo/log"
)

// 大陆 IPv4 路由表（v2.12 清单4，2026-10-22）。
//
// 判定语义：目标 IP 属"中国大陆 IPv4 路由表"且未命中已知游戏段表 → GameLane
// 不接管（直连放行）。替代 v2.11 的 GeoIP(MMDB) 方案，理由：
//   - MMDB 是外部数据文件，云电脑部署包常缺、版本漂移，缺数据时 ONLY 能
//     保守退化（把国内目标也接管）→ 国内对局被绕出国再回国（高延迟/丢包）；
//   - 路由表可编译进二进制（go:embed），开箱即用、零外部依赖、可审计。
//
// 数据来源：chnroutes2（Sukka 优化版）https://chnroutes2.cdn.skk.moe/chnroutes.txt
// 上游：Misaka Network, Inc.；许可：CC BY-SA 2.0 + MIT（见 data/CHNRoutes-NOTICE.txt）。
// 数据仅含 IP-CIDR 文本，不含任何游戏名词条（红线：不得硬编码单个游戏名词）。
//
// 运行时覆盖：runtime/china_ip.txt 若存在且解析出 ≥100 条有效 IPv4 CIDR，
// 则整体替换内置表（用户/运维可自行更新路由数据，无需重新编译）。
const (
	chinaIPDataDir       = "data"
	chinaIPRuntimeFile   = "china_ip.txt"
	chinaIPMinValidCIDRs = 100
)

//go:embed data/chnroutes_china_ip.txt
var chinaIPEmbedded string

// chinaMainlandFn 判定入口的可替换实现（测试注入用；生产始终指向内置表）。
// 单独抽成变量是为了让单测能构造"命中/不命中"两种世界，而不必依赖真实
// 路由数据的具体网段（数据每次更新都会变，用例不得硬编码公网 IP）。
var chinaMainlandFn = defaultChinaMainlandMatch

// isChinaMainlandIP 目标 IP 是否属中国大陆路由表。
// 只认 IPv4（GameLane 目标注册本身也只接受 IPv4）；非法/非 v4 地址返回 false
// （保守：不直连，走原接管路径）。
func isChinaMainlandIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	if chinaMainlandFn == nil {
		return false
	}
	return chinaMainlandFn(addr)
}

// defaultChinaMainlandMatch 内置/运行时覆盖表的前缀树匹配。
func defaultChinaMainlandMatch(addr netip.Addr) bool {
	t := chinaIPTable()
	if t == nil || t.count == 0 {
		return false
	}
	return t.trie.IsContainForString(addr.String())
}

// chinaIPTableData 路由表快照（启动构建一次，运行期只读）。
type chinaIPTableData struct {
	trie   *trie.IpCidrTrie
	count  int
	source string
}

var (
	chinaIPOnce sync.Once
	chinaIPMu   sync.RWMutex
	chinaIPNow  *chinaIPTableData
)

func chinaIPTable() *chinaIPTableData {
	chinaIPOnce.Do(func() {
		chinaIPMu.Lock()
		chinaIPNow = buildChinaIPTable(chinaIPEmbedded, "embedded chnroutes2")
		chinaIPMu.Unlock()
	})
	chinaIPMu.RLock()
	defer chinaIPMu.RUnlock()
	return chinaIPNow
}

// buildChinaIPTable 把 CIDR 文本解析为前缀树；返回 nil 表示数据不可用。
func buildChinaIPTable(text, source string) *chinaIPTableData {
	t := trie.NewIpCidrTrie()
	count := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 只接受 IPv4 CIDR：chnroutes2 为纯 IPv4；含 ':' 的 IPv6 行跳过。
		if strings.Contains(line, ":") {
			continue
		}
		if err := t.AddIpCidrForString(line); err != nil {
			continue
		}
		count++
	}
	if count == 0 {
		log.Warnln("[GameLane] china IP table empty, source=%s", source)
		return nil
	}
	log.Infoln("[GameLane] china IP table ready: cidr=%d source=%s", count, source)
	return &chinaIPTableData{trie: t, count: count, source: source}
}

// LoadChinaMainlandTable 用运行时文件整体替换内置大陆路由表（可选）。
// 文件不存在 / 不可解析 / 有效条目过少时静默保留内置表——宁可继续用
// 编译期数据，也不允许被一个残缺文件打回"全量接管"或"全量直连"。
// 由 config 初始化阶段调用（此时尚无流量，替换无并发风险）。
func LoadChinaMainlandTable(path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Infoln("[GameLane] china ip override skip: %v", err)
		return
	}
	nt := buildChinaIPTable(string(data), path)
	if nt == nil || nt.count < chinaIPMinValidCIDRs {
		log.Warnln("[GameLane] china ip override rejected (count< %d), keep embedded table", chinaIPMinValidCIDRs)
		return
	}
	chinaIPOnce.Do(func() {}) // 标记 once 已消费，避免后续又被内置表初始化覆盖
	chinaIPMu.Lock()
	chinaIPNow = nt
	chinaIPMu.Unlock()
	log.Infoln("[GameLane] china ip override applied: cidr=%d file=%s", nt.count, filepath.Base(path))
}

// ChinaIPTableStats 返回当前大陆路由表条目数与来源（供 /game-lane 状态/诊断输出）。
func ChinaIPTableStats() (int, string) {
	t := chinaIPTable()
	if t == nil {
		return 0, "unavailable"
	}
	return t.count, t.source
}
