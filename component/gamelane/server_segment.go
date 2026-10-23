package gamelane

// 内置游戏服务器段表（开箱即用、零配置）：
//   - 数据源：blackmatrix7 Game_No_Resolve.yaml（主）与 MetaCubeX
//     category-games.yaml（备），均为 Clash 规则集（payload 列表）；
//   - 启动时后台异步拉取并解析为 IP-CIDR 前缀树 + 游戏域名后缀集，
//     常驻内存，匹配复用 mihomo 现有 trie 前缀树（radix tree），
//     禁止顺序遍历，单包匹配开销微秒级；
//   - 本地缓存 game_segments.json（相对 HomeDir），失败用缓存不阻塞。
//
// 全程不新增 config.yaml 字段、不要求用户导入规则或面板操作。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/trie"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	rulesCommon "github.com/metacubex/mihomo/rules/common"

	"go.yaml.in/yaml/v3"
)

// 段表数据源与缓存常量。
const (
	gameSegmentPrimaryURL  = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Game/Game_No_Resolve.yaml"
	gameSegmentFallbackURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-games.yaml"
	gameSegmentCacheName   = "game_segments.json" // 相对 HomeDir，与 game_memory.json 同目录
	gameSegmentRefreshSecs = 86400                // 默认每天拉取一次（interval 86400s）
	gameSegmentFetchTO     = 90 * time.Second     // 单次拉取超时
	gameSegmentCacheVer    = "1"
)

// segmentCacheFile 本地缓存文件结构（runtime/game_segments.json）。
type segmentCacheFile struct {
	Version string   `json:"version"`
	Updated string   `json:"updated"` // RFC3339
	Source  string   `json:"source"`
	CIDRs   []string `json:"cidrs"`
	Domains []string `json:"domains"`
}

// GameServerSegmentTable 游戏服务器段表：
// IP-CIDR 用 trie.IpCidrTrie（前缀树），游戏域名后缀用 trie.DomainSet
// （后缀树），均天然前缀匹配，查询 O(位数)/O(标签数)，微秒级。
type GameServerSegmentTable struct {
	mu          sync.RWMutex
	cidrTrie    *trie.IpCidrTrie
	domainSet   *trie.DomainSet
	cidrCount   int
	domainCount int
	updated     time.Time
	source      string
}

var defaultSegments = &GameServerSegmentTable{}

// SegmentTable 返回全局段表单例（零配置内置，启动即用）。
func SegmentTable() *GameServerSegmentTable {
	return defaultSegments
}

// MatchIP 判断 IP 是否命中已知游戏服务器段表（IP-CIDR 前缀树匹配）。
// F11：除远端规则集外，同时匹配内置游戏段（gameBuiltInCIDRs，原为死代码
// 现接入）与云厂商游戏段（cloudGameSegments）；命中即可注册，但区判定
// 是否可信需另查 RegionTrustedFor（云段一律不可信，红线 2）。
func (s *GameServerSegmentTable) MatchIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if isCloudSegmentIP(ip) {
		return true // 云段：已知游戏部署（区判定见 RegionTrustedFor）
	}
	s.mu.RLock()
	trieHit := false
	if s.cidrTrie != nil {
		trieHit = s.cidrTrie.IsContainForString(ip.String())
	}
	s.mu.RUnlock()
	if trieHit {
		return true
	}
	a := ip.Unmap()
	if !a.Is4() {
		return false
	}
	for _, p := range gameBuiltInCIDRs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// RegionTrustedFor 该 IP 命中段表时其 GeoIP 区判定是否可信（F11 第三态）：
// 云厂商全球段（cloudGameSegments，如 216.244.0.0/16）一律不可信——
// GeoIP 会把全球段标成美国/欧洲；其余段表命中（远端规则集 + 内置游戏段）
// 视为可信。供 trustedServer 判定 / last_proxies 豁免 / 记忆污染治理统一
// 使用，未命中段表返回 false（调用方按原有“未命中段表”语义处理）。
func (s *GameServerSegmentTable) RegionTrustedFor(ip netip.Addr) bool {
	if !ip.IsValid() || !s.MatchIP(ip) {
		return false
	}
	return !isCloudSegmentIP(ip)
}

// MatchDomain 判断域名（或其子域）是否命中已知游戏域名后缀集。
func (s *GameServerSegmentTable) MatchDomain(domain string) bool {
	if domain == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.domainSet == nil {
		return false
	}
	return s.domainSet.Has(domain)
}

// Stats 返回段表统计（条目数与更新时间，供诊断展示）。
func (s *GameServerSegmentTable) Stats() (cidrs, domains int, updated time.Time, source string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cidrCount, s.domainCount, s.updated, s.source
}

// StartSegmentLoader 启动段表后台加载：
//   - 先读本地缓存（秒加载，不阻塞内核启动）；
//   - 后台异步拉取远端规则集，下载完成即生效；
//   - 之后每 gameSegmentRefreshSecs（默认每天）定时拉取；
//   - 拉取失败一律静默使用本地缓存，不阻塞、不崩溃、不打扰。
//
// 零配置：无需任何 config.yaml 字段，parseGameLane 时自动调用。
func StartSegmentLoader() {
	cachePath := C.Path.Resolve(gameSegmentCacheName)
	go func() {
		loadSegmentCache(cachePath)
		refreshSegments(cachePath)
		ticker := time.NewTicker(gameSegmentRefreshSecs * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			refreshSegments(cachePath)
		}
	}()
}

// loadSegmentCache 启动时读本地缓存，秒级加载；缺失/损坏则以空表启动。
func loadSegmentCache(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Infoln("[GameLane] segment cache load skip: %v", err)
		return
	}
	var cf segmentCacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		log.Warnln("[GameLane] segment cache parse fail: %v", err)
		return
	}
	if len(cf.CIDRs) == 0 && len(cf.Domains) == 0 {
		return
	}
	var updated time.Time
	if cf.Updated != "" {
		if t, err := time.Parse(time.RFC3339, cf.Updated); err == nil {
			updated = t
		}
	}
	buildSegmentTable(cf.CIDRs, cf.Domains, cf.Source, updated)
	log.Infoln("[GameLane] segment cache loaded: cidr=%d domain=%d source=%s",
		len(cf.CIDRs), len(cf.Domains), cf.Source)
}

// refreshSegments 拉取远端规则集并重建段表；失败静默保留当前表（缓存兜底）。
func refreshSegments(cachePath string) {
	data, source, err := fetchGameSegments()
	if err != nil {
		log.Debugln("[GameLane] segment fetch fail, keep cache: %v", err)
		return
	}
	var sy struct {
		Payload []string `yaml:"payload"`
	}
	if err := yaml.Unmarshal(data, &sy); err != nil {
		log.Warnln("[GameLane] segment yaml parse fail: %v", err)
		return
	}
	cidrs, domains := parseSegmentPayload(sy.Payload)
	if len(cidrs) == 0 && len(domains) == 0 {
		log.Warnln("[GameLane] segment payload empty, keep cache")
		return
	}
	now := time.Now()
	buildSegmentTable(cidrs, domains, source, now)
	saveSegmentCache(cachePath, cidrs, domains, source, now)
	log.Infoln("[GameLane] segment refreshed: cidr=%d domain=%d source=%s",
		len(cidrs), len(domains), source)
}

// buildSegmentTable 用解析出的 CIDR/域名重建段表（整体原子替换，RWMutex 保护）。
func buildSegmentTable(cidrs []string, domains []string, source string, updated time.Time) {
	cidrTrie := trie.NewIpCidrTrie()
	for _, c := range cidrs {
		_ = cidrTrie.AddIpCidrForString(c)
	}
	builder := trie.DomainSetBuilder{}
	for _, d := range domains {
		_ = builder.Insert(d)
	}
	domainSet := builder.Build()

	t := &GameServerSegmentTable{
		cidrTrie:    cidrTrie,
		domainSet:   domainSet,
		cidrCount:   len(cidrs),
		domainCount: len(domains),
		updated:     updated,
		source:      source,
	}
	defaultSegments.mu.Lock()
	// 逐字段赋值，保留 defaultSegments 自身的 mu（不可整体拷贝覆盖已锁状态）
	defaultSegments.cidrTrie = t.cidrTrie
	defaultSegments.domainSet = t.domainSet
	defaultSegments.cidrCount = t.cidrCount
	defaultSegments.domainCount = t.domainCount
	defaultSegments.updated = t.updated
	defaultSegments.source = t.source
	defaultSegments.mu.Unlock()
}

// parseSegmentPayload 解析 Clash 规则集 payload 列表：
//   - IP-CIDR / IP-CIDR6 → CIDR 段（前缀树）；
//   - DOMAIN-SUFFIX / DOMAIN → 游戏域名（后缀树）；
//   - 其余类型（DOMAIN-KEYWORD / PROCESS-NAME 等）忽略，不参与段表。
func parseSegmentPayload(payload []string) (cidrs, domains []string) {
	for _, line := range payload {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tp, p, _, _ := rulesCommon.ParseRulePayload(line, false)
		switch tp {
		case "IP-CIDR", "IP-CIDR6":
			if p != "" {
				cidrs = append(cidrs, p)
			}
		case "DOMAIN-SUFFIX":
			// 后缀语义：匹配根域与其所有子域。DomainSet 的 ".xxx" 通配只
			// 匹配子域，须同时插入根域与带点通配两项。
			if p != "" {
				domains = append(domains, p, "."+p)
			}
		case "DOMAIN":
			if p != "" {
				domains = append(domains, p)
			}
		}
	}
	return
}

// fetchSegmentBytes 拉取远端规则集的可注入入口（单测可替换为本地桩）。
var fetchSegmentBytes = httpGetBytes

// fetchGameSegments 主源优先拉取，失败自动降级备源。
func fetchGameSegments() ([]byte, string, error) {
	if data, err := fetchSegmentBytes(gameSegmentPrimaryURL); err == nil {
		return data, "blackmatrix7", nil
	}
	data, err := fetchSegmentBytes(gameSegmentFallbackURL)
	if err != nil {
		return nil, "", err
	}
	return data, "metacubex", nil
}

// httpGetBytes 简单 GET 拉取（带超时与大小上限，防异常响应撑爆内存）。
// 走 mihomo 自有 HTTP 栈（component/http 的 HttpRequest），避免触碰
// net.DefaultResolver 防呆（main.go 将默认 resolver 的 Dial 设为 panic）。
func httpGetBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gameSegmentFetchTO)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{code: resp.StatusCode, url: url}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

type httpError struct {
	code int
	url  string
}

func (e *httpError) Error() string {
	return "http status " + http.StatusText(e.code) + " for " + e.url
}

// saveSegmentCache 将段表写入本地缓存（原子写：临时文件 + 改名）。
func saveSegmentCache(path string, cidrs, domains []string, source string, updated time.Time) {
	cf := segmentCacheFile{
		Version: gameSegmentCacheVer,
		Updated: updated.Format(time.RFC3339),
		Source:  source,
		CIDRs:   cidrs,
		Domains: domains,
	}
	data, err := json.Marshal(cf)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}
