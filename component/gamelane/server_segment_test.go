package gamelane

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 构造一段 Clash 规则集 payload（模拟 blackmatrix7 Game_No_Resolve.yaml
// 与 MetaCubeX category-games.yaml 的常见条目形态）。
func segmentPayloadFixture() []string {
	return []string{
		"IP-CIDR,104.27.144.0/24,no-resolve",
		"IP-CIDR,8.8.8.0/24,no-resolve",
		"IP-CIDR6,2a06:98c0:3600::103,no-resolve",
		"DOMAIN-SUFFIX,epicgames.com",
		"DOMAIN-SUFFIX,playstation.net",
		"DOMAIN,somegame.example",
		"DOMAIN-KEYWORD,game",
		"PROCESS-NAME,SomeLauncher.exe",
		"",
		"  IP-CIDR,1.1.1.0/24,no-resolve  ",
	}
}

func TestParseSegmentPayload(t *testing.T) {
	cidrs, domains := parseSegmentPayload(segmentPayloadFixture())
	if len(cidrs) != 4 {
		t.Fatalf("cidrs = %d, want 4: %v", len(cidrs), cidrs)
	}
	// 2 个 DOMAIN-SUFFIX 各展开为根域 + 带点通配两项，再加 1 个 DOMAIN
	if len(domains) != 5 {
		t.Fatalf("domains = %d, want 5: %v", len(domains), domains)
	}
	// DOMAIN-KEYWORD / PROCESS-NAME 不进入段表
	for _, d := range domains {
		if d == "game" {
			t.Fatalf("DOMAIN-KEYWORD leaked into domains: %v", domains)
		}
	}
	// 前后带空白的条目应被 trim
	found := false
	for _, c := range cidrs {
		if c == "1.1.1.0/24" {
			found = true
		}
	}
	if !found {
		t.Fatalf("trimmed CIDR not parsed: %v", cidrs)
	}
}

func TestSegmentMatchIPRadix(t *testing.T) {
	cidrs, domains := parseSegmentPayload(segmentPayloadFixture())
	buildSegmentTable(cidrs, domains, "test", time.Now())

	cases := []struct {
		ip   string
		want bool
	}{
		{"104.27.144.5", true},   // 段内
		{"104.27.144.255", true}, // 段内边界
		{"104.27.143.1", false},  // 段外
		{"8.8.8.8", true},        // 段内
		{"8.8.9.1", false},       // 段外
		{"1.1.1.1", true},        // trim 后条目
		{"9.9.9.9", false},       // 未收录
	}
	for _, c := range cases {
		got := SegmentTable().MatchIP(netip.MustParseAddr(c.ip))
		if got != c.want {
			t.Errorf("MatchIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestSegmentMatchDomain(t *testing.T) {
	cidrs, domains := parseSegmentPayload(segmentPayloadFixture())
	buildSegmentTable(cidrs, domains, "test", time.Now())

	cases := []struct {
		domain string
		want   bool
	}{
		{"epicgames.com", true},
		{"store.epicgames.com", true},   // 子域后缀命中
		{"www.playstation.net", true},   // 子域后缀命中
		{"somegame.example", true},      // 全域名
		{"somegame.example.com", false}, // 非后缀（.example 后缀不存在）
		{"epicgames.com.evil.cn", false},
		{"", false},
	}
	for _, c := range cases {
		got := SegmentTable().MatchDomain(c.domain)
		if got != c.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestSegmentCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, gameSegmentCacheName)

	cidrs, domains := parseSegmentPayload(segmentPayloadFixture())
	now := time.Now()
	saveSegmentCache(cachePath, cidrs, domains, "blackmatrix7", now)

	// 读取缓存文件确认写入
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("cache file empty")
	}

	// 重置段表后再从缓存加载，验证等价
	resetSegmentsForTest()
	loadSegmentCache(cachePath)
	if got, _, _, _ := SegmentTable().Stats(); got != len(cidrs) {
		t.Fatalf("cache load cidr count = %d, want %d", got, len(cidrs))
	}
	if !SegmentTable().MatchIP(netip.MustParseAddr("104.27.144.5")) {
		t.Fatal("cache-loaded trie miss 104.27.144.5")
	}
	if !SegmentTable().MatchDomain("store.epicgames.com") {
		t.Fatal("cache-loaded domain set miss store.epicgames.com")
	}
}

func TestSegmentRefreshFromPayload(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, gameSegmentCacheName)

	yaml := "payload:\n" +
		"  - IP-CIDR,10.10.0.0/16,no-resolve\n" +
		"  - DOMAIN-SUFFIX,testgame.com\n"
	old := fetchSegmentBytes
	fetchSegmentBytes = func(url string) ([]byte, error) {
		return []byte(yaml), nil
	}
	defer func() { fetchSegmentBytes = old }()

	refreshSegments(cachePath)
	if !SegmentTable().MatchIP(netip.MustParseAddr("10.10.1.2")) {
		t.Fatal("refresh trie miss 10.10.1.2")
	}
	if !SegmentTable().MatchDomain("login.testgame.com") {
		t.Fatal("refresh domain set miss login.testgame.com")
	}
	// 缓存也应落盘
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("refresh did not persist cache: %v", err)
	}
}

func TestSegmentRefreshFallbackSource(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, gameSegmentCacheName)

	// 主源失败、备源成功
	old := fetchSegmentBytes
	fetchSegmentBytes = func(url string) ([]byte, error) {
		if url == gameSegmentPrimaryURL {
			return nil, os.ErrNotExist
		}
		return []byte("payload:\n  - DOMAIN-SUFFIX,fallbackgame.com\n"), nil
	}
	defer func() { fetchSegmentBytes = old }()

	refreshSegments(cachePath)
	if !SegmentTable().MatchDomain("fallbackgame.com") {
		t.Fatal("fallback source not applied")
	}
}

func TestSegmentRefreshFailureKeepsCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, gameSegmentCacheName)

	cidrs, domains := parseSegmentPayload(segmentPayloadFixture())
	buildSegmentTable(cidrs, domains, "test", time.Now())
	before, _, _, _ := SegmentTable().Stats()

	// 拉取失败：保留原表
	old := fetchSegmentBytes
	fetchSegmentBytes = func(url string) ([]byte, error) {
		return nil, os.ErrPermission
	}
	defer func() { fetchSegmentBytes = old }()

	refreshSegments(cachePath)
	after, _, _, _ := SegmentTable().Stats()
	if before != after {
		t.Fatalf("table mutated on fetch failure: before=%d after=%d", before, after)
	}
	if !SegmentTable().MatchIP(netip.MustParseAddr("104.27.144.5")) {
		t.Fatal("old trie lost after failed refresh")
	}
}

// resetSegmentsForTest 清空全局段表（仅供单测隔离状态）。
func resetSegmentsForTest() {
	defaultSegments.mu.Lock()
	defaultSegments.cidrTrie = nil
	defaultSegments.domainSet = nil
	defaultSegments.cidrCount = 0
	defaultSegments.domainCount = 0
	defaultSegments.updated = time.Time{}
	defaultSegments.source = ""
	defaultSegments.mu.Unlock()
}
