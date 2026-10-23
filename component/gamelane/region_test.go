package gamelane

import (
	"reflect"
	"testing"
)

func TestExtractRegionTag(t *testing.T) {
	cases := []struct {
		name string
		want string
		ok   bool
	}{
		// ===== HK =====
		{"香港-01", "HK", true},
		{"香港节点", "HK", true},
		{"HK-01", "HK", true},
		{"hk-01", "HK", true},
		{"港-01", "HK", true},
		{"港", "HK", true},
		{"hongkong-01", "HK", true},
		{"hkg-01", "HK", true},
		{"香港香港-01", "HK", true},
		{"香港 - 东京中转", "HK", true},
		{"香港-01-东京", "HK", true},
		// ===== TW =====
		{"台湾-01", "TW", true},
		{"TW节点", "TW", true},
		{"tw-01", "TW", true},
		{"台-01", "TW", true},
		{"taiwan-01", "TW", true},
		{"tai-01", "TW", true},
		// ===== JP =====
		{"日本-01", "JP", true},
		{"JP节点", "JP", true},
		{"jp-01", "JP", true},
		{"东京-01", "JP", true},
		{"东京-01-香港", "HK", true},
		// ===== KR =====
		{"韩国-01", "KR", true},
		{"韩国节点", "KR", true},
		{"KR-01", "KR", true},
		{"kr-01", "KR", true},
		{"韩-01", "KR", true},
		{"korea-01", "KR", true},
		{"korean-01", "KR", true},
		{"southkorea-01", "KR", true},
		{"首尔-01", "KR", true},
		// ===== SG =====
		{"新加坡-01", "SG", true},
		{"新加坡节点", "SG", true},
		{"SG-01", "SG", true},
		{"sg-01", "SG", true},
		{"星-01", "SG", true},
		{"singapore-01", "SG", true},
		// ===== US =====
		{"美国-01", "US", true},
		{"US节点", "US", true},
		{"us-01", "US", true},
		{"美东-01", "US", true},
		{"美东-02", "US", true},
		{"美西-01", "US", true},
		{"usa-01", "US", true},
		{"america-01", "US", true},
		{"美国香港-01", "US", true},
		// ===== CA =====
		{"加拿大-01", "CA", true},
		{"加拿大节点", "CA", true},
		{"CA-01", "CA", true},
		{"ca-01", "CA", true},
		{"加-01", "CA", true},
		{"canada-01", "CA", true},
		{"canadian-01", "CA", true},
		// ===== GB =====
		{"英国-01", "GB", true},
		{"英国节点", "GB", true},
		{"GB-01", "GB", true},
		{"uk-01", "GB", true},
		{"britain-01", "GB", true},
		{"british-01", "GB", true},
		{"england-01", "GB", true},
		{"london-01", "GB", true},
		// ===== DE =====
		{"德国-01", "DE", true},
		{"德国节点", "DE", true},
		{"DE-01", "DE", true},
		{"de-01", "DE", true},
		{"德-01", "DE", true},
		{"germany-01", "DE", true},
		{"german-01", "DE", true},
		{"frankfurt-01", "DE", true},
		// ===== FR =====
		{"法国-01", "FR", true},
		{"法国节点", "FR", true},
		{"FR-01", "FR", true},
		{"fr-01", "FR", true},
		{"法-01", "FR", true},
		{"france-01", "FR", true},
		{"french-01", "FR", true},
		// ===== NL =====
		{"荷兰-01", "NL", true},
		{"荷兰节点", "NL", true},
		{"NL-01", "NL", true},
		{"nl-01", "NL", true},
		{"尼-01", "NL", true},
		{"netherlands-01", "NL", true},
		{"dutch-01", "NL", true},
		{"dutchland-01", "NL", true},
		{"amsterdam-01", "NL", true},
		// ===== RU =====
		{"俄罗斯-01", "RU", true},
		{"俄罗斯节点", "RU", true},
		{"RU-01", "RU", true},
		{"ru-01", "RU", true},
		{"俄-01", "RU", true},
		{"russia-01", "RU", true},
		{"russian-01", "RU", true},
		// ===== AU =====
		{"澳大利亚-01", "AU", true},
		{"澳大利亚节点", "AU", true},
		{"AU-01", "AU", true},
		{"au-01", "AU", true},
		{"澳-01", "AU", true},
		{"australia-01", "AU", true},
		{"australian-01", "AU", true},
		{"sydney-01", "AU", true},
		{"melbourne-01", "AU", true},
		// ===== 防误配 =====
		// 中文 "英" 不单独作为 GB 关键词（避免 "英美" 之类误判），以下不匹配：
		{"英-01", "", false},
		// "新加坡 - 01" 只能进 SG，不进其他区
		{"新加坡-01", "SG", true},
		// 纯无地区信息
		{"节点-01", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := extractRegionTag(c.name)
		if ok != c.ok || got != c.want {
			t.Errorf("extractRegionTag(%q) = (%q, %v), want (%q, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestRegionContains(t *testing.T) {
	cases := []struct {
		name  string
		target string
		want  bool
	}{
		{"香港-01", "HK", true},
		{"香港 - 东京中转", "HK", true},
		{"香港 - 东京中转", "JP", false},
		{"东京-01", "JP", true},
		{"东京-01", "HK", false},
		{"新加坡-01", "SG", true},
		{"新加坡-01", "US", false},
		{"美东-01", "US", true},
		{"美东-02", "US", true},
		{"美西-01", "US", true},
		{"美国香港-01", "US", true},
		{"节点-01", "US", false},
		{"", "HK", false},
	}
	for _, c := range cases {
		if got := regionContains(c.name, c.target); got != c.want {
			t.Errorf("regionContains(%q, %q) = %v, want %v", c.name, c.target, got, c.want)
		}
	}
}

func TestFilterByRegion(t *testing.T) {
	names := []string{
		"香港-01", "东京-01", "新加坡-01", "美东-01", "美西-02",
		"韩国-01", "伦敦-01", "德国-01", "巴黎-01", "阿姆斯特丹-01",
		"莫斯科-01", "悉尼-01", "台湾-01", "多伦多-01",
	}
	got := FilterByRegion(names, "香港-01", "HK")
	want := []string{"香港-01"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FilterByRegion(HK) = %v, want %v", got, want)
	}

	got = FilterByRegion(names, "美东-01", "US")
	want = []string{"美东-01", "美西-02"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FilterByRegion(US) = %v, want %v", got, want)
	}

	got = FilterByRegion(names, "新加坡-01", "SG")
	want = []string{"新加坡-01"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FilterByRegion(SG) = %v, want %v", got, want)
	}

	got = FilterByRegion(names, "悉尼-01", "AU")
	want = []string{"悉尼-01"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FilterByRegion(AU) = %v, want %v", got, want)
	}
}

func TestFilterByRegion_Empty(t *testing.T) {
	got := FilterByRegion(nil, "香港-01", "HK")
	if got == nil {
		t.Errorf("FilterByRegion(nil) should return empty slice, got nil")
	}
	got = FilterByRegion([]string{}, "香港-01", "HK")
	if got == nil || len(got) != 0 {
		t.Errorf("FilterByRegion(empty) = %v, want empty slice", got)
	}
}

func TestFilterByRegion_FallbackToAll(t *testing.T) {
	names := []string{"香港-01", "东京-01", "新加坡-01"}
	got := FilterByRegion(names, "节点-01", "")
	want := names
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FilterByRegion(empty region) = %v, want %v", got, want)
	}
}

func TestTopN(t *testing.T) {
	rtt := map[string]int{
		"a": 100, "b": 50, "c": 200, "d": 10, "e": 300, "f": 5,
	}
	got := topNByRtt([]string{"a", "b", "c", "d", "e", "f"}, rtt, 3)
	want := []string{"f", "d", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("topNByRtt = %v, want %v", got, want)
	}

	// n 超过候选数
	got = topNByRtt([]string{"a", "b"}, rtt, 5)
	want = []string{"b", "a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("topNByRtt(all) = %v, want %v", got, want)
	}

	// 空候选
	if got := topNByRtt(nil, rtt, 3); got != nil {
		t.Errorf("topNByRtt(nil) = %v, want nil", got)
	}
}
