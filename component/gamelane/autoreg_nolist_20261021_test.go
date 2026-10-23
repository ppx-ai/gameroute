package gamelane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// 2026-10-21 无词表通用识别改造单测：
// 覆盖 ①不得残留任何单游戏硬编码词条（Warframe 案例）②中文/英文通用游戏
// 目录特征 ③父目录与 Tools 子目录引擎 DLL 嗅探 ④Oodle 精确名与前缀兜底
// ⑤虚构条目 unrealengine.dll 已删除 ⑥aux 表对齐浏览器/IM/播放器/系统进程
// ⑦processGate 改为"只否决 aux、未知进程放行"。

func writeFileT(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestNoList20261021NoHardcodedGameKeyword 禁止任何单游戏名词进词表。
func TestNoList20261021NoHardcodedGameKeyword(t *testing.T) {
	for _, k := range gameProcessKeywords {
		if strings.EqualFold(k, "warframe") {
			t.Fatalf("gameProcessKeywords 不得包含单游戏硬编码词 %q", k)
		}
	}
	for _, name := range []string{"warframe.x64.exe", "warframe.exe"} {
		if matchGameProcessKeyword(name) {
			t.Fatalf("裸进程名 %q 不应命中关键词表（无词表通用识别）", name)
		}
		if ok, _ := isGameProcess(name); ok {
			t.Fatalf("裸进程名 %q 不应被判定为游戏", name)
		}
	}
}

// TestNoList20261021ChineseGameDirs 中文游戏目录特征（顺网/网咖出盘形态）。
func TestNoList20261021ChineseGameDirs(t *testing.T) {
	cases := []string{
		`D:\我的游戏\SomeTitle\SomeTitle.exe`,
		`E:\网络游戏\SomeTitle\Binaries\Win64\SomeTitle-Win64-Shipping.exe`,
		`E:\对战游戏\SomeTitle\SomeTitle.exe`,
		`E:\单机游戏\SomeTitle\SomeTitle.exe`,
		`F:\Games\SomeTitle\SomeTitle.exe`,
	}
	for _, p := range cases {
		ok, reason := isGameProcess(p)
		if !ok {
			t.Fatalf("expect game for %q, got false", p)
		}
		if reason != "keyword" {
			t.Fatalf("expect reason keyword for %q, got %q", p, reason)
		}
	}
}

// TestNoList20261021ChineseDirsNotMatchPrefixNoSlash 目录特征必须带尾随分隔符，
// 避免 "我的游戏X\" / "GamesX\" 之类前缀误命中。
func TestNoList20261021ChineseDirsNotMatchPrefixNoSlash(t *testing.T) {
	cases := []string{
		`D:\我的游戏备份\Tool\Tool.exe`,
		`D:\GamesBackup\Tool\Tool.exe`,
	}
	for _, p := range cases {
		if ok, reason := isGameProcess(p); ok {
			t.Fatalf("expect not game for %q, got game (reason=%s)", p, reason)
		}
	}
}

// TestNoList20261021ParentDirDLL 父目录存在引擎 DLL → 判定游戏。
func TestNoList20261021ParentDirDLL(t *testing.T) {
	base := t.TempDir()
	exeDir := filepath.Join(base, "SomeTitle", "Binaries", "Win64")
	writeFileT(t, filepath.Join(exeDir, "SomeTitle-Win64-Shipping.exe"))
	writeFileT(t, filepath.Join(base, "SomeTitle", "Binaries", "steam_api64.dll"))

	ok, reason := isGameProcess(filepath.Join(exeDir, "SomeTitle-Win64-Shipping.exe"))
	if !ok || reason != "keyword" {
		// -shipping 词条优先命中，属预期；此处只校验判定为游戏。
		t.Fatalf("expect game for shipping exe, got (%v,%s)", ok, reason)
	}

	// 换一个不含任何词条的进程名，专测父目录 DLL 嗅探。
	plain := filepath.Join(exeDir, "client.exe")
	writeFileT(t, plain)
	ok, reason = isGameProcess(plain)
	if !ok || reason != "dll" {
		t.Fatalf("expect (true,dll) via parent dir for %q, got (%v,%s)", plain, ok, reason)
	}
}

// TestNoList20261021ToolsDirDLL 同目录 Tools 子目录存在引擎 DLL → 判定游戏。
func TestNoList20261021ToolsDirDLL(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "client.exe")
	writeFileT(t, exe)
	writeFileT(t, filepath.Join(dir, "Tools", "unityplayer.dll"))

	ok, reason := isGameProcess(exe)
	if !ok || reason != "dll" {
		t.Fatalf("expect (true,dll) via Tools dir, got (%v,%s)", ok, reason)
	}
}

// TestNoList20261021OodleExact Oodle 精确版本名命中。
func TestNoList20261021OodleExact(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "client.exe")
	writeFileT(t, exe)
	writeFileT(t, filepath.Join(dir, "oo2core_8_win64.dll"))

	if ok, reason := isGameProcess(exe); !ok || reason != "dll" {
		t.Fatalf("expect (true,dll) via oo2core exact, got (%v,%s)", ok, reason)
	}
}

// TestNoList20261021OodleFallback 未知 Oodle 版本名由前缀兜底扫描命中。
func TestNoList20261021OodleFallback(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "client.exe")
	writeFileT(t, exe)
	writeFileT(t, filepath.Join(dir, "oo2core_99_win64.dll"))

	if ok, reason := isGameProcess(exe); !ok || reason != "dll" {
		t.Fatalf("expect (true,dll) via oo2core prefix fallback, got (%v,%s)", ok, reason)
	}
}

// TestNoList20261021UnrealEngineDllRemoved 虚构条目 unrealengine.dll 必须失效。
func TestNoList20261021UnrealEngineDllRemoved(t *testing.T) {
	for _, dll := range gameEngineDLLs {
		if dll == "unrealengine.dll" {
			t.Fatalf("gameEngineDLLs 不得保留虚构条目 unrealengine.dll")
		}
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "client.exe")
	writeFileT(t, exe)
	writeFileT(t, filepath.Join(dir, "unrealengine.dll"))

	if ok, reason := isGameProcess(exe); ok {
		t.Fatalf("仅存在 unrealengine.dll 不应判定为游戏，got (true,%s)", reason)
	}
}

// TestNoList20261021AuxNewEntries 新增 aux 词条对齐。
func TestNoList20261021AuxNewEntries(t *testing.T) {
	cases := []string{
		`C:\Users\U\AppData\Local\Discord\app-1.0\Discord.exe`,
		`C:\Program Files\Tencent\QQNT\QQ.exe`,
		`C:\Program Files\Tencent\QQMusic\QQMusic.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files\qBittorrent\qbittorrent.exe`,
		`C:\Program Files\DAUM\PotPlayer\PotPlayerMini64.exe`,
		`C:\Program Files\Netease\CloudMusic\cloudmusic.exe`,
		`C:\Windows\System32\svchost.exe`,
		`C:\Windows\explorer.exe`,
		`C:\Windows\System32\RuntimeBroker.exe`,
		`C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe`,
	}
	for _, p := range cases {
		if !isAuxProcessName(p) {
			t.Fatalf("expect isAuxProcessName true for %q", p)
		}
		if ok, _ := isGameProcess(p); ok {
			t.Fatalf("expect not game for aux path %q", p)
		}
	}
}

// TestNoList20261022AuxStreamClientNotExcluded v2.12 清单4（2026-10-22）：
// 云电脑/串流客户端（airlinks / shunwangcloud）已从 aux 排除表移除——
// 云电脑场景下它就是承载游戏运行的宿主进程，排除它等于整局游戏不被识别；
// 误伤风险改由"进程门禁只做 aux 否决 + 观察窗/打分期"承接。
func TestNoList20261022AuxStreamClientNotExcluded(t *testing.T) {
	cases := []string{
		`D:\Program Files\shunwangcloud\data\flutter_assets\assets\airlinks\win\airlinks.exe`,
		`C:\Program Files\shunwangcloud\airlinks.exe`,
	}
	for _, p := range cases {
		if isAuxProcessName(p) {
			t.Fatalf("串流客户端不应再被 aux 排除：%q", p)
		}
	}
}

// TestNoList20261021ProcessGate processGate 只否决 aux，未知进程放行。
func TestNoList20261021ProcessGate(t *testing.T) {
	old := findProcess
	defer func() { findProcess = old }()

	cases := []struct {
		name string
		want bool
	}{
		{`C:\Users\U\AppData\Local\Discord\app-1.0\Discord.exe`, false},
		{`C:\Program Files\Tencent\QQMusic\QQMusic.exe`, false},
		{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, false},
		{`C:\Windows\System32\svchost.exe`, false},
		// 无词条、非 aux 的第三方程序/游戏：放行，交由流量特征打分兜底。
		{`D:\我的游戏\SomeTitle\SomeTitle.exe`, true},
		{`D:\SomeApp\weirdclient.exe`, true},
		{`D:\Games\SomeTitle\bin\client.exe`, true},
	}
	for _, c := range cases {
		name := c.name
		findProcess = func(m *C.Metadata) (uint32, string) { return 4242, name }
		if got := processGate(&C.Metadata{}); got != c.want {
			t.Fatalf("processGate(%q) = %v, want %v", name, got, c.want)
		}
	}

	// 反查失败（空进程名）→ 放行。
	findProcess = func(m *C.Metadata) (uint32, string) { return 0, "" }
	if !processGate(&C.Metadata{}) {
		t.Fatalf("processGate 反查失败应放行")
	}
}
