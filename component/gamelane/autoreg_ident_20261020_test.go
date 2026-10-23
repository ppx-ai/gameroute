package gamelane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIdent20261020DirKeyword 平台安装目录特征命中即为游戏（库内任意游戏）。
func TestIdent20261020DirKeyword(t *testing.T) {
	cases := []string{
		`D:\SteamLibrary\steamapps\common\SomeGame\SomeGame.exe`,
		`D:\SteamLibrary\steamapps\common\SomeGame\Binaries\Win64\SomeGame-Win64-Shipping.exe`,
		`C:\Program Files\Epic Games\SomeTitle\SomeTitle.exe`,
		`C:\Riot Games\SomeGame\live\SomeGame.exe`,
		`C:\Program Files (x86)\Origin Games\SomeGame\SomeGame.exe`,
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

// TestIdent20261020AuxExcluded 启动器/辅助进程即便落在游戏平台目录也排除。
func TestIdent20261020AuxExcluded(t *testing.T) {
	cases := []string{
		`C:\Program Files (x86)\Steam\steamwebhelper.exe`,
		`C:\Program Files (x86)\Steam\steam.exe`,
		`C:\Program Files (x86)\Battle.net\Battle.net.exe`,
		`C:\Program Files\Epic Games\Launcher\Portal\Extras\EOS\EpicWebHelper.exe`,
		`C:\Riot Games\Riot Client\RiotClientServices.exe`,
		`C:\Program Files (x86)\Origin\Origin.exe`,
		`C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\UbisoftConnect.exe`,
		`C:\Program Files\EasyAntiCheat\EasyAntiCheat.exe`,
	}
	for _, p := range cases {
		ok, reason := isGameProcess(p)
		if ok {
			t.Fatalf("expect aux excluded for %q, got game (reason=%s)", p, reason)
		}
		if !isAuxProcessName(p) {
			t.Fatalf("expect isAuxProcessName true for %q", p)
		}
	}
}

// TestIdent20261020DllSniff 进程名无词条命中，但同目录存在引擎 DLL → 判定游戏。
func TestIdent20261020DllSniff(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "GameProbe.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "UnityPlayer.dll"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write dll: %v", err)
	}
	ok, reason := isGameProcess(exe)
	if !ok || reason != "dll" {
		t.Fatalf("expect (true,dll) for %q, got (%v,%s)", exe, ok, reason)
	}
}

// TestIdent20261020AuxPriorityOverDll aux 判定优先于 DLL 嗅探。
func TestIdent20261020AuxPriorityOverDll(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "steamwebhelper.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "UnityPlayer.dll"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write dll: %v", err)
	}
	if ok, reason := isGameProcess(exe); ok {
		t.Fatalf("aux must win over dll sniff, got game (reason=%s)", reason)
	}
}

// TestIdent20261020OldKeywordsIntact 旧词条一条未删（抽样回归）。
func TestIdent20261020OldKeywordsIntact(t *testing.T) {
	cases := []string{
		"r5apex.exe", "tslgame.exe", "pubg.exe", "valorant-win64-shipping.exe",
		"cs2.exe", "csgo.exe", "overwatch.exe", "dota2.exe", "rainbowsix.exe",
		"escapefromtarkov.exe", "deadbydaylight-win64-shipping.exe",
		"helldivers2.exe", "thefinals.exe", "marvelrivals.exe",
		"deltaforceclient-win64-shipping.exe", "naraka.exe", "genshinimpact.exe",
		"starrail.exe", "league of legends.exe", "x-win64-shipping.exe",
	}
	for _, n := range cases {
		if !isGameProcessName(n) {
			t.Fatalf("old keyword regressed for %q", n)
		}
	}
}

// TestIdent20261020VscodeStillExcluded VS Code 排除语义保持。
func TestIdent20261020VscodeStillExcluded(t *testing.T) {
	if isGameProcessName("Code.exe") {
		t.Fatal("Code.exe must stay excluded")
	}
	if ok, _ := isGameProcess(`C:\Users\x\AppData\Local\Programs\Microsoft VS Code\Code.exe`); ok {
		t.Fatal("Code.exe must stay excluded in path form")
	}
}

// TestIdent20261020BattleNetNotInKeyword battle.net 不得进入关键词表。
func TestIdent20261020BattleNetNotInKeyword(t *testing.T) {
	for _, k := range gameProcessKeywords {
		if k == "battle.net" || k == "blizzard" {
			t.Fatalf("launcher keyword leaked into gameProcessKeywords: %q", k)
		}
	}
}

// TestIdent20261020DllCache 缓存命中 + TTL 过期 + 上限重置行为正确。
func TestIdent20261020DllCache(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "MyGame.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	// 首次：无 DLL → false，缓存写入 false
	if dirHasEngineDLL(exe) {
		t.Fatal("expect false before dll exists")
	}
	dllSniffMu.RLock()
	_, cached := dllSniffCache[filepath.Dir(strings.ToLower(exe))]
	dllSniffMu.RUnlock()
	if !cached {
		t.Fatal("expect negative result cached")
	}
	// 补 DLL 后 TTL 内仍走缓存 false
	if err := os.WriteFile(filepath.Join(dir, "UnityPlayer.dll"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write dll: %v", err)
	}
	if dirHasEngineDLL(exe) {
		t.Fatal("expect cached false within TTL")
	}
	// 人为把时间戳推过 TTL → 重新嗅探命中
	key := filepath.Dir(strings.ToLower(exe))
	dllSniffMu.Lock()
	dllSniffCache[key] = dllSniffCacheEntry{hit: false, ts: time.Now().Add(-dllSniffTTL - time.Second)}
	dllSniffMu.Unlock()
	if !dirHasEngineDLL(exe) {
		t.Fatal("expect true after TTL expiry")
	}
}

