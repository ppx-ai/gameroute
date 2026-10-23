package gamelane

import (
	"net/netip"
	"testing"
)

// ---- 2026-10-18 v2.2：铁律三（段表首包同步注册）+ 强制修正二 ----

// 场景 4（铁律三）：216.244.12.165 命中编译内置云段（cloudGameSegments），
// 首包无进程反查结果也必须同步注册成功（注册路径前置后不依赖 findProcess）。
func TestRegisterGameTargetIfNeeded_SegmentSyncFirstPacket(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	if !m.RegisterGameTargetIfNeeded(gameMetadata("216.244.12.165", 10200), true) {
		t.Fatal("segment hit (216.244.0.0/16 built-in cloud) must register synchronously on first packet")
	}
	// 已注册目标不得重复注册
	if m.RegisterGameTargetIfNeeded(gameMetadata("216.244.12.165", 10200), true) {
		t.Fatal("already-registered target must not re-register")
	}
}

// 强制修正二：auto 目标 currentPrimary 未初始化时，EffectiveProxyForIP 主动
// 走 ensureAutoPrimary 链拿确定节点名（同节点短路可用）；未注册 IP 返回空。
func TestEffectiveProxyForIP_AutoInitializes(t *testing.T) {
	m := newDefaultManager()
	m.SetEnabled(true)
	m.SetAllProxies([]string{"HK-01", "TW-01", "SG-01", "JP-01", "KR-01"})
	// v2.13 起禁盲选：无任何实测值时选主返回空串（走先测再进），
	// 故此处给出实测表，验证 auto 目标仍能经 ensureAutoPrimary 拿到确定节点。
	m.SetRTTTable(map[string]int{"HK-01": 30, "JP-01": 55})
	m.SetTargets([]Target{{
		ProcessName: "auto-t",
		CIDR:        []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")},
	}})
	if got := m.EffectiveProxyForIP("198.51.100.7"); got == "" {
		t.Fatal("auto target with no primary must initialize via ensureAutoPrimary chain")
	}
	if m.EffectiveProxyForIP("1.2.3.4") != "" {
		t.Fatal("unregistered IP must return empty string")
	}
}

// 显式配置目标：EffectiveProxyForIP 原样返回配置 Proxy（铁律一比较基准）。
func TestEffectiveProxyForIP_Explicit(t *testing.T) {
	m := newDefaultManager()
	m.SetTargets([]Target{{
		ProcessName: "fix-t",
		CIDR:        []netip.Prefix{netip.MustParsePrefix("203.0.113.5/32")},
		Proxy:       "SG 01",
	}})
	if got := m.EffectiveProxyForIP("203.0.113.5"); got != "SG 01" {
		t.Fatalf("explicit target proxy must return as-is, got %q", got)
	}
}
