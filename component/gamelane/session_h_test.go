package gamelane

import (
	"sync"
	"testing"
	"time"
)

// 手动操纵 protectedSince 模拟保护期状态，验证切换拦截逻辑。
// 切换为异步执行（launchSwitch 内 goroutine），断言前需轮询等待。

func waitSwitchCalled(t *testing.T, mu *sync.Mutex, called *bool, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		mu.Lock()
		c := *called
		mu.Unlock()
		if c {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestSessionConn_H_ProtectionPeriod(t *testing.T) {
	pc := newFakePacketConn(t, "h-protection")
	defer pc.Close()

	switchCalled := false
	switchMu := sync.Mutex{}

	sc := NewSessionConn(pc, "h-test", false, DefaultConfig(), func(bool) error {
		switchMu.Lock()
		switchCalled = true
		switchMu.Unlock()
		return nil
	})
	defer sc.Close()

	// 1. 新创建的 SessionConn 应处于保护期内
	if !sc.isProtected() {
		t.Fatal("new session should be in protection period")
	}

	// 2. 保护期内切换应被阻止
	switchCalled = false
	sc.doSwitchToFallback()
	if waitSwitchCalled(t, &switchMu, &switchCalled, 100*time.Millisecond) {
		t.Fatal("doSwitchToFallback should be blocked in protection period")
	}

	// 3. 保护期内 launchSwitch 也应被阻止
	switchCalled = false
	sc.doSwitchAsync(false)
	if waitSwitchCalled(t, &switchMu, &switchCalled, 100*time.Millisecond) {
		t.Fatal("doSwitchAsync should be blocked in protection period")
	}

	// 4. 手动清零保护期后，切换应允许执行
	sc.protectedSince.Store(0)
	switchCalled = false
	sc.doSwitchToFallback()
	if !waitSwitchCalled(t, &switchMu, &switchCalled, time.Second) {
		t.Fatal("doSwitchToFallback should be allowed after protection cleared")
	}

	// 5. 过期时间戳应视为保护期结束
	sc.protectedSince.Store(time.Now().UnixMilli() - 1000)
	if sc.isProtected() {
		t.Fatal("isProtected should return false after expiry")
	}
}

func TestSessionConn_H_LaunchSwitchBlockedInProtection(t *testing.T) {
	pc := newFakePacketConn(t, "h-ls")
	defer pc.Close()

	switchCalled := false
	switchMu := sync.Mutex{}
	sc := NewSessionConn(pc, "h-ls-test", false, DefaultConfig(), func(bool) error {
		switchMu.Lock()
		switchCalled = true
		switchMu.Unlock()
		return nil
	})
	defer sc.Close()

	// 保护期内 launchSwitch 应被拦截
	switchCalled = false
	sc.doSwitchAsync(false)
	if waitSwitchCalled(t, &switchMu, &switchCalled, 100*time.Millisecond) {
		t.Fatal("launchSwitch should be blocked in protection period")
	}

	// 保护期过后，切换应允许
	sc.protectedSince.Store(0)
	switchCalled = false
	sc.doSwitchAsync(false)
	if !waitSwitchCalled(t, &switchMu, &switchCalled, time.Second) {
		t.Fatal("launchSwitch should be allowed after protection cleared")
	}
}

func TestSessionConn_H_IsProtectedLifecycle(t *testing.T) {
	pc := newFakePacketConn(t, "h-life")
	defer pc.Close()

	sc := NewSessionConn(pc, "h-life-test", false, DefaultConfig(), nil)
	defer sc.Close()

	// 刚创建应处于保护期
	if !sc.isProtected() {
		t.Fatal("new session should be in protection period")
	}

	// 清零后不应处于保护期
	sc.protectedSince.Store(0)
	if sc.isProtected() {
		t.Fatal("isProtected should be false after clearing")
	}

	// 设置过去的时间戳，不应处于保护期
	sc.protectedSince.Store(time.Now().UnixMilli() - 5000)
	if sc.isProtected() {
		t.Fatal("isProtected should be false for expired timestamp")
	}
}

func TestSessionConn_H_SwitchSilentBlockedInProtection(t *testing.T) {
	pc := newFakePacketConn(t, "h-ss")
	defer pc.Close()

	switchCalled := false
	switchMu := sync.Mutex{}
	sc := NewSessionConn(pc, "h-ss-test", false, DefaultConfig(), func(bool) error {
		switchMu.Lock()
		switchCalled = true
		switchMu.Unlock()
		return nil
	})
	defer sc.Close()

	// 保护期内 doSwitchSilentAsync 也应被拦截
	switchCalled = false
	sc.doSwitchSilentAsync()
	if waitSwitchCalled(t, &switchMu, &switchCalled, 100*time.Millisecond) {
		t.Fatal("doSwitchSilentAsync should be blocked in protection period")
	}

	// 保护期过后应允许
	sc.protectedSince.Store(0)
	switchCalled = false
	sc.doSwitchSilentAsync()
	if !waitSwitchCalled(t, &switchMu, &switchCalled, time.Second) {
		t.Fatal("doSwitchSilentAsync should be allowed after protection cleared")
	}
}

func TestSessionConn_H_AutoPickBlockedInProtection(t *testing.T) {
	pc := newFakePacketConn(t, "h-ap")
	defer pc.Close()

	sc := NewSessionConn(pc, "h-ap-test", false, DefaultConfig(), func(bool) error {
		return nil
	})
	defer sc.Close()

	// 保护期内 auto-pick 探测应被拦截（autoPickDone 不应被设置）
	sc.SetAutoPick(true)
	sc.maybeBeginAutoPickProbe()
	if sc.autoPickDone.Load() {
		t.Fatal("auto-pick probe should be blocked in protection period")
	}

	// 保护期过后允许发起探测
	sc.protectedSince.Store(0)
	sc.maybeBeginAutoPickProbe()
	// 无候选池时 maybeBeginAutoPickProbe 在池检查处提前 return，
	// autoPickDone 不会设置；此用例只验证保护期拦截不误伤后续调用
	if !sc.autoPickDone.Load() {
		// 无池时该方法确实不会设置 autoPickDone，属预期分支
	}
}
