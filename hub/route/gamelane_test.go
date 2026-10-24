package route

import (
	"bytes"
	"encoding/json"
	muxhttp "github.com/metacubex/http"
	"testing"

	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/component/gamelane"

	httptest "github.com/metacubex/http/httptest"
)

// newGameLaneTestRouter 挂载被测路由，与生产挂载方式保持一致。
func newGameLaneTestRouter() muxhttp.Handler {
	r := chi.NewRouter()
	r.Mount("/gameroute", gameLaneRouter())
	return r
}

// resetGameLane 清理全局 Manager 单例状态，避免用例间相互污染。
func resetGameLane() {
	m := gamelane.Default()
	m.SetEnabled(false)
	m.SetTargets(nil)
	gamelane.ResetM3Stats()
}

func doReq(t *testing.T, h muxhttp.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// decodeStatus 解析 GET /gameroute/status 响应。
func decodeStatus(t *testing.T, w *httptest.ResponseRecorder) (bool, []gameLaneTarget) {
	t.Helper()
	var resp struct {
		Enabled bool             `json:"enabled"`
		Targets []gameLaneTarget `json:"targets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return resp.Enabled, resp.Targets
}

func TestGameLaneStatus_InitialDisabled(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	w := doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)

	if w.Code != muxhttp.StatusOK {
		t.Fatalf("status code = %d, want 200", w.Code)
	}
	enabled, targets := decodeStatus(t, w)
	if enabled {
		t.Fatal("initial status should be disabled")
	}
	if len(targets) != 0 {
		t.Fatalf("initial targets = %d, want 0", len(targets))
	}
}

func TestGameLaneStatus_AfterPutReflectsState(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	body := map[string]any{
		"enable": true,
		"targets": []map[string]any{
			{"process_name": "genshin.exe", "proxy": "节点A"},
			// 注意：私网段（RFC1918）被排除层拒绝注册（设计如此），
			// 用公网测试段（TEST-NET-3）验证 CIDR 目标正常入库。
			{"cidr": []string{"203.0.113.0/24"}, "proxy": "节点B"},
		},
	}
	w := doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", body)
	if w.Code != muxhttp.StatusNoContent {
		t.Fatalf("PUT status code = %d, want 204; body=%s", w.Code, w.Body.String())
	}

	w = doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	if w.Code != muxhttp.StatusOK {
		t.Fatalf("status code = %d, want 200", w.Code)
	}
	enabled, targets := decodeStatus(t, w)
	if !enabled {
		t.Fatal("status should be enabled after PUT")
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	if targets[0].ProcessName != "genshin.exe" || targets[0].Proxy != "节点A" {
		t.Fatalf("target[0] = %+v, want process genshin.exe proxy 节点A", targets[0])
	}
	if len(targets[1].CIDR) != 1 || targets[1].CIDR[0] != "203.0.113.0/24" {
		t.Fatalf("target[1].CIDR = %v, want [203.0.113.0/24]", targets[1].CIDR)
	}
}

func TestGameLanePut_EmptyTargetsClearsRegistry(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	// 先塞入一条
	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{{"process_name": "a.exe", "proxy": "p"}},
	})
	// 再整体替换为空（清空）
	w := doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{},
	})
	if w.Code != muxhttp.StatusNoContent {
		t.Fatalf("PUT status code = %d, want 204", w.Code)
	}

	w = doReq(t, h, muxhttp.MethodGet, "/gameroute/targets", nil)
	if w.Code != muxhttp.StatusOK {
		t.Fatalf("status code = %d, want 200", w.Code)
	}
	var resp struct {
		Targets []gameLaneTarget `json:"targets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode targets: %v", err)
	}
	if len(resp.Targets) != 0 {
		t.Fatalf("targets = %d, want 0", len(resp.Targets))
	}
}

func TestGameLanePut_BadJSON(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	req := httptest.NewRequest(muxhttp.MethodPut, "/gameroute/targets", bytes.NewBufferString("{not-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != muxhttp.StatusBadRequest {
		t.Fatalf("status code = %d, want 400", w.Code)
	}
}

func TestGameLanePut_MissingTargets(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	// 只有 enable 没有 targets 字段
	w := doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{"enable": true})
	if w.Code != muxhttp.StatusBadRequest {
		t.Fatalf("status code = %d, want 400", w.Code)
	}
}

func TestGameLanePut_EmptyProxy(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	// proxy 为空 = auto 模式（v2 Auto-Pick Primary）：接受并返回 204
	w := doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{{"process_name": "a.exe", "proxy": ""}},
	})
	if w.Code != muxhttp.StatusNoContent {
		t.Fatalf("status code = %d, want 204", w.Code)
	}
	// 显式 "auto" 同样表示 auto 模式
	resetGameLane()
	w = doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{{"process_name": "a.exe", "proxy": "auto"}},
	})
	if w.Code != muxhttp.StatusNoContent {
		t.Fatalf("status code = %d, want 204", w.Code)
	}
}

func TestGameLanePut_InvalidCIDR(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	w := doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{{"cidr": []string{"999.999.0.0/8"}, "proxy": "p"}},
	})
	if w.Code != muxhttp.StatusBadRequest {
		t.Fatalf("status code = %d, want 400", w.Code)
	}
}

func TestGameLanePut_TargetWithoutProcessOrCIDR(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	// proxy 有值但进程名和 CIDR 都没有：无匹配条件，拒绝
	w := doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{{"proxy": "p"}},
	})
	if w.Code != muxhttp.StatusBadRequest {
		t.Fatalf("status code = %d, want 400", w.Code)
	}
}

func TestGameLanePut_EnableOptionalKeepsState(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	// 第一步：enable + targets
	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"enable":  true,
		"targets": []map[string]any{{"process_name": "a.exe", "proxy": "p"}},
	})
	// 第二步：只替换 targets，不传 enable，开关保持开启
	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{{"process_name": "b.exe", "proxy": "p2"}},
	})

	w := doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	enabled, targets := decodeStatus(t, w)
	if !enabled {
		t.Fatal("enable should stay true when omitted")
	}
	if len(targets) != 1 || targets[0].ProcessName != "b.exe" {
		t.Fatalf("targets = %+v, want only b.exe", targets)
	}
}

// decodeM3Status 解析 GET /gameroute/status 中的 m3 子对象。
func decodeM3Status(t *testing.T, w *httptest.ResponseRecorder) gamelane.M3Snapshot {
	t.Helper()
	var resp struct {
		M3 gamelane.M3Snapshot `json:"m3"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode m3 status: %v", err)
	}
	return resp.M3
}

func TestGameLaneStatus_IncludesM3Snapshot(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	w := doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	if w.Code != muxhttp.StatusOK {
		t.Fatalf("status code = %d, want 200", w.Code)
	}
	m3 := decodeM3Status(t, w)
	if m3.Enabled {
		t.Fatal("m3 should be disabled initially")
	}
	if m3.SwitchCount != 0 || m3.CurrentProxy != "" || m3.LossRate != 0 {
		t.Fatalf("initial m3 snapshot = %+v, want all-zero", m3)
	}
	if !m3.LastSwitchAt.IsZero() {
		t.Fatalf("initial last_switch_at = %v, want zero", m3.LastSwitchAt)
	}
}

func TestGameLanePut_EnableM3(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"enable_m3": true,
		"targets":   []map[string]any{},
	})

	w := doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	if m3 := decodeM3Status(t, w); !m3.Enabled {
		t.Fatal("m3 should be enabled after PUT enable_m3=true")
	}

	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"enable_m3": false,
		"targets":   []map[string]any{},
	})
	w = doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	if m3 := decodeM3Status(t, w); m3.Enabled {
		t.Fatal("m3 should be disabled after PUT enable_m3=false")
	}
}

func TestGameLanePut_EnableM3OptionalKeepsState(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"enable_m3": true,
		"targets":   []map[string]any{},
	})
	// 再次 PUT 只替换 targets 不传 enable_m3，M3 开关保持开启
	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{{"process_name": "a.exe", "proxy": "p"}},
	})

	w := doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	if m3 := decodeM3Status(t, w); !m3.Enabled {
		t.Fatal("m3 should stay enabled when enable_m3 omitted")
	}
}

func TestGameLanePut_FallbackRoundTrip(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	doReq(t, h, muxhttp.MethodPut, "/gameroute/targets", map[string]any{
		"targets": []map[string]any{
			{"process_name": "genshin.exe", "proxy": "香港-A", "fallback": "香港-B"},
		},
	})

	w := doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	_, targets := decodeStatus(t, w)
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	if targets[0].Fallback != "香港-B" {
		t.Fatalf("target[0].Fallback = %q, want 香港-B", targets[0].Fallback)
	}

	w = doReq(t, h, muxhttp.MethodGet, "/gameroute/targets", nil)
	var resp struct {
		Targets []gameLaneTarget `json:"targets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode targets: %v", err)
	}
	if len(resp.Targets) != 1 || resp.Targets[0].Fallback != "香港-B" {
		t.Fatalf("targets fallback round-trip failed: %+v", resp.Targets)
	}
}

func TestGameLaneStatus_M3StatsAfterRecordSwitch(t *testing.T) {
	defer resetGameLane()
	resetGameLane()

	h := newGameLaneTestRouter()
	gamelane.RecordM3Switch(false, "节点B", 0.12)
	gamelane.RecordM3Switch(false, "节点C", 0.18)

	w := doReq(t, h, muxhttp.MethodGet, "/gameroute/status", nil)
	m3 := decodeM3Status(t, w)
	if m3.SwitchCount != 2 {
		t.Fatalf("switch_count = %d, want 2", m3.SwitchCount)
	}
	if m3.CurrentProxy != "节点C" {
		t.Fatalf("current_proxy = %q, want 节点C", m3.CurrentProxy)
	}
	if m3.LossRate != 0.18 {
		t.Fatalf("loss_rate = %v, want 0.18", m3.LossRate)
	}
	if m3.LastSwitchAt.IsZero() {
		t.Fatal("last_switch_at should be set after record")
	}
}
