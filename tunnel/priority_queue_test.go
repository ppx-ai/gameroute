package tunnel

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/gamelane"
	C "github.com/metacubex/mihomo/constant"
)

// ---------------------------------------------------------------------------
// mocks
// ---------------------------------------------------------------------------

type dropRecorder struct {
	mu  sync.Mutex
	seq []string
}

func (r *dropRecorder) record(tag string) {
	r.mu.Lock()
	r.seq = append(r.seq, tag)
	r.mu.Unlock()
}

func (r *dropRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.seq...)
	return out
}

func (r *dropRecorder) waitFor(n int, timeout time.Duration) []string {
	deadline := time.Now().Add(timeout)
	for {
		r.mu.Lock()
		if len(r.seq) >= n {
			out := append([]string(nil), r.seq...)
			r.mu.Unlock()
			return out
		}
		r.mu.Unlock()
		if time.Now().After(deadline) {
			r.mu.Lock()
			out := append([]string(nil), r.seq...)
			r.mu.Unlock()
			return out
		}
		time.Sleep(2 * time.Millisecond)
	}
}

type recPacket struct {
	tag   string
	rec   *dropRecorder
	local net.Addr
}

func (p *recPacket) Data() []byte { return nil }
func (p *recPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	return len(b), nil
}
func (p *recPacket) Drop() { p.rec.record(p.tag) }
func (p *recPacket) LocalAddr() net.Addr {
	if p.local != nil {
		return p.local
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

// newInvalidAdapter returns a PacketAdapter whose metadata fails handleUDPConn
// early (invalid metadata), so processUDP only exercises the scheduling layer.
func newInvalidAdapter(tag string, rec *dropRecorder) C.PacketAdapter {
	return C.NewPacketAdapter(&recPacket{tag: tag, rec: rec}, &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5, // status is Suspend by default, isHandle returns false anyway
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		SrcPort: 53,
	})
}

// ---------------------------------------------------------------------------
// processUDP: high-priority first
// ---------------------------------------------------------------------------

func TestProcessUDP_HighPriorityFirst(t *testing.T) {
	hi := make(chan C.PacketAdapter, 64)
	normal := make(chan C.PacketAdapter, 64)
	rec := &dropRecorder{}

	for i := 1; i <= 3; i++ {
		hi <- newInvalidAdapter("H"+itoa(i), rec)
	}
	for i := 1; i <= 2; i++ {
		normal <- newInvalidAdapter("N"+itoa(i), rec)
	}

	go processUDP(hi, normal)
	seq := rec.waitFor(5, 3*time.Second)

	if len(seq) != 5 {
		t.Fatalf("expected 5 consumed packets, got %d: %v", len(seq), seq)
	}
	want := []string{"H1", "H2", "H3", "N1", "N2"}
	for i, w := range want {
		if seq[i] != w {
			t.Fatalf("step %d: want %s got %s (full seq %v)", i, w, seq[i], seq)
		}
	}
}

// ---------------------------------------------------------------------------
// processUDP: 3:1 burst limit prevents normal starvation
// ---------------------------------------------------------------------------

func TestProcessUDP_NoStarvation(t *testing.T) {
	hi := make(chan C.PacketAdapter, 64)
	normal := make(chan C.PacketAdapter, 64)
	rec := &dropRecorder{}

	for i := 1; i <= 6; i++ {
		hi <- newInvalidAdapter("H"+itoa(i), rec)
	}
	for i := 1; i <= 2; i++ {
		normal <- newInvalidAdapter("N"+itoa(i), rec)
	}

	go processUDP(hi, normal)
	seq := rec.waitFor(8, 3*time.Second)

	if len(seq) != 8 {
		t.Fatalf("expected 8 consumed packets, got %d: %v", len(seq), seq)
	}
	want := []string{"H1", "H2", "H3", "N1", "H4", "H5", "H6", "N2"}
	for i, w := range want {
		if seq[i] != w {
			t.Fatalf("step %d: want %s got %s (full seq %v)", i, w, seq[i], seq)
		}
	}
}

// ---------------------------------------------------------------------------
// processUDP: per-session order preserved within the same queue
// ---------------------------------------------------------------------------

func TestProcessUDP_SessionOrderPreserved(t *testing.T) {
	hi := make(chan C.PacketAdapter, 64)
	normal := make(chan C.PacketAdapter, 64)
	rec := &dropRecorder{}

	// session A (high lane) packets A1..A3, session B (normal) packets B1..B2
	hi <- newInvalidAdapter("A1", rec)
	hi <- newInvalidAdapter("A2", rec)
	hi <- newInvalidAdapter("A3", rec)
	normal <- newInvalidAdapter("B1", rec)
	normal <- newInvalidAdapter("B2", rec)

	go processUDP(hi, normal)
	seq := rec.waitFor(5, 3*time.Second)

	// A session packets must be consumed in their arrival order
	aOrder := filterTags(seq, "A")
	wantA := []string{"A1", "A2", "A3"}
	for i := range wantA {
		if aOrder[i] != wantA[i] {
			t.Fatalf("session A order broken: %v (full seq %v)", aOrder, seq)
		}
	}
	bOrder := filterTags(seq, "B")
	wantB := []string{"B1", "B2"}
	for i := range wantB {
		if bOrder[i] != wantB[i] {
			t.Fatalf("session B order broken: %v (full seq %v)", bOrder, seq)
		}
	}
}

func filterTags(seq []string, prefix string) []string {
	var out []string
	for _, s := range seq {
		if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
			out = append(out, s)
		}
	}
	return out
}

func itoa(i int) string {
	return string(rune('0' + i))
}

// ---------------------------------------------------------------------------
// selectUDPQueue: lane session uses high-priority queue, cached and stable
// ---------------------------------------------------------------------------

func TestSelectUDPQueue_LaneSessionStable(t *testing.T) {
	udpQueuesHi = []chan C.PacketAdapter{make(chan C.PacketAdapter, 64)}
	udpQueuesNormal = []chan C.PacketAdapter{make(chan C.PacketAdapter, 64)}
	laneCache = xsync.Map[string, *laneEntry]{}

	mgr := gamelane.Default()
	mgr.SetEnabled(true)
	defer mgr.SetEnabled(false)
	mgr.SetTargets([]gamelane.Target{{
		CIDR:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Proxy: "DIRECT",
	}})

	laneMeta := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("203.0.113.9"),
		DstPort: 27015, // v2.4 铁令 C：443 在排除端口总闸名单，lane 用例改用对局端口
	}
	normalMeta := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 12346,
		DstIP:   netip.MustParseAddr("198.51.100.9"),
		DstPort: 27015, // v2.4 铁令 C：443 在排除端口总闸名单，lane 用例改用对局端口
	}

	keyA := "lane-session-key"
	keyB := "normal-session-key"

	// first packet of lane session -> high queue, and cached
	q1 := selectUDPQueue(keyA, laneMeta, 0)
	if q1 != udpQueuesHi[0] {
		t.Fatalf("lane session first packet must go to hi queue")
	}
	// following packets of the same session stay on the same queue
	q2 := selectUDPQueue(keyA, laneMeta, 0)
	if q2 != udpQueuesHi[0] {
		t.Fatalf("lane session queue must be stable across packets")
	}

	// normal session -> normal queue, stable
	q3 := selectUDPQueue(keyB, normalMeta, 0)
	if q3 != udpQueuesNormal[0] {
		t.Fatalf("normal session must go to normal queue")
	}
	q4 := selectUDPQueue(keyB, normalMeta, 0)
	if q4 != udpQueuesNormal[0] {
		t.Fatalf("normal session queue must be stable across packets")
	}
}

// ---------------------------------------------------------------------------
// selectUDPQueue: disabled gameroute has zero impact (always normal queue)
// ---------------------------------------------------------------------------

func TestSelectUDPQueue_DisabledZeroImpact(t *testing.T) {
	udpQueuesHi = []chan C.PacketAdapter{make(chan C.PacketAdapter, 64)}
	udpQueuesNormal = []chan C.PacketAdapter{make(chan C.PacketAdapter, 64)}
	laneCache = xsync.Map[string, *laneEntry]{}

	mgr := gamelane.Default()
	mgr.SetEnabled(false)
	mgr.SetTargets([]gamelane.Target{{
		CIDR:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Proxy: "DIRECT",
	}})

	meta := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("203.0.113.9"),
		DstPort: 27015, // v2.4 铁令 C：443 在排除端口总闸名单，lane 用例改用对局端口
	}

	if q := selectUDPQueue("any-key", meta, 0); q != udpQueuesNormal[0] {
		t.Fatalf("disabled gameroute must not change queue selection")
	}
	// no lane cache entry should be created while disabled
	if _, ok := laneCache.Load("any-key"); ok {
		t.Fatalf("disabled gameroute must not write lane cache")
	}
}

// ---------------------------------------------------------------------------
// HandleUDPPacket: queue selection end-to-end (no consumers running)
// ---------------------------------------------------------------------------

func TestHandleUDPPacket_QueueSelection(t *testing.T) {
	// initialize real workers first; afterwards we swap queue vars so the
	// running workers keep consuming the old channels and our assertions
	// read from the new (unconsumed) queues.
	udpInit.Do(initUDP)
	udpQueuesHi = []chan C.PacketAdapter{make(chan C.PacketAdapter, 64)}
	udpQueuesNormal = []chan C.PacketAdapter{make(chan C.PacketAdapter, 64)}
	laneCache = xsync.Map[string, *laneEntry]{}

	mgr := gamelane.Default()
	mgr.SetEnabled(true)
	defer mgr.SetEnabled(false)
	mgr.SetTargets([]gamelane.Target{{
		CIDR:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Proxy: "DIRECT",
	}})

	rec := &dropRecorder{}
	lanePacket := C.NewPacketAdapter(&recPacket{tag: "L", rec: rec, local: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1111}}, &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("203.0.113.9"),
		DstPort: 27015, // v2.4 铁令 C：443 在排除端口总闸名单，lane 用例改用对局端口
	})
	normalPacket := C.NewPacketAdapter(&recPacket{tag: "N", rec: rec, local: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2222}}, &C.Metadata{
		NetWork: C.UDP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 12346,
		DstIP:   netip.MustParseAddr("198.51.100.9"),
		DstPort: 27015, // v2.4 铁令 C：443 在排除端口总闸名单，lane 用例改用对局端口
	})

	// lane session -> hi queue
	select {
	case p := <-udpQueuesHi[0]:
		t.Fatalf("hi queue should be empty before HandleUDPPacket, got %s", p.Key())
	default:
	}
	Tunnel.HandleUDPPacket(lanePacket, lanePacket.Metadata())
	select {
	case p := <-udpQueuesHi[0]:
		if p.Key() != lanePacket.Key() {
			t.Fatalf("unexpected packet in hi queue")
		}
	default:
		t.Fatalf("lane packet must be routed to hi queue")
	}

	// normal session -> normal queue, hi queue untouched
	Tunnel.HandleUDPPacket(normalPacket, normalPacket.Metadata())
	select {
	case p := <-udpQueuesNormal[0]:
		if p.Key() != normalPacket.Key() {
			t.Fatalf("unexpected packet in normal queue")
		}
	default:
		t.Fatalf("normal packet must be routed to normal queue")
	}
	select {
	case p := <-udpQueuesHi[0]:
		t.Fatalf("hi queue should be empty, got %s", p.Key())
	default:
	}
}
