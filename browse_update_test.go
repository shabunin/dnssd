package dnssd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeConn delivers prepared messages to lookupType.
type fakeConn struct {
	ch chan *Request
}

func (c *fakeConn) SendQuery(q *Query) error                 { return nil }
func (c *fakeConn) SendResponse(resp *Response) error        { return nil }
func (c *fakeConn) Read(ctx context.Context) <-chan *Request { return c.ch }
func (c *fakeConn) Drain(ctx context.Context)                {}
func (c *fakeConn) Close()                                   {}

type browseEvent struct {
	added bool
	entry BrowseEntry
}

const testInstance = "Bridge._hap._tcp.local."

func announcement(ttl uint32, port uint16, ips ...string) *dns.Msg {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.PTR{Hdr: dns.RR_Header{Name: "_hap._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}, Ptr: testInstance},
		&dns.SRV{Hdr: dns.RR_Header{Name: testInstance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}, Port: port, Target: "bridge.local."},
	}
	for _, ip := range ips {
		m.Extra = append(m.Extra, addressRecord(ttl, ip))
	}
	return m
}

func addressRecord(ttl uint32, ip string) dns.RR {
	parsed := net.ParseIP(ip)
	if parsed.To4() != nil {
		return &dns.A{Hdr: dns.RR_Header{Name: "bridge.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: parsed}
	}
	return &dns.AAAA{Hdr: dns.RR_Header{Name: "bridge.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: parsed}
}

func startBrowse(t *testing.T) (chan<- *dns.Msg, <-chan browseEvent) {
	conn := &fakeConn{ch: make(chan *Request)}
	events := make(chan browseEvent, 10)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go lookupType(ctx, "_hap._tcp.local.", conn,
		func(e BrowseEntry) { events <- browseEvent{true, e} },
		func(e BrowseEntry) { events <- browseEvent{false, e} })

	msgs := make(chan *dns.Msg)
	iface := &net.Interface{Name: "eth0", Index: 1}
	go func() {
		for {
			select {
			case m := <-msgs:
				conn.ch <- &Request{msg: m, iface: iface}
			case <-ctx.Done():
				return
			}
		}
	}()
	return msgs, events
}

func next(t *testing.T, events <-chan browseEvent) browseEvent {
	t.Helper()
	select {
	case ev := <-events:
		return ev
	case <-time.After(time.Second):
		t.Fatal("expected browse event")
	}
	return browseEvent{}
}

func expectNoEvent(t *testing.T, events <-chan browseEvent) {
	t.Helper()
	select {
	case ev := <-events:
		t.Fatalf("unexpected event: added=%v %+v", ev.added, ev.entry)
	case <-time.After(100 * time.Millisecond):
	}
}

func ipStrings(ips []net.IP) []string {
	var res []string
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	return res
}

func TestBrowsePortChange(t *testing.T) {
	msgs, events := startBrowse(t)

	msgs <- announcement(120, 1000, "10.0.0.1")
	if ev := next(t, events); !ev.added || ev.entry.Port != 1000 {
		t.Fatalf("expected add with port 1000, got added=%v %+v", ev.added, ev.entry)
	}

	// service restarted on another port without sending goodbye
	msgs <- announcement(120, 2000, "10.0.0.1")
	if ev := next(t, events); ev.added || ev.entry.Port != 1000 {
		t.Fatalf("expected remove of port 1000, got added=%v %+v", ev.added, ev.entry)
	}
	if ev := next(t, events); !ev.added || ev.entry.Port != 2000 {
		t.Fatalf("expected add with port 2000, got added=%v %+v", ev.added, ev.entry)
	}
	expectNoEvent(t, events)
}

func TestBrowseReannouncement(t *testing.T) {
	msgs, events := startBrowse(t)

	msgs <- announcement(120, 1000, "10.0.0.1")
	next(t, events)

	// same records again, e.g. answer to a query of another host
	msgs <- announcement(120, 1000, "10.0.0.1")
	msgs <- announcement(120, 1000, "10.0.0.1")
	expectNoEvent(t, events)
}

func TestBrowseGoodbye(t *testing.T) {
	msgs, events := startBrowse(t)

	msgs <- announcement(120, 1000, "10.0.0.1")
	next(t, events)

	msgs <- announcement(0, 1000)
	if ev := next(t, events); ev.added || ev.entry.Port != 1000 {
		t.Fatalf("expected remove, got added=%v %+v", ev.added, ev.entry)
	}
	expectNoEvent(t, events)
}

func TestCacheIgnoresKnownIPs(t *testing.T) {
	cache := NewCache()
	eth0 := &net.Interface{Name: "eth0", Index: 1}
	wlan0 := &net.Interface{Name: "wlan0", Index: 2}

	for i := 0; i < 3; i++ {
		cache.UpdateFrom(&Request{msg: announcement(120, 1000, "10.0.0.1", "fe80::1"), iface: eth0})
	}
	cache.UpdateFrom(&Request{msg: announcement(120, 1000, "10.0.0.1"), iface: wlan0})

	srv := cache.services[testInstance]
	if srv == nil {
		t.Fatal("service not cached")
	}
	if got := ipStrings(srv.IPs); len(got) != 2 {
		t.Fatalf("expected 2 IPs, got %v", got)
	}
	if got := ipStrings(srv.ifaceIPs["eth0"]); len(got) != 2 {
		t.Fatalf("expected 2 IPs at eth0, got %v", got)
	}
	if got := ipStrings(srv.ifaceIPs["wlan0"]); len(got) != 1 {
		t.Fatalf("expected 1 IP at wlan0, got %v", got)
	}
}

func TestBrowseAddressChange(t *testing.T) {
	msgs, events := startBrowse(t)

	msgs <- announcement(120, 1000, "10.0.0.1")
	next(t, events)

	// address changed, e.g. new dhcp lease, service was not restarted
	msgs <- announcement(120, 1000, "10.0.0.2")
	ev := next(t, events)
	if !ev.added || ev.entry.Port != 1000 {
		t.Fatalf("expected add with updated addresses, got added=%v %+v", ev.added, ev.entry)
	}
	if got := ipStrings(ev.entry.IPs); len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("unexpected IPs %v", got)
	}

	msgs <- announcement(120, 1000, "10.0.0.2")
	expectNoEvent(t, events)
}

func withText(m *dns.Msg, ttl uint32, txt ...string) *dns.Msg {
	m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: testInstance, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}, Txt: txt})
	return m
}

func TestBrowseTextChange(t *testing.T) {
	msgs, events := startBrowse(t)

	msgs <- withText(announcement(120, 1000, "10.0.0.1"), 120, "c#=1", "id=AA")
	if ev := next(t, events); !ev.added || ev.entry.Text["c#"] != "1" {
		t.Fatalf("expected add with c#=1, got added=%v %+v", ev.added, ev.entry)
	}

	// accessory configuration changed
	msgs <- withText(announcement(120, 1000, "10.0.0.1"), 120, "c#=2", "id=AA")
	if ev := next(t, events); !ev.added || ev.entry.Text["c#"] != "2" {
		t.Fatalf("expected add with c#=2, got added=%v %+v", ev.added, ev.entry)
	}

	msgs <- withText(announcement(120, 1000, "10.0.0.1"), 120, "c#=2", "id=AA")
	expectNoEvent(t, events)
}

// queryConn records when queries are sent.
type queryConn struct {
	fakeConn
	sent chan time.Time
}

func (c *queryConn) SendQuery(q *Query) error {
	c.sent <- time.Now()
	return nil
}

// startQueryBrowse browses with given query intervals at one interface
// and records sent queries.
func startQueryBrowse(t *testing.T, minInterval, maxInterval time.Duration) *queryConn {
	oldMin, oldMax, oldIfaces := queryMinInterval, queryMaxInterval, multicastInterfaces
	t.Cleanup(func() { queryMinInterval, queryMaxInterval, multicastInterfaces = oldMin, oldMax, oldIfaces })
	queryMinInterval, queryMaxInterval = minInterval, maxInterval
	multicastInterfaces = func(...string) []*net.Interface {
		return []*net.Interface{{Name: "eth0", Index: 1}}
	}

	conn := &queryConn{fakeConn: fakeConn{ch: make(chan *Request)}, sent: make(chan time.Time, 10)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		lookupType(ctx, "_hap._tcp.local.", conn, func(BrowseEntry) {}, func(BrowseEntry) {})
		close(done)
	}()
	// before intervals are restored
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return conn
}

func TestBrowseRepeatsQuery(t *testing.T) {
	conn := startQueryBrowse(t, 20*time.Millisecond, 80*time.Millisecond)

	var times []time.Time
	for len(times) < 6 {
		select {
		case at := <-conn.sent:
			times = append(times, at)
		case <-time.After(time.Second):
			t.Fatalf("only %d queries sent", len(times))
		}
	}

	// 20, 40, 80, 80, 80 ms
	want := []time.Duration{20, 40, 80, 80, 80}
	for i, w := range want {
		got := times[i+1].Sub(times[i])
		w *= time.Millisecond
		if got < w-5*time.Millisecond || got > w+30*time.Millisecond {
			t.Fatalf("interval %d is %v, want %v", i, got, w)
		}
	}
}

func TestBrowseRefreshesBeforeExpiry(t *testing.T) {
	// no scheduled queries during test
	conn := startQueryBrowse(t, time.Hour, time.Hour)
	<-conn.sent

	received := time.Now()
	conn.ch <- &Request{msg: announcement(2, 1000, "10.0.0.1"), iface: &net.Interface{Name: "eth0", Index: 1}}

	// at 80%, 85%, 90% and 95% of 2s
	for _, want := range []time.Duration{1600, 1700, 1800, 1900} {
		select {
		case at := <-conn.sent:
			got := at.Sub(received)
			want *= time.Millisecond
			if got < want-10*time.Millisecond || got > want+60*time.Millisecond {
				t.Fatalf("query at %v, want %v", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no query at %v", want)
		}
	}
	select {
	case <-conn.sent:
		t.Fatal("unexpected query after 95% of ttl")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestBrowseRemovesExpired(t *testing.T) {
	msgs, events := startBrowse(t)

	msgs <- announcement(1, 1000, "10.0.0.1")
	next(t, events)

	// nothing is received anymore
	select {
	case ev := <-events:
		if ev.added {
			t.Fatalf("expected remove, got add %+v", ev.entry)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired instance should be removed")
	}
}

func message(rrs ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = rrs
	return m
}

func TestCacheLifetimeOfInstance(t *testing.T) {
	eth0 := &net.Interface{Name: "eth0", Index: 1}
	ptr := func(ttl uint32) dns.RR {
		return &dns.PTR{Hdr: dns.RR_Header{Name: "_hap._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}, Ptr: testInstance}
	}
	srv := func(ttl uint32) dns.RR {
		return &dns.SRV{Hdr: dns.RR_Header{Name: testInstance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}, Port: 1000, Target: "bridge.local."}
	}
	txt := func(ttl uint32) dns.RR {
		return &dns.TXT{Hdr: dns.RR_Header{Name: testInstance, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}, Txt: []string{"id=AA"}}
	}
	expiresIn := func(c *Cache) time.Duration {
		s := c.services[testInstance]
		if s == nil {
			return 0
		}
		return time.Until(s.expiration).Round(time.Minute)
	}

	c := NewCache()
	c.UpdateFrom(&Request{msg: message(ptr(4500), srv(120), txt(4500)), iface: eth0})
	if d := expiresIn(c); d != 75*time.Minute {
		t.Fatalf("listed instance expires in %v, want PTR ttl", d)
	}
	// e.g. other host asked for SRV record
	c.UpdateFrom(&Request{msg: message(srv(120)), iface: eth0})
	if d := expiresIn(c); d != 75*time.Minute {
		t.Fatalf("SRV record shortened lifetime to %v", d)
	}

	c = NewCache()
	c.UpdateFrom(&Request{msg: message(ptr(120), srv(120), txt(4500)), iface: eth0})
	if d := expiresIn(c); d != 2*time.Minute {
		t.Fatalf("TXT record extended lifetime to %v", d)
	}

	// resolved by name, no PTR record
	c = NewCache()
	c.UpdateFrom(&Request{msg: message(srv(120), txt(4500)), iface: eth0})
	if d := expiresIn(c); d != 2*time.Minute {
		t.Fatalf("resolved instance expires in %v, want SRV ttl", d)
	}

	// goodbye of SRV record
	c.UpdateFrom(&Request{msg: message(srv(0)), iface: eth0})
	if _, ok := c.services[testInstance]; ok {
		t.Fatal("instance should be removed")
	}
}
