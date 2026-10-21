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
