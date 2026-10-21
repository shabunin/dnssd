package dnssd

import (
	"github.com/miekg/dns"
	"github.com/shabunin/dnssd/log"

	"context"
	"fmt"
	"net"
	"time"
)

// BrowseEntry represents a discovered service instance.
type BrowseEntry struct {
	IPs       []net.IP
	Host      string
	Port      int
	IfaceName string
	Name      string
	Type      string
	Domain    string
	Text      map[string]string
}

// AddFunc is called when a service instance was found.
// It is called again for the same instance, when new IP addresses
// of the instance are found or its txt records change.
type AddFunc func(BrowseEntry)

// RmvFunc is called when a service instance disappared.
type RmvFunc func(BrowseEntry)

// LookupType browses for service instances.
func LookupType(ctx context.Context, service string, add AddFunc, rmv RmvFunc) (err error) {
	conn, err := newMDNSConn()
	if err != nil {
		return err
	}
	defer conn.close()

	return lookupType(ctx, service, conn, add, rmv)
}

// LookupTypeAtInterface browses for service instances at specific network interfaces.
func LookupTypeAtInterfaces(ctx context.Context, service string, add AddFunc, rmv RmvFunc, ifaces ...string) (err error) {
	conn, err := newMDNSConn(ifaces...)
	if err != nil {
		return err
	}
	defer conn.close()

	return lookupType(ctx, service, conn, add, rmv, ifaces...)
}

// ServiceInstanceName returns the service instance name
// in the form of <instance name>.<service>.<domain>.
// (Note the trailing dot.)
func (e BrowseEntry) EscapedServiceInstanceName() string {
	return fmt.Sprintf("%s.%s.%s.", escape.Replace(e.Name), e.Type, e.Domain)
}

// ServiceInstanceName returns the same as `ServiceInstanceName()`
// but removes any escape characters.
func (e BrowseEntry) ServiceInstanceName() string {
	return fmt.Sprintf("%s.%s.%s.", e.Name, e.Type, e.Domain)
}

// Intervals between browsing queries: the second query is sent a second
// after the first one, then the interval doubles up to an hour (RFC 6762 5.2).
var (
	queryMinInterval = time.Second
	queryMaxInterval = time.Hour
)

// multicastInterfaces is replaced in tests.
var multicastInterfaces = MulticastInterfaces

func lookupType(ctx context.Context, service string, conn MDNSConn, add AddFunc, rmv RmvFunc, ifaces ...string) (err error) {
	var cache = NewCache()

	m := new(dns.Msg)
	m.Question = []dns.Question{
		dns.Question{
			Name:   service,
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		},
	}
	// TODO include known answers which current ttl is more than half of the correct ttl (see TFC6772 7.1: Known-Answer Supression)
	// m.Answer = ...
	// m.Authoritive = false // because our answers are *believes*

	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()

	ch := conn.Read(readCtx)

	sendQueries := func() {
		for _, iface := range multicastInterfaces(ifaces...) {
			q := &Query{msg: m, iface: iface}
			log.Debug.Printf("Send browsing query at %s\n%s\n", q.IfaceName(), q.msg)
			if err := conn.SendQuery(q); err != nil {
				log.Debug.Println("SendQuery:", err)
			}
		}
	}

	// The query is repeated, so that a lost query or response doesn't hide
	// service instances until they announce themselves again,
	// and a responder that ignored the query, because it answered
	// another one less than a second ago, answers the next one.
	sendQueries()
	interval := queryMinInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()

	es := []*BrowseEntry{}
	for {
		select {
		case <-timer.C:
			sendQueries()
			interval = min(interval*2, queryMaxInterval)
			timer.Reset(interval)

		case req := <-ch:
			log.Debug.Printf("Receive message at %s\n%s\n", req.IfaceName(), req.msg)
			cache.UpdateFrom(req)

			// Process removed entries first, so that a service instance
			// that changed its port is removed before it is added again.
			tmp := []*BrowseEntry{}
			for _, e := range es {
				var found = false
				for _, srv := range cache.Services() {
					if srv.ServiceInstanceName() == e.ServiceInstanceName() && srv.Port == e.Port {
						found = true
						break
					}
				}

				if found {
					tmp = append(tmp, e)
				} else {
					// TODO
					rmv(*e)
				}
			}
			es = tmp

			for _, srv := range cache.Services() {
				if srv.ServiceName() != service {
					continue
				}

				for ifaceName, ips := range srv.ifaceIPs {
					var found *BrowseEntry
					for _, e := range es {
						if e.Name == srv.Name && e.IfaceName == ifaceName && e.Port == srv.Port {
							found = e
							break
						}
					}
					if found != nil {
						if !containsIPs(found.IPs, ips) || !equalText(found.Text, srv.Text) {
							// new addresses or txt records of known instance
							found.IPs = append([]net.IP(nil), ips...)
							found.Text = srv.Text
							add(*found)
						}
					} else {
						e := BrowseEntry{
							IPs:       append([]net.IP(nil), ips...),
							Host:      srv.Host,
							Port:      srv.Port,
							IfaceName: ifaceName,
							Name:      srv.Name,
							Type:      srv.Type,
							Domain:    srv.Domain,
							Text:      srv.Text,
						}
						es = append(es, &e)
						add(e)
					}
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// containsIPs returns true if all ips are in known.
func containsIPs(known []net.IP, ips []net.IP) bool {
	for _, ip := range ips {
		if !containsIP(known, ip) {
			return false
		}
	}
	return true
}

func equalText(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
