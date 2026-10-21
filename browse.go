package dnssd

import (
	"github.com/miekg/dns"
	"github.com/shabunin/dnssd/log"

	"context"
	"fmt"
	"net"
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

	qs := make(chan *Query)
	go func() {
		for _, iface := range MulticastInterfaces(ifaces...) {
			iface := iface
			q := &Query{msg: m, iface: iface}
			qs <- q
		}
	}()

	es := []*BrowseEntry{}
	for {
		select {
		case q := <-qs:
			log.Debug.Printf("Send browsing query at %s\n%s\n", q.IfaceName(), q.msg)
			if err := conn.SendQuery(q); err != nil {
				log.Debug.Println("SendQuery:", err)
			}

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
