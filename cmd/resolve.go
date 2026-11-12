package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"codeberg.org/miekg/dns"
)

// rootNameServers are the root name servers specified by iana, hard coded for now but probably better off in a seperate file
// iana.org/domains/root/servers
var rootNameServers = []netip.AddrPort{
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 41, 0, 4}), 53),     // a.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{170, 247, 170, 2}), 53),  // b.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 33, 4, 12}), 53),    // c.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{199, 7, 91, 13}), 53),    // d.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 203, 230, 10}), 53), // e.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 5, 5, 241}), 53),    // f.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 112, 36, 4}), 53),   // g.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 97, 190, 53}), 53),  // h.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 36, 148, 17}), 53),  // i.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 58, 128, 30}), 53),  // j.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{193, 0, 14, 129}), 53),   // k.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{199, 7, 83, 42}), 53),    // l.root-servers.net
	netip.AddrPortFrom(netip.AddrFrom4([4]byte{202, 12, 27, 33}), 53),   // m.root-servers.net
}

func ResolveDomain(ctx context.Context, domain string) ([]*netip.Addr, error) {
	c := dns.NewClient()
	for _, rootNs := range rootNameServers {
		slog.Debug("resolving domain from root name server", "domain", domain, "root_server", rootNs.String())
		addrs, err := resolve(ctx, c, domain, rootNs.String())
		if err != nil {
			slog.Debug("error resolving domain from root name server, trying another..", "root_server", rootNs.String(), "error", err)
			continue
		}
		return addrs, nil
	}
	return []*netip.Addr{}, nil
}

func resolve(ctx context.Context, c *dns.Client, domain string, target string) ([]*netip.Addr, error) {
	ips := []*netip.Addr{}
	m := dns.NewMsg(domain, dns.TypeA)

	slog.Debug("querying dns server for record", "dns_server", target, "domain", domain)
	res, _, err := c.Exchange(ctx, m, "udp", target)
	if err != nil {
		slog.Debug("error querying dns server", "server", target, "error", err)
		return nil, err
	}

	if res.Rcode != 0 {
		slog.Debug("got error response code from server", "rcode", res.Rcode)
		return nil, fmt.Errorf("dns response error code %d", res.Rcode)
	}

	if !res.Authoritative {
		slog.Debug("got non-authoritative response from server, querying NS records")
		m := dns.NewMsg(domain, dns.TypeNS)
		res, _, err := c.Exchange(ctx, m, "udp", target)
		if err!=nil {
			slog.Debug("error querying ns records", "error", err)
			return nil, fmt.Errorf("NS query error: %w", err)
		}
		if len(res.Ns) <= 0 {
			slog.Debug("no answers in response nameserver section", "response", res)
			return nil, fmt.Errorf("empty authority section")
		}
		ns := res.Ns[0].Data().String()
		m = dns.NewMsg(ns, dns.TypeA)
		res, _, err = c.Exchange(ctx, m, "udp", target)
		if err!=nil {
			slog.Debug("error resolving NS address", "error", err)
			return nil, fmt.Errorf("NS host resolution error: %w", err)
		}
		nsip := res.Answer[0].Data().String()
		return resolve(ctx, c, domain, nsip)
	}

	slog.Debug("got authoritative response")
	for _, rr := range res.Answer {
		parsedip, err := netip.ParseAddr(rr.Data().String())
		if err!=nil {
			slog.Debug("error parsing ip from response string", "response", rr, "error", err)
			return nil, fmt.Errorf("parsing error: %w", err)
		}
		ips = append(ips, &parsedip)
	}
	return ips, nil
}
