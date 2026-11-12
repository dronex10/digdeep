package cmd

import (
	"context"
	"errors"
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
	m := dns.NewMsg(domain, dns.TypeA)

	slog.Debug("querying dns server for record", "dns_server", target, "domain", domain)
	r, _, err := c.Exchange(ctx, m, "udp", target)
	if err != nil {
		slog.Debug("error querying dns server", "server", target, "error", err)
		return nil, err
	}

	if r.Authoritative {
		slog.Debug("got authoritative response from server", "server", target, "domain", domain, "raw response", r)
		if r.Rcode != 0 {
			slog.Debug("got error response from authoritative dns server", "server", target, "rcode", r.Rcode)
			return nil, errors.New("got none-zero rcode from authoritative dns server")
		}

		addrs := []*netip.Addr{}
		if len(r.Answer) > 0 {
			slog.Debug("authoritative answer contains one or more records")
			for _, ans := range r.Answer {
				if dns.RRToType(ans) != dns.TypeA {
					slog.Debug("found a non-A type record in response, skipping", "record", ans.String())
					continue
				}
				addr, err := netip.ParseAddr(ans.Data().String())
				if err != nil {
					slog.Debug("could not parse address from dns query response", "error", err)
					return nil, err
				}
				slog.Debug("successfully parsed address from record response, appending", "addr", addr, "authoritative_server", target)
				addrs = append(addrs, &addr)
			}
			return addrs, nil
		}

		slog.Debug("received authoritative response, but had no records in answer section")
		return addrs, nil
	}

	slog.Debug("got non-authoritative response, querying glue records", "glue records", r.Extra)
	glueRecords := make(map[string]struct{})

	if len(r.Ns) > 0 {
		for _, ns := range r.Ns {
			glueRecords[ns.Data().String()] = struct{}{}
		}
	}

	if len(r.Extra) > 0 {
		for _, ref := range r.Extra {
			if _, exists := glueRecords[ref.Header().Name]; exists {
				addr, err := resolve(ctx, c, domain, fmt.Sprintf("%s:%s", ref.Data().String(), "53"))
				if err != nil {
					slog.Debug("error querying glue record", "server", ref.Data().String(), "error", err)
					continue
				}
				return addr, nil
			}
		}
	}

	slog.Debug("got no glue records in response from non-authoritative name server")
	return nil, errors.New("no nameservers found")
}
