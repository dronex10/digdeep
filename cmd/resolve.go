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
	//if we dont resolve with one root name server, we try another until we exhaust them all. this is probably unnecessary because they should all be replicated but whatever
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

//recursively resolve until we find an authoritative response, or a non-authoritative response that we cannot continue from
//since we only return on authoritative responses (or failures), there shouldn't be a situation where we get a cached response from a non-authoritative source
func resolve(ctx context.Context, c *dns.Client, domain string, target string) ([]*netip.Addr, error) {
	ips := []*netip.Addr{}
	m := dns.NewMsg(domain, dns.TypeA)

	res, _, err := c.Exchange(ctx, m, "udp", target)
	if err != nil {
		return nil, err
	}

	if res.Rcode != 0 {
		slog.Debug("got error code in dns response", "code", res.Rcode)
		return nil, fmt.Errorf("dns response error code %d", res.Rcode)
	}

	if !res.Authoritative {
		//check for records in authority section
		if hasAuthoritys(res) {
			slog.Debug("got non authoritative response with authority section, checking glue records..")
			authorities := map[string]struct{}{}
			for _, authority := range res.Ns {
				if _, ok := authority.(*dns.NS); ok {
					slog.Debug("found NS record")
					authorities[authority.Data().String()] = struct{}{}
				}
			}
			if hasExtra(res) {
				for _, gluerecord := range res.Extra {
					_, isAuthority := authorities[gluerecord.Header().Name]
					if isAuthority {
						slog.Debug("found matching glue record")
						if _, ok := gluerecord.(*dns.A); ok { 
							authorityAddr := gluerecord.Data().String()
							authorityParsedAddr, err := netip.ParseAddr(authorityAddr)
							if err!=nil {
								return nil, fmt.Errorf("error parsing authority address to netip addr")
							}
							authorityPortAddr := netip.AddrPortFrom(authorityParsedAddr, 53)
							slog.Debug("querying matching glue record..")
							return resolve(ctx, c, domain, authorityPortAddr.String())
						}
					}
				}
			}
			slog.Debug("no glue records attached with authority records, this is an out-of-bailiwick scenario, bailing. handle this later.")
			return nil, fmt.Errorf("out-of-bailiwick")
		}
		slog.Debug("non-authoritative response and no records in authority section, bailing")
		return nil, fmt.Errorf("no delegation from non-authoritative nameserver")
	}

	slog.Debug("got authoritative response, parsing records..")
	for _, rr := range res.Answer {
		if _, ok := rr.(*dns.A); ok {
			parsedip, err := netip.ParseAddr(rr.Data().String())
			if err!=nil {
				slog.Debug("error parsing ip from response string", "response", rr, "error", err)
				return nil, fmt.Errorf("parsing error: %w", err)
			}
			ips = append(ips, &parsedip)
		}
	}
	return ips, nil
}

func hasExtra(m *dns.Msg) bool {
	return len(m.Extra)>0
}

func hasAuthoritys(m *dns.Msg) bool {
	return len(m.Ns)>0
}
