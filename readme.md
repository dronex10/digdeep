small cli tool to resolve domains iteratively from root until authoritative ns to avoid caches
made it for testing a dynamic dns client im making, but thought it'd be useful on its own


this tool does not work properly as is, there will be a 'no addresses found' response if any of the nameservers between root and the authoritative nameserver have a cached resolution for the domain
