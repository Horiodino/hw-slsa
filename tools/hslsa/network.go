package hslsa

// The tapeout check's network rule: a Design L3 step reaches declared license
// servers and nothing else. Implements the spec section "Network access and
// licensed tools".

// checkNetwork checks one design step's hwFlow.network block. The block must
// agree with itself whenever it is present; the policy's design.network
// settings add the isolation requirement, the list of allowed license servers
// and a ceiling on bytes sent.
func checkNetwork(stmt Obj, label string, pol Obj) error {
	netPol := O(pol, "network")
	require := get(netPol, "requireIsolation") == true
	net := O(stmt, "predicate", "hwFlow", "network")
	mode := "open"
	if net != nil {
		mode = S(net, "mode")
	}
	switch mode {
	case "isolated", "license-server":
	case "open":
		if require {
			return failf("%s: network access is open, so the step is not isolated", label)
		}
		return nil
	default:
		return failf("%s: unknown network mode %q", label, mode)
	}

	servers := Objs(net, "licenseServers")
	if mode == "isolated" && len(servers) > 0 {
		return failf("%s: isolated step declares license servers", label)
	}
	if mode == "license-server" && len(servers) == 0 {
		return failf("%s: license-server mode declares no license server", label)
	}
	listed := map[string][]string{}
	for _, s := range Objs(netPol, "allowedLicenseServers") {
		listed[S(s, "address")] = Strs(s, "endpoints")
	}
	checkList := require || Has(netPol, "allowedLicenseServers")
	addresses := map[string]bool{}
	endpoints := map[string]bool{}
	for _, s := range servers {
		addr := S(s, "address")
		eps := Strs(s, "endpoints")
		if len(eps) == 0 {
			return failf("%s: license server %s declares no endpoints", label, addr)
		}
		addresses[addr] = true
		for _, ep := range eps {
			if checkList && !contains(listed[addr], ep) {
				return failf("%s: license server %s endpoint %s is not on the policy's list", label, addr, ep)
			}
			endpoints[ep] = true
		}
	}

	var sent int64
	for _, o := range Objs(net, "observed") {
		if get(o, "allowed") != true {
			continue
		}
		if ep := S(o, "endpoint"); !endpoints[ep] {
			return failf("%s: connected to %s, which is not a declared license server endpoint", label, ep)
		}
		n, _ := Int(o, "bytesSent")
		sent += n
	}
	for _, f := range Objs(net, "features") {
		if !addresses[S(f, "server")] {
			return failf("%s: license feature %s came from undeclared server %s", label, S(f, "name"), S(f, "server"))
		}
	}
	if limit, ok := Int(netPol, "maxBytesSent"); ok && sent > limit {
		return failf("%s: sent %d bytes to license servers, over the policy's limit of %d", label, sent, limit)
	}
	return nil
}
