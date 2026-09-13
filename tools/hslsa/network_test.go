package hslsa

// Tests for the Design L3 network rule (spec: "Network access and licensed
// tools"). No example runs its steps isolated yet, so the unit tests build the
// hwFlow.network block directly, starting from the spec's own example, and one
// tamper test puts a lying block into the PicoRV32 chain.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// specNetworkExample is the hwFlow.network example from the spec, parsed fresh on every call.
func specNetworkExample(t *testing.T) Obj {
	t.Helper()
	data := ok(os.ReadFile(filepath.Join(root, "spec", "hslsa-v0.1.md")))
	_, rest, found := strings.Cut(string(data), "#### Network access and licensed tools")
	if found {
		_, rest, found = strings.Cut(rest, "```json\n")
	}
	block, _, closed := strings.Cut(rest, "\n```")
	if !found || !closed {
		t.Fatal("spec has no JSON example under Network access and licensed tools")
	}
	return O(ok(decodeJSON([]byte("{"+block+"}"))), "network")
}

func netPolicy(t *testing.T) Obj {
	t.Helper()
	return O(ok(decodeJSON([]byte(`{"network": {
		"requireIsolation": true,
		"allowedLicenseServers": [{"address": "27000@lic1.flow.internal", "endpoints": ["10.20.0.5:27000", "10.20.0.5:27010"]}],
		"maxBytesSent": 1048576
	}}`))))
}

func stepWithNetwork(network Obj) Obj {
	hw := Obj{"step": "synthesis"}
	if network != nil {
		hw["network"] = network
	}
	return Obj{"predicate": Obj{"hwFlow": hw}}
}

func blockedAttempt() Obj {
	return Obj{"endpoint": "203.0.113.7:443", "allowed": false, "connections": 1, "bytesSent": 0, "bytesReceived": 0}
}

func TestNetworkRuleAccepts(t *testing.T) {
	cases := map[string]struct {
		network func(t *testing.T) Obj
		policy  Obj
	}{
		"spec-example":                {specNetworkExample, netPolicy(t)},
		"spec-example-without-policy": {specNetworkExample, Obj{}},
		"isolated-with-blocked-attempt": {func(*testing.T) Obj {
			return Obj{"mode": "isolated", "observed": []any{blockedAttempt()}}
		}, netPolicy(t)},
		"license-server-with-blocked-attempt": {func(t *testing.T) Obj {
			n := specNetworkExample(t)
			n["observed"] = append(A(n, "observed"), blockedAttempt())
			return n
		}, netPolicy(t)},
		"no-block-without-isolation": {func(*testing.T) Obj { return nil }, Obj{}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			must(t, checkNetwork(stepWithNetwork(c.network(t)), "design synthesis", c.policy))
		})
	}
}

func TestNetworkRuleRejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(n Obj) Obj
		policy func(t *testing.T) Obj
		reason string
	}{
		"no-block": {func(Obj) Obj { return nil }, netPolicy,
			"design synthesis: network access is open, so the step is not isolated"},
		"open-mode": {func(n Obj) Obj { n["mode"] = "open"; return n }, netPolicy,
			"network access is open, so the step is not isolated"},
		"unknown-mode": {func(n Obj) Obj { n["mode"] = "airgapped"; return n }, netPolicy,
			`unknown network mode "airgapped"`},
		"isolated-with-servers": {func(n Obj) Obj { n["mode"] = "isolated"; return n }, netPolicy,
			"isolated step declares license servers"},
		"no-servers": {func(n Obj) Obj { n["licenseServers"] = []any{}; return n }, netPolicy,
			"license-server mode declares no license server"},
		"server-without-endpoints": {func(n Obj) Obj { Objs(n, "licenseServers")[0]["endpoints"] = []any{}; return n }, netPolicy,
			"license server 27000@lic1.flow.internal declares no endpoints"},
		"server-not-listed": {func(n Obj) Obj { Objs(n, "licenseServers")[0]["address"] = "27000@lic.vendor.example"; return n }, netPolicy,
			"license server 27000@lic.vendor.example endpoint 10.20.0.5:27000 is not on the policy's list"},
		"endpoint-not-listed": {func(n Obj) Obj {
			s := Objs(n, "licenseServers")[0]
			s["endpoints"] = append(A(s, "endpoints"), "10.20.0.5:27011")
			return n
		}, netPolicy, "endpoint 10.20.0.5:27011 is not on the policy's list"},
		"listed-server-without-isolation-requirement": {func(n Obj) Obj { Objs(n, "licenseServers")[0]["address"] = "27000@lic.vendor.example"; return n },
			func(t *testing.T) Obj { p := netPolicy(t); delete(O(p, "network"), "requireIsolation"); return p },
			"is not on the policy's list"},
		"undeclared-connection": {func(n Obj) Obj {
			n["observed"] = append(A(n, "observed"), Obj{"endpoint": "203.0.113.7:443", "allowed": true, "connections": 1, "bytesSent": 4096, "bytesReceived": 512})
			return n
		}, netPolicy, "connected to 203.0.113.7:443, which is not a declared license server endpoint"},
		"undeclared-connection-without-policy": {func(n Obj) Obj {
			Objs(n, "observed")[0]["endpoint"] = "203.0.113.7:443"
			return n
		}, func(*testing.T) Obj { return Obj{} }, "connected to 203.0.113.7:443"},
		"isolated-but-connected": {func(Obj) Obj {
			return Obj{"mode": "isolated", "observed": []any{Obj{"endpoint": "10.20.0.5:27000", "allowed": true, "connections": 1, "bytesSent": 10, "bytesReceived": 10}}}
		}, netPolicy, "connected to 10.20.0.5:27000, which is not a declared license server endpoint"},
		"feature-from-undeclared-server": {func(n Obj) Obj { Objs(n, "features")[0]["server"] = "27000@lic2.flow.internal"; return n }, netPolicy,
			"license feature Example-Synthesis came from undeclared server 27000@lic2.flow.internal"},
		"over-byte-ceiling": {func(n Obj) Obj { Objs(n, "observed")[1]["bytesSent"] = 50000000; return n }, netPolicy,
			"sent 50001830 bytes to license servers, over the policy's limit of 1048576"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			step := stepWithNetwork(c.mutate(specNetworkExample(t)))
			rejects(t, checkNetwork(step, "design synthesis", c.policy(t)), c.reason)
		})
	}
}

// The tapeout check applies the rule to the chain's own design steps.
func TestUndeclaredNetworkConnection(t *testing.T) {
	bundle := chipBundle(t)
	chipResign(t, bundle, AttName("synthesis"), "flow-platform", func(s Obj) {
		O(s, "predicate", "hwFlow")["network"] = Obj{
			"mode":     "isolated",
			"observed": []any{Obj{"endpoint": "203.0.113.7:443", "allowed": true, "connections": 1, "bytesSent": 2048, "bytesReceived": 128}},
		}
	})
	rejects(t, chipCheck(t, bundle, nil), "design synthesis: connected to 203.0.113.7:443, which is not a declared license server endpoint")
}
