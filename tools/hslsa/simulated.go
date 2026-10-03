package hslsa

// Records made from simulated hardware (spec section "Records from simulated
// hardware").
//
// Until a real fab, OSAT, programming station or board takes part, every
// physical fact in the examples comes from a simulator: a scenario file, the
// virtual shuttle (shuttle.go), the Caliptra emulator or the simulated
// boards. A record made from one says so in its hardware block, as
// hwMfg.simulated or hwProvision.simulated, and the verifier refuses such a
// record unless the buyer's policy sets simulated.accept. When it accepts
// one, every VSA over it also states HSLSA_SIMULATED, so a summary of
// simulated evidence cannot be read as one of real parts.
//
// The mark is the signer's own statement, like every other field: a record
// without it is not thereby proven to come from real equipment.

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SimulatedLevel is the verifiedLevels value of a VSA over simulated evidence.
// SLSA allows custom values that do not start with SLSA_.
const SimulatedLevel = "HSLSA_SIMULATED"

// simulatedBlocks are the predicate blocks a record's hardware facts sit in.
var simulatedBlocks = []string{"hwMfg", "hwProvision", "hwInspection", "hwAfterSale"}

// checkSimulated checks a simulated block before it goes into a record: it
// names the simulator and what it stands in for.
func checkSimulated(mark Obj, where string) error {
	if mark == nil {
		return nil
	}
	if S(mark, "simulator") == "" || S(mark, "standsIn") == "" {
		return fmt.Errorf("%s: simulated needs simulator (what made the data) and standsIn (the equipment or process it stands in for)", where)
	}
	return nil
}

// markSimulated returns a copy of hw with the simulated block, or hw itself
// when there is none.
func markSimulated(hw, mark Obj) Obj {
	if mark == nil {
		return hw
	}
	out := Obj{}
	for k, v := range hw {
		out[k] = v
	}
	out["simulated"] = mark
	return out
}

// simulatedOf returns a statement's simulated block, or nil.
func simulatedOf(stmt Obj) Obj {
	for _, b := range simulatedBlocks {
		if p := O(stmt, "predicate", b); p != nil && Has(p, "simulated") {
			if m := O(p, "simulated"); m != nil {
				return m
			}
			return Obj{"simulator": "unnamed"}
		}
	}
	if contains(Strs(stmt, "predicate", "verifiedLevels"), SimulatedLevel) {
		return Obj{"simulator": "a verifier's summary of simulated evidence"}
	}
	return nil
}

// simulatedRecords lists the inputs, read from bundle by their names, that
// were made from simulated hardware, each with its simulator. An input that
// is not a DSSE envelope (a review report, a data file) is skipped: the
// checks that named it already read it.
func simulatedRecords(bundle string, inputs []Obj) []string {
	var out []string
	seen := map[string]bool{}
	for _, in := range inputs {
		name := S(in, "name")
		if seen[name] {
			continue
		}
		seen[name] = true
		stmt, err := DecodeEnvelope(filepath.Join(bundle, filepath.FromSlash(name)))
		if err != nil {
			continue
		}
		if m := simulatedOf(stmt); m != nil {
			out = append(out, fmt.Sprintf("%s (%s)", name, S(m, "simulator")))
		}
	}
	return out
}

// acceptsSimulated says whether a policy accepts simulated evidence.
func acceptsSimulated(policy Obj) bool { return Truthy(get(policy, "simulated", "accept")) }

// simulatedCheck refuses simulated inputs unless the policy accepts them,
// and returns the ones it accepted.
func simulatedCheck(bundle string, policy Obj, inputs []Obj, what string) ([]string, error) {
	sim := simulatedRecords(bundle, inputs)
	if len(sim) == 0 || acceptsSimulated(policy) {
		return sim, nil
	}
	return nil, failf("%s: %d record(s) made from simulated hardware, and the policy does not accept simulated evidence (simulated.accept): %s",
		what, len(sim), strings.Join(sim, ", "))
}

// vsaLevels is the verifiedLevels of a VSA: the policy's claims, plus
// HSLSA_SIMULATED when the evidence was simulated.
func vsaLevels(levels any, simulated bool) any {
	if !simulated {
		return levels
	}
	out := []any{}
	for _, l := range Strs(Obj{"v": levels}, "v") {
		if l != SimulatedLevel {
			out = append(out, l)
		}
	}
	return append(out, SimulatedLevel)
}

// refuseSimulatedVSA refuses a VSA that states HSLSA_SIMULATED under a policy
// that does not accept simulated evidence.
func refuseSimulatedVSA(stmt, policy Obj, label string) error {
	if contains(Strs(stmt, "predicate", "verifiedLevels"), SimulatedLevel) && !acceptsSimulated(policy) {
		return failf("%s: summarizes simulated evidence (%s), and the policy does not accept it (simulated.accept)", label, SimulatedLevel)
	}
	return nil
}

// printSimulated says which records were simulated, when the policy accepted them.
func printSimulated(sim []string) {
	if len(sim) == 0 {
		return
	}
	fmt.Printf("made from simulated hardware, accepted by the policy (simulated.accept); every VSA states %s:\n", SimulatedLevel)
	for _, s := range sim {
		fmt.Printf("  %s\n", s)
	}
}
