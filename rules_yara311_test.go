// +build !yara3.11

package yara

import (
	"strings"
	"testing"
)

func TestResetRulesCosts(t *testing.T) {
	r := makeRules(t, `
		 rule slow { strings: $a = /a.*b/ condition: $a }`)
	_, err := r.ScanMem([]byte(strings.Repeat("a", 1000)), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, cost := range r.GetMostCostlyRules(1) {
		if cost.Cost == 0 {
			t.Fatal("Cost shouldn't be zero")
		}
	}
	r.ResetCosts()
	for _, cost := range r.GetMostCostlyRules(1) {
		if cost.Cost != 0 {
			t.Fatal("Cost should be zero")
		}
	}
}
