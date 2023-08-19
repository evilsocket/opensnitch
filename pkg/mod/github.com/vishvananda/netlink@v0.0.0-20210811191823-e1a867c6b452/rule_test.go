// +build linux

package netlink

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRuleAddDel(t *testing.T) {
	skipUnlessRoot(t)
	defer setUpNetlinkTest(t)()

	srcNet := &net.IPNet{IP: net.IPv4(172, 16, 0, 1), Mask: net.CIDRMask(16, 32)}
	dstNet := &net.IPNet{IP: net.IPv4(172, 16, 1, 1), Mask: net.CIDRMask(24, 32)}

	rulesBegin, err := RuleList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	rule := NewRule()
	rule.Table = unix.RT_TABLE_MAIN
	rule.Src = srcNet
	rule.Dst = dstNet
	rule.Priority = 5
	rule.OifName = "lo"
	rule.IifName = "lo"
	rule.Invert = true
	rule.Tos = 0x10
	rule.Dport = NewRulePortRange(80, 80)
	rule.Sport = NewRulePortRange(1000, 1024)
	if err := RuleAdd(rule); err != nil {
		t.Fatal(err)
	}

	rules, err := RuleList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != len(rulesBegin)+1 {
		t.Fatal("Rule not added properly")
	}

	// find this rule
	found := ruleExists(rules, *rule)
	if !found {
		t.Fatal("Rule has diffrent options than one added")
	}

	if err := RuleDel(rule); err != nil {
		t.Fatal(err)
	}

	rulesEnd, err := RuleList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(rulesEnd) != len(rulesBegin) {
		t.Fatal("Rule not removed properly")
	}
}

func TestRuleListFiltered(t *testing.T) {
	skipUnlessRoot(t)
	defer setUpNetlinkTest(t)()

	t.Run("IPv4", testRuleListFilteredIPv4)
	t.Run("IPv6", testRuleListFilteredIPv6)
}

func testRuleListFilteredIPv4(t *testing.T) {
	srcNet := &net.IPNet{IP: net.IPv4(172, 16, 0, 1), Mask: net.CIDRMask(16, 32)}
	dstNet := &net.IPNet{IP: net.IPv4(172, 16, 1, 1), Mask: net.CIDRMask(24, 32)}
	runRuleListFiltered(t, FAMILY_V4, srcNet, dstNet)
}

func testRuleListFilteredIPv6(t *testing.T) {
	ip1 := net.ParseIP("fd56:6b58:db28:2913::")
	ip2 := net.ParseIP("fde9:379f:3b35:6635::")

	srcNet := &net.IPNet{IP: ip1, Mask: net.CIDRMask(64, 128)}
	dstNet := &net.IPNet{IP: ip2, Mask: net.CIDRMask(96, 128)}
	runRuleListFiltered(t, FAMILY_V6, srcNet, dstNet)
}

func runRuleListFiltered(t *testing.T, family int, srcNet, dstNet *net.IPNet) {
	defaultRules, _ := RuleList(family)

	tests := []struct {
		name       string
		ruleFilter *Rule
		filterMask uint64
		preRun     func() *Rule // Creates sample rule harness
		postRun    func(*Rule)  // Deletes sample rule harness
		setupWant  func(*Rule) ([]Rule, bool)
	}{
		{
			name:       "returns all rules",
			ruleFilter: nil,
			filterMask: 0,
			preRun:     func() *Rule { return nil },
			postRun:    func(r *Rule) {},
			setupWant: func(_ *Rule) ([]Rule, bool) {
				return defaultRules, false
			},
		},
		{
			name:       "returns one rule filtered by Src",
			ruleFilter: &Rule{Src: srcNet},
			filterMask: RT_FILTER_SRC,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns one rule filtered by Dst",
			ruleFilter: &Rule{Dst: dstNet},
			filterMask: RT_FILTER_DST,
			preRun: func() *Rule {
				r := NewRule()
				r.Dst = dstNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns two rules filtered by Dst",
			ruleFilter: &Rule{Dst: dstNet},
			filterMask: RT_FILTER_DST,
			preRun: func() *Rule {
				r := NewRule()
				r.Dst = dstNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				RuleAdd(r)

				rc := *r // Create almost identical copy
				rc.Src = srcNet
				RuleAdd(&rc)

				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)

				rc := *r // Delete the almost identical copy
				rc.Src = srcNet
				RuleDel(&rc)
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				rs := []Rule{}
				rs = append(rs, *r)

				rc := *r // Append the almost identical copy
				rc.Src = srcNet
				rs = append(rs, rc)

				return rs, false
			},
		},
		{
			name:       "returns one rule filtered by Src when two rules exist",
			ruleFilter: &Rule{Src: srcNet},
			filterMask: RT_FILTER_SRC,
			preRun: func() *Rule {
				r := NewRule()
				r.Dst = dstNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				RuleAdd(r)

				rc := *r // Create almost identical copy
				rc.Src = srcNet
				RuleAdd(&rc)

				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)

				rc := *r // Delete the almost identical copy
				rc.Src = srcNet
				RuleDel(&rc)
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				rs := []Rule{}
				// Do not append `r`

				rc := *r // Append the almost identical copy
				rc.Src = srcNet
				rs = append(rs, rc)

				return rs, false
			},
		},
		{
			name:       "returns rules with specific priority",
			ruleFilter: &Rule{Priority: 5},
			filterMask: RT_FILTER_PRIORITY,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 5
				r.Table = 1
				RuleAdd(r)

				for i := 2; i < 5; i++ {
					rc := *r // Create almost identical copy
					rc.Table = i
					RuleAdd(&rc)
				}

				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)

				for i := 2; i < 5; i++ {
					rc := *r // Delete the almost identical copy
					rc.Table = -1
					RuleDel(&rc)
				}
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				rs := []Rule{}
				rs = append(rs, *r)

				for i := 2; i < 5; i++ {
					rc := *r // Append the almost identical copy
					rc.Table = i
					rs = append(rs, rc)
				}

				return rs, false
			},
		},
		{
			name:       "returns rules filtered by Table",
			ruleFilter: &Rule{Table: 199},
			filterMask: RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority otherwise it's auto-assigned
				r.Table = 199
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Mask",
			ruleFilter: &Rule{Mask: 0x5},
			filterMask: RT_FILTER_MASK,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Table = 1
				r.Mask = 0x5
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Mark",
			ruleFilter: &Rule{Mark: 0xbb},
			filterMask: RT_FILTER_MARK,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority, table, mask otherwise it's auto-assigned
				r.Table = 1
				r.Mask = 0xff
				r.Mark = 0xbb
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Tos",
			ruleFilter: &Rule{Tos: 12},
			filterMask: RT_FILTER_TOS,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority, table, mask otherwise it's auto-assigned
				r.Table = 12
				r.Tos = 12 // Tos must equal table
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.preRun()
			rules, err := RuleListFiltered(family, tt.ruleFilter, tt.filterMask)
			tt.postRun(rule)

			wantRules, wantErr := tt.setupWant(rule)

			if len(wantRules) != len(rules) {
				t.Errorf("Expected len: %d, got: %d", len(wantRules), len(rules))
			} else {
				for i := range wantRules {
					if !ruleEquals(wantRules[i], rules[i]) {
						t.Errorf("Rules mismatch, want %v, got %v", wantRules[i], rules[i])
					}
				}
			}

			if (err != nil) != wantErr {
				t.Errorf("Error expectation not met, want %v, got %v", (err != nil), wantErr)
			}
		})
	}
}

func ruleExists(rules []Rule, rule Rule) bool {
	for i := range rules {
		if ruleEquals(rules[i], rule) {
			return true
		}
	}

	return false
}

func ruleEquals(a, b Rule) bool {
	return a.Table == b.Table &&
		((a.Src == nil && b.Src == nil) ||
			(a.Src != nil && b.Src != nil && a.Src.String() == b.Src.String())) &&
		((a.Dst == nil && b.Dst == nil) ||
			(a.Dst != nil && b.Dst != nil && a.Dst.String() == b.Dst.String())) &&
		a.OifName == b.OifName &&
		a.Priority == b.Priority &&
		a.IifName == b.IifName &&
		a.Invert == b.Invert &&
		a.Tos == b.Tos
}
