// +build linux

package netlink

import (
	"bytes"
	"net"
	"testing"
)

const zeroCIDR = "0.0.0.0/0"

func TestXfrmPolicyAddUpdateDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	policy := getPolicy()
	if err := XfrmPolicyAdd(policy); err != nil {
		t.Fatal(err)
	}
	policies, err := XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}

	if len(policies) != 1 {
		t.Fatal("Policy not added properly")
	}

	if !comparePolicies(policy, &policies[0]) {
		t.Fatalf("unexpected policy returned.\nExpected: %v.\nGot %v", policy, policies[0])
	}

	if policies[0].Ifindex != 0 {
		t.Fatalf("default policy has a non-zero interface index.\nGot %d", policies[0].Ifindex)
	}

	if policies[0].Ifid != 0 {
		t.Fatalf("default policy has non-zero if_id.\nGot %d", policies[0].Ifid)
	}

	if policies[0].Action != XFRM_POLICY_ALLOW {
		t.Fatalf("default policy has non-allow action.\nGot %s", policies[0].Action)
	}

	// Look for a specific policy
	sp, err := XfrmPolicyGet(policy)
	if err != nil {
		t.Fatal(err)
	}

	if !comparePolicies(policy, sp) {
		t.Fatalf("unexpected policy returned")
	}

	// Modify the policy
	policy.Priority = 100
	if err := XfrmPolicyUpdate(policy); err != nil {
		t.Fatal(err)
	}
	sp, err = XfrmPolicyGet(policy)
	if err != nil {
		t.Fatal(err)
	}
	if sp.Priority != 100 {
		t.Fatalf("failed to modify the policy")
	}

	if err = XfrmPolicyDel(policy); err != nil {
		t.Fatal(err)
	}

	policies, err = XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Fatal("Policy not removed properly")
	}

	// Src and dst are not mandatory field. Creation should succeed
	policy.Src = nil
	policy.Dst = nil
	if err = XfrmPolicyAdd(policy); err != nil {
		t.Fatal(err)
	}

	sp, err = XfrmPolicyGet(policy)
	if err != nil {
		t.Fatal(err)
	}

	if !comparePolicies(policy, sp) {
		t.Fatalf("unexpected policy returned")
	}

	if err = XfrmPolicyDel(policy); err != nil {
		t.Fatal(err)
	}

	if _, err := XfrmPolicyGet(policy); err == nil {
		t.Fatalf("Unexpected success")
	}
}

func TestXfrmPolicyFlush(t *testing.T) {
	defer setUpNetlinkTest(t)()

	p1 := getPolicy()
	if err := XfrmPolicyAdd(p1); err != nil {
		t.Fatal(err)
	}

	p1.Dir = XFRM_DIR_IN
	s := p1.Src
	p1.Src = p1.Dst
	p1.Dst = s
	if err := XfrmPolicyAdd(p1); err != nil {
		t.Fatal(err)
	}

	policies, err := XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("unexpected number of policies: %d", len(policies))
	}

	if err := XfrmPolicyFlush(); err != nil {
		t.Fatal(err)
	}

	policies, err = XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Fatalf("unexpected number of policies: %d", len(policies))
	}

}

func TestXfrmPolicyBlockWithIfindex(t *testing.T) {
	defer setUpNetlinkTest(t)()

	pBlock := getPolicy()
	pBlock.Action = XFRM_POLICY_BLOCK
	pBlock.Ifindex = 1 // loopback interface
	if err := XfrmPolicyAdd(pBlock); err != nil {
		t.Fatal(err)
	}
	policies, err := XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("unexpected number of policies: %d", len(policies))
	}
	if !comparePolicies(pBlock, &policies[0]) {
		t.Fatalf("unexpected policy returned.\nExpected: %v.\nGot %v", pBlock, policies[0])
	}
	if err = XfrmPolicyDel(pBlock); err != nil {
		t.Fatal(err)
	}
}

func TestXfrmPolicyWithIfid(t *testing.T) {
	minKernelRequired(t, 4, 19)
	defer setUpNetlinkTest(t)()

	pol := getPolicy()
	pol.Ifid = 54321

	if err := XfrmPolicyAdd(pol); err != nil {
		t.Fatal(err)
	}
	policies, err := XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("unexpected number of policies: %d", len(policies))
	}
	if !comparePolicies(pol, &policies[0]) {
		t.Fatalf("unexpected policy returned.\nExpected: %v.\nGot %v", pol, policies[0])
	}
	if err = XfrmPolicyDel(&policies[0]); err != nil {
		t.Fatal(err)
	}
}

func TestXfrmPolicyWithOptional(t *testing.T) {
	minKernelRequired(t, 4, 19)
	defer setUpNetlinkTest(t)()

	pol := getPolicy()
	pol.Tmpls[0].Optional = 1

	if err := XfrmPolicyAdd(pol); err != nil {
		t.Fatal(err)
	}
	policies, err := XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("unexpected number of policies: %d", len(policies))
	}
	if !comparePolicies(pol, &policies[0]) {
		t.Fatalf("unexpected policy returned.\nExpected: %v.\nGot %v", pol, policies[0])
	}
	if err = XfrmPolicyDel(&policies[0]); err != nil {
		t.Fatal(err)
	}
}

func comparePolicies(a, b *XfrmPolicy) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	// Do not check Index which is assigned by kernel
	return a.Dir == b.Dir && a.Priority == b.Priority &&
		compareIPNet(a.Src, b.Src) && compareIPNet(a.Dst, b.Dst) &&
		a.Action == b.Action && a.Ifindex == b.Ifindex &&
		a.Mark.Value == b.Mark.Value && a.Mark.Mask == b.Mark.Mask &&
		a.Ifid == b.Ifid && compareTemplates(a.Tmpls, b.Tmpls)
}

func compareTemplates(a, b []XfrmPolicyTmpl) bool {
	if len(a) != len(b) {
		return false
	}
	for i, ta := range a {
		tb := b[i]
		if !ta.Dst.Equal(tb.Dst) || !ta.Src.Equal(tb.Src) || ta.Spi != tb.Spi ||
			ta.Mode != tb.Mode || ta.Reqid != tb.Reqid || ta.Proto != tb.Proto ||
			ta.Optional != tb.Optional {
			return false
		}
	}
	return true
}

func compareIPNet(a, b *net.IPNet) bool {
	if a == b {
		return true
	}
	// For unspecified src/dst parseXfrmPolicy would set the zero address cidr
	if (a == nil && b.String() == zeroCIDR) || (b == nil && a.String() == zeroCIDR) {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask)
}

func getPolicy() *XfrmPolicy {
	src, _ := ParseIPNet("127.1.1.1/32")
	dst, _ := ParseIPNet("127.1.1.2/32")
	policy := &XfrmPolicy{
		Src:     src,
		Dst:     dst,
		Proto:   17,
		DstPort: 1234,
		SrcPort: 5678,
		Dir:     XFRM_DIR_OUT,
		Mark: &XfrmMark{
			Value: 0xabff22,
			Mask:  0xffffffff,
		},
		Priority: 10,
	}
	tmpl := XfrmPolicyTmpl{
		Src:   net.ParseIP("127.0.0.1"),
		Dst:   net.ParseIP("127.0.0.2"),
		Proto: XFRM_PROTO_ESP,
		Mode:  XFRM_MODE_TUNNEL,
		Spi:   0xabcdef99,
	}
	policy.Tmpls = append(policy.Tmpls, tmpl)
	return policy
}
