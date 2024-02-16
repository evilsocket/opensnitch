package nftest

import (
	"testing"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// AddTestRule adds a generic table, chain and rule with the given expression.
func AddTestRule(t *testing.T, conn *nftables.Conn, exp *[]expr.Any) (*nftables.Rule, *nftables.Chain) {

	_, err := Fw.AddTable("yyy", exprs.NFT_FAMILY_INET)
	if err != nil {
		t.Errorf("pre step add_table() yyy-inet failed: %s", err)
		return nil, nil
	}
	chn := Fw.AddChain(
		exprs.NFT_HOOK_INPUT,
		"yyy",
		exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityFilter,
		nftables.ChainTypeFilter,
		nftables.ChainHookInput,
		nftables.ChainPolicyAccept)
	if chn == nil {
		t.Error("pre step add_chain() input-yyy-inet failed")
		return nil, nil
	}
	//nft.Commit()

	r, err := Fw.AddRule(
		exprs.NFT_HOOK_INPUT, "yyy", exprs.NFT_FAMILY_INET,
		0,
		"key-yyy",
		exp)
	if err != nil {
		t.Errorf("Error adding rule: %s", err)
		return nil, nil
	}
	t.Logf("Rule: %+v", r)

	return r, chn
}

// AddTestSNATRule adds a generic table, chain and rule with the given expression.
func AddTestSNATRule(t *testing.T, conn *nftables.Conn, exp *[]expr.Any) (*nftables.Rule, *nftables.Chain) {

	_, err := Fw.AddTable("uuu", exprs.NFT_FAMILY_INET)
	if err != nil {
		t.Errorf("pre step add_table() uuu-inet failed: %s", err)
		return nil, nil
	}
	chn := Fw.AddChain(
		exprs.NFT_HOOK_POSTROUTING,
		"uuu",
		exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityNATSource,
		nftables.ChainTypeNAT,
		nftables.ChainHookPostrouting,
		nftables.ChainPolicyAccept)
	if chn == nil {
		t.Error("pre step add_chain() input-uuu-inet failed")
		return nil, nil
	}
	//nft.Commit()

	r, err := Fw.AddRule(
		exprs.NFT_HOOK_POSTROUTING, "uuu", exprs.NFT_FAMILY_INET,
		0,
		"key-uuu",
		exp)
	if err != nil {
		t.Errorf("Error adding rule: %s", err)
		return nil, nil
	}
	t.Logf("Rule: %+v", r)

	return r, chn
}

// AddTestDNATRule adds a generic table, chain and rule with the given expression.
func AddTestDNATRule(t *testing.T, conn *nftables.Conn, exp *[]expr.Any) (*nftables.Rule, *nftables.Chain) {

	_, err := Fw.AddTable("iii", exprs.NFT_FAMILY_INET)
	if err != nil {
		t.Errorf("pre step add_table() iii-inet failed: %s", err)
		return nil, nil
	}
	chn := Fw.AddChain(
		exprs.NFT_HOOK_PREROUTING,
		"iii",
		exprs.NFT_FAMILY_INET,
		nftables.ChainPriorityNATDest,
		nftables.ChainTypeNAT,
		nftables.ChainHookPrerouting,
		nftables.ChainPolicyAccept)
	if chn == nil {
		t.Error("pre step add_chain() input-iii-inet failed")
		return nil, nil
	}
	//nft.Commit()

	r, err := Fw.AddRule(
		exprs.NFT_HOOK_PREROUTING, "iii", exprs.NFT_FAMILY_INET,
		0,
		"key-iii",
		exp)
	if err != nil {
		t.Errorf("Error adding rule: %s", err)
		return nil, nil
	}
	t.Logf("Rule: %+v", r)

	return r, chn
}
