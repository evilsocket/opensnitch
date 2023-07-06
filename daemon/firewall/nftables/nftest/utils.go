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
