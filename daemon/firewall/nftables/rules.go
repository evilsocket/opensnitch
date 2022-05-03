package nftables

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// QueueDNSResponses redirects DNS responses to us, in order to keep a cache
// of resolved domains.
// This rule must be added in top of the system rules, otherwise it may get bypassed.
// nft insert rule ip filter input udp sport 53 queue num 0 bypass
func (n *Nft) QueueDNSResponses(enable bool, logError bool) (error, error) {
	if n.conn == nil {
		return nil, nil
	}
	families := []string{exprs.NFT_FAMILY_INET}
	for _, fam := range families {
		table := getTable(exprs.NFT_CHAIN_FILTER, fam)
		chain := getChain(exprs.NFT_HOOK_INPUT, table)
		if table == nil {
			log.Error("QueueDNSResponses() Error getting table: %s-filter", fam)
			continue
		}
		if chain == nil {
			log.Error("QueueDNSResponses() Error getting chain: %s-%d", table.Name, table.Family)
			continue
		}

		// nft list ruleset -a
		n.conn.InsertRule(&nftables.Rule{
			Position: 0,
			Table:    table,
			Chain:    chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{unix.IPPROTO_UDP},
				},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       0,
					Len:          2,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     binaryutil.BigEndian.PutUint16(uint16(53)),
				},
				&expr.Queue{
					Num:  n.QueueNum,
					Flag: expr.QueueFlagBypass,
				},
			},
			// rule key, to allow get it later by key
			UserData: []byte(interceptionRuleKey),
		})
	}
	// apply changes
	if !n.Commit() {
		return fmt.Errorf("Error adding DNS interception rules"), nil
	}

	return nil, nil
}

// QueueConnections inserts the firewall rule which redirects connections to us.
// Connections are queued until the user denies/accept them, or reaches a timeout.
// This rule must be added at the end of all the other rules, that way we can add
// rules above this one to exclude a service/app from being intercepted.
// nft insert rule ip mangle OUTPUT ct state new queue num 0 bypass
func (n *Nft) QueueConnections(enable bool, logError bool) (error, error) {
	if n.conn == nil {
		return nil, fmt.Errorf("nftables QueueConnections: netlink connection not active")
	}
	table := getTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
	if table == nil {
		return nil, fmt.Errorf("QueueConnections() Error getting table mangle-inet")
	}
	chain := getChain(exprs.NFT_HOOK_OUTPUT, table)
	if chain == nil {
		return nil, fmt.Errorf("QueueConnections() Error getting outputChain: output-%s", table.Name)
	}

	n.conn.AddRule(&nftables.Rule{
		Position: 0,
		Table:    table,
		Chain:    chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Queue{
				Num:  n.QueueNum,
				Flag: expr.QueueFlagBypass,
			},
		},
		// rule key, to allow get it later by key
		UserData: []byte(interceptionRuleKey),
	})
	// apply changes
	if !n.Commit() {
		return fmt.Errorf("Error adding interception rule "), nil
	}

	if enable {
		// flush conntrack as soon as netfilter rule is set. This ensures that already-established
		// connections will go to netfilter queue.
		if err := netlink.ConntrackTableFlush(netlink.ConntrackTable); err != nil {
			log.Error("nftables, error in ConntrackTableFlush %s", err)
		}
	}

	return nil, nil
}

func (n *Nft) insertRule(chain, table, family string, position uint64, exprs *[]expr.Any) error {
	tbl := getTable(table, family)
	if tbl == nil {
		return fmt.Errorf("%s addRule, Error getting table: %s, %s", logTag, table, family)
	}

	chainKey := getChainKey(chain, tbl)
	chn := sysChains[chainKey]

	rule := &nftables.Rule{
		Position: position,
		Table:    tbl,
		Chain:    chn,
		Exprs:    *exprs,
		UserData: []byte(systemRuleKey),
	}
	n.conn.InsertRule(rule)
	if !n.Commit() {
		return fmt.Errorf("%s Error adding rule", logTag)
	}

	return nil
}

func (n *Nft) addRule(chain, table, family string, position uint64, exprs *[]expr.Any) error {
	tbl := getTable(table, family)
	if tbl == nil {
		return fmt.Errorf("%s addRule, Error getting table: %s, %s", logTag, table, family)
	}

	chainKey := getChainKey(chain, tbl)
	chn := sysChains[chainKey]

	rule := &nftables.Rule{
		Position: position,
		Table:    tbl,
		Chain:    chn,
		Exprs:    *exprs,
		UserData: []byte(systemRuleKey),
	}
	n.conn.AddRule(rule)
	if !n.Commit() {
		return fmt.Errorf("%s Error adding rule", logTag)
	}

	return nil
}

func (n *Nft) delRulesByKey(key string) error {
	chains, err := n.conn.ListChains()
	if err != nil {
		return fmt.Errorf("error listing nftables chains (%s): %s", key, err)
	}
	for _, c := range chains {
		rules, err := n.conn.GetRule(c.Table, c)
		if err != nil {
			log.Warning("Error listing rules (%s): %s", key, err)
			continue
		}
		delRules := 0
		for _, r := range rules {
			if string(r.UserData) != key {
				continue
			}
			// just passing the r object doesn't work.
			if err := n.conn.DelRule(&nftables.Rule{
				Table:  c.Table,
				Chain:  c,
				Handle: r.Handle,
			}); err != nil {
				log.Warning("[nftables] error deleting rule (%s): %s", key, err)
				continue
			}
			delRules++
		}
		if delRules > 0 {
			if !n.Commit() {
				log.Warning("%s error deleting rules: %s", logTag, err)
			}
		}
		if len(rules) == 0 || len(rules) == delRules {
			if _, ok := sysChains[getChainKey(c.Name, c.Table)]; ok {
				n.delChain(c)
			}
		}
	}

	return nil
}

func (n *Nft) delInterceptionRules() {
	n.delRulesByKey(interceptionRuleKey)
}
