package nftables

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
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
	if n.Conn == nil {
		return nil, nil
	}
	families := []string{exprs.NFT_FAMILY_INET}
	for _, fam := range families {
		table := n.GetTable(exprs.NFT_CHAIN_FILTER, fam)
		chain := GetChain(exprs.NFT_HOOK_INPUT, table)
		if table == nil {
			log.Error("QueueDNSResponses() Error getting table: %s-filter", fam)
			continue
		}
		if chain == nil {
			log.Error("QueueDNSResponses() Error getting chain: %s-%d", table.Name, table.Family)
			continue
		}

		// nft list ruleset -a
		n.Conn.InsertRule(&nftables.Rule{
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
			UserData: []byte(InterceptionRuleKey),
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
	if n.Conn == nil {
		return nil, fmt.Errorf("nftables QueueConnections: netlink connection not active")
	}
	table := n.GetTable(exprs.NFT_CHAIN_MANGLE, exprs.NFT_FAMILY_INET)
	if table == nil {
		return nil, fmt.Errorf("QueueConnections() Error getting table mangle-inet")
	}
	chain := GetChain(exprs.NFT_HOOK_OUTPUT, table)
	if chain == nil {
		return nil, fmt.Errorf("QueueConnections() Error getting outputChain: output-%s", table.Name)
	}

	n.Conn.AddRule(&nftables.Rule{
		Position: 0,
		Table:    table,
		Chain:    chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
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
		UserData: []byte(InterceptionRuleKey),
	})

	/* nft --debug=netlink add rule inet mangle output tcp flags '& (fin|syn|rst|ack) == syn' queue bypass num 0
	[ meta load l4proto => reg 1 ]
	[ cmp eq reg 1 0x00000006 ]
	[ payload load 1b @ transport header + 13 => reg 1 ]
	[ bitwise reg 1 = ( reg 1 & 0x00000002 ) ^ 0x00000000 ]
	[ cmp neq reg 1 0x00000000 ]
	[ queue num 0 bypass ]

	Intercept packets *only* with the SYN flag set.
	Using 'ct state NEW' causes to intercept packets with other flags set, which
	sometimes means that we receive outbound connections not in the expected order:
	  443:1.1.1.1 -> 192.168.123:12345 (bits ACK, ACK+PSH or SYN+ACK set)
	*/
	n.Conn.AddRule(&nftables.Rule{
		Position: 0,
		Table:    table,
		Chain:    chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       13,
				Len:          1,
			},
			&expr.Bitwise{
				DestRegister:   1,
				SourceRegister: 1,
				Len:            1,
				Mask:           []byte{0x17},
				Xor:            []byte{0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x02},
			},
			&expr.Queue{
				Num:  n.QueueNum,
				Flag: expr.QueueFlagBypass,
			},
		},
		// rule key, to allow get it later by key
		UserData: []byte(InterceptionRuleKey),
	})

	// apply changes
	if !n.Commit() {
		return fmt.Errorf("Error adding interception rule "), nil
	}

	if enable {
		// flush conntrack as soon as netfilter rule is set. This ensures that already-established
		// connections will go to netfilter queue.
		if err := netlink.ConntrackTableFlush(netlink.ConntrackTable); err != nil {
			log.Error("nftables, error flushing ConntrackTable %s", err)
		}
		if err := netlink.ConntrackTableFlush(netlink.ConntrackExpectTable); err != nil {
			log.Error("nftables, error flusing ConntrackExpectTable %s", err)
		}

		// Force established connections to reestablish again.
		daemonNetlink.KillAllSockets()
	}

	return nil, nil
}

// InsertRule inserts a rule at the top of rules list.
func (n *Nft) InsertRule(chain, table, family string, position uint64, exprs *[]expr.Any) error {
	tbl := n.GetTable(table, family)
	if tbl == nil {
		return fmt.Errorf("%s getting table: %s, %s", logTag, table, family)
	}

	chainKey := getChainKey(chain, tbl)
	chn, chok := sysChains.Load(chainKey)
	if !chok {
		return fmt.Errorf("%s getting table: %s, %s", logTag, table, family)
	}

	rule := &nftables.Rule{
		Position: position,
		Table:    tbl,
		Chain:    chn.(*nftables.Chain),
		Exprs:    *exprs,
		UserData: []byte(SystemRuleKey),
	}
	n.Conn.InsertRule(rule)
	if !n.Commit() {
		return fmt.Errorf("rule not added")
	}

	return nil
}

// AddRule adds a rule to the system.
func (n *Nft) AddRule(chain, table, family string, position uint64, key string, exprs *[]expr.Any) (*nftables.Rule, error) {
	tbl := n.GetTable(table, family)
	if tbl == nil {
		return nil, fmt.Errorf("getting %s table: %s, %s", logTag, table, family)
	}

	chainKey := getChainKey(chain, tbl)
	chn, chok := sysChains.Load(chainKey)
	if !chok {
		return nil, fmt.Errorf("getting table: %s, %s", table, family)
	}

	rule := &nftables.Rule{
		Position: position,
		Table:    tbl,
		Chain:    chn.(*nftables.Chain),
		Exprs:    *exprs,
		UserData: []byte(key),
	}
	n.Conn.AddRule(rule)
	if !n.Commit() {
		return nil, fmt.Errorf("adding %s rule", logTag)
	}

	return rule, nil
}

func (n *Nft) delRulesByKey(key string) error {
	chains, err := n.Conn.ListChains()
	if err != nil {
		return fmt.Errorf("error listing nftables chains (%s): %s", key, err)
	}
	for _, c := range chains {
		rules, err := n.Conn.GetRule(c.Table, c)
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
			if err := n.Conn.DelRule(&nftables.Rule{
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
			_, chfound := sysChains.Load(getChainKey(c.Name, c.Table))
			if chfound {
				n.DelChain(c)
			}
		}
	}

	return nil
}

// DelInterceptionRules deletes our interception rules, by key.
func (n *Nft) DelInterceptionRules() {
	n.delRulesByKey(InterceptionRuleKey)
}
