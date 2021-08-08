package nftables

import (
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (n *Nft) addGlobalTables() error {
	filter := n.conn.AddTable(filterTable)
	filter6 := n.conn.AddTable(filterTable6)

	mangle := n.conn.AddTable(mangleTable)
	mangle6 := n.conn.AddTable(mangleTable6)
	n.mangleTables = []*nftables.Table{mangle, mangle6}
	n.filterTables = []*nftables.Table{filter, filter6}

	// apply changes
	if err := n.conn.Flush(); err != nil {
		return err
	}

	return nil
}

// TODO: add more parameters, make it more generic
func (n *Nft) addChain(name string, table *nftables.Table, prio nftables.ChainPriority, ctype nftables.ChainType, hook nftables.ChainHook) *nftables.Chain {
	// nft list chains
	return n.conn.AddChain(&nftables.Chain{
		Name:     name,
		Table:    table,
		Type:     ctype,
		Hooknum:  hook,
		Priority: prio,
		//Policy:   nftables.ChainPolicyDrop
	})
}

func (n *Nft) addGlobalChains() error {
	// nft list tables
	for _, table := range n.mangleTables {
		n.outputChains[table] = n.addChain(outputChain, table, nftables.ChainPriorityMangle, nftables.ChainTypeRoute, nftables.ChainHookOutput)
	}
	for _, table := range n.filterTables {
		n.inputChains[table] = n.addChain(inputChain, table, nftables.ChainPriorityFilter, nftables.ChainTypeFilter, nftables.ChainHookInput)
	}
	// apply changes
	if err := n.conn.Flush(); err != nil {
		log.Warning("Error adding nftables mangle tables:", err)
	}

	return nil
}

// QueueDNSResponses redirects DNS responses to us, in order to keep a cache
// of resolved domains.
// nft insert rule ip filter input udp sport 53 queue num 0 bypass
func (n *Nft) QueueDNSResponses(enable bool, logError bool) (error, error) {
	if n.conn == nil {
		return nil, nil
	}
	for _, table := range n.filterTables {
		// nft list ruleset -a
		n.conn.InsertRule(&nftables.Rule{
			Position: 0,
			Table:    table,
			Chain:    n.inputChains[table],
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
			UserData: []byte(fwKey),
		})
	}
	// apply changes
	if err := n.conn.Flush(); err != nil {
		return err, nil
	}

	return nil, nil
}

// QueueConnections inserts the firewall rule which redirects connections to us.
// They are queued until the user denies/accept them, or reaches a timeout.
// nft insert rule ip mangle OUTPUT ct state new queue num 0 bypass
func (n *Nft) QueueConnections(enable bool, logError bool) (error, error) {
	if n.conn == nil {
		return nil, nil
	}
	if enable {
		// flush conntrack as soon as netfilter rule is set. This ensures that already-established
		// connections will go to netfilter queue.
		if err := netlink.ConntrackTableFlush(netlink.ConntrackTable); err != nil {
			log.Error("nftables, error in ConntrackTableFlush %s", err)
		}
	}

	for _, table := range n.mangleTables {
		n.conn.InsertRule(&nftables.Rule{
			Position: 0,
			Table:    table,
			Chain:    n.outputChains[table],
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
			UserData: []byte(fwKey),
		})
	}
	// apply changes
	if err := n.conn.Flush(); err != nil {
		return err, nil
	}

	return nil, nil
}

func (n *Nft) delInterceptionRules() {
	n.delRulesByKey(fwKey)
}

func (n *Nft) delRulesByKey(key string) {
	chains, err := n.conn.ListChains()
	if err != nil {
		log.Warning("nftables, error listing chains: %s", err)
		return
	}
	commit := false
	for _, c := range chains {
		deletedRules := 0
		rules, err := n.conn.GetRule(c.Table, c)
		if err != nil {
			log.Warning("nftables, error listing rules: %s", err)
			continue
		}

		for _, r := range rules {
			if string(r.UserData) == key {
				// just passing the rule object doesn't work.
				if err := n.conn.DelRule(&nftables.Rule{
					Table:  c.Table,
					Chain:  c,
					Handle: r.Handle,
				}); err != nil {
					log.Warning("nftables, error deleting interception rule: %s", err)
					continue
				}
				deletedRules++
				commit = true
			}
		}
		if deletedRules == len(rules) {
			n.conn.DelTable(c.Table)
		}
	}
	if commit {
		if err := n.conn.Flush(); err != nil {
			log.Warning("nftables, error applying interception rules: %s", err)
		}
	}

	return
}
