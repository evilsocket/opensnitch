package nftables

import (
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// nftables rules are composed of expressions, for example:
// tcp dport 443 ip daddr 192.168.1.1
// \-----------/ \------------------/
// with these format:
// keyword1<SPACE>keyword2<SPACE>value...
//
// here we parse the expression, and based on keyword1, we build the rule with the given options.
//
// If the rule has multiple values (tcp dport 80,443,8080), no spaces are allowed,
// and the separator is a ",", instead of the format { 80, 443, 8080 }
//
// In order to debug invalid expressions, or how to build new ones, use the following command:
// # nft --debug netlink  add rule filter output mark set 1
// ip filter output
//  [ immediate reg 1 0x00000001 ]
//  [ meta set mark with reg 1 ]
//
// Debugging added rules:
// nft --debug netlink list ruleset
//
// https://wiki.archlinux.org/title/Nftables#Expressions
// https://wiki.nftables.org/wiki-nftables/index.php/Building_rules_through_expressions
func (n *Nft) parseExpression(table, chain, family string, expression *config.Expressions) *[]expr.Any {
	var exprList []expr.Any
	cmpOp := exprs.NewOperator(expression.Statement.Op)

	switch expression.Statement.Name {

	case exprs.NFT_CT:
		exprCt := n.buildConntrackRule(expression.Statement.Values, &cmpOp)
		if exprCt == nil {
			log.Warning("%s Ct statement error", logTag)
			return nil
		}
		exprList = append(exprList, *exprCt...)

	case exprs.NFT_META:
		metaExpr, err := exprs.NewExprMeta(expression.Statement.Values, &cmpOp)
		if err != nil {
			log.Warning("%s meta statement error: %s", logTag, err)
			return nil
		}

		for _, exprValue := range expression.Statement.Values {
			switch exprValue.Key {
			case exprs.NFT_META_L4PROTO:
				l4rule, err := n.buildL4ProtoRule(table, family, exprValue.Value, &cmpOp)
				if err != nil {
					log.Warning("%s meta.l4proto statement error: %s", logTag, err)
					return nil
				}
				*metaExpr = append(*metaExpr, *l4rule...)
			case exprs.NFT_DPORT, exprs.NFT_SPORT:
				exprPDir, err := exprs.NewExprPortDirection(exprValue.Key)
				if err != nil {
					log.Warning("%s ports statement error: %s", logTag, err)
					return nil
				}
				*metaExpr = append(*metaExpr, []expr.Any{exprPDir}...)
				portsRule, err := n.buildPortsRule(table, family, exprValue.Value, &cmpOp)
				if err != nil {
					log.Warning("%s meta.l4proto.ports statement error: %s", logTag, err)
					return nil
				}
				*metaExpr = append(*metaExpr, *portsRule...)
			}
		}
		return metaExpr

	case exprs.NFT_ETHER:
		etherExpr, err := exprs.NewExprEther(expression.Statement.Values)
		if err != nil {
			log.Warning("%s ether statement error: %s", logTag, err)
			return nil
		}
		return etherExpr

	// TODO: support iif, oif
	case exprs.NFT_IIFNAME, exprs.NFT_OIFNAME:
		isOut := expression.Statement.Name == exprs.NFT_OIFNAME
		iface := expression.Statement.Values[0].Key
		if iface == "" {
			log.Warning("%s network interface statement error: %s", logTag, expression.Statement.Name)
			return nil
		}
		exprList = append(exprList, *exprs.NewExprIface(iface, isOut, cmpOp)...)

	case exprs.NFT_FAMILY_IP, exprs.NFT_FAMILY_IP6:
		exprIP, err := exprs.NewExprIP(family, expression.Statement.Values, cmpOp)
		if err != nil {
			log.Warning("%s addr statement error: %s", logTag, err)
			return nil
		}
		exprList = append(exprList, *exprIP...)

	case exprs.NFT_PROTO_ICMP, exprs.NFT_PROTO_ICMPv6:
		exprICMP := n.buildICMPRule(table, family, expression.Statement.Name, expression.Statement.Values)
		if exprICMP == nil {
			log.Warning("%s icmp statement error", logTag)
			return nil
		}
		exprList = append(exprList, *exprICMP...)

	case exprs.NFT_LOG:
		exprLog, err := exprs.NewExprLog(expression.Statement)
		if err != nil {
			log.Warning("%s log statement error", logTag)
			return nil
		}
		exprList = append(exprList, *exprLog...)

	case exprs.NFT_LIMIT:
		exprLimit, err := exprs.NewExprLimit(expression.Statement)
		if err != nil {
			log.Warning("%s %s", logTag, err)
			return nil
		}
		exprList = append(exprList, *exprLimit...)

	case exprs.NFT_PROTO_UDP, exprs.NFT_PROTO_TCP, exprs.NFT_PROTO_UDPLITE, exprs.NFT_PROTO_SCTP, exprs.NFT_PROTO_DCCP:
		exprProto, err := exprs.NewExprProtocol(expression.Statement.Name)
		if err != nil {
			log.Warning("%s proto statement error: %s", logTag, err)
			return nil
		}
		exprList = append(exprList, *exprProto...)

		for _, exprValue := range expression.Statement.Values {

			switch exprValue.Key {
			case exprs.NFT_DPORT, exprs.NFT_SPORT:
				exprPDir, err := exprs.NewExprPortDirection(exprValue.Key)
				if err != nil {
					log.Warning("%s ports statement error: %s", logTag, err)
					return nil
				}
				exprList = append(exprList, []expr.Any{exprPDir}...)
				portsRule, err := n.buildPortsRule(table, family, exprValue.Value, &cmpOp)
				if err != nil {
					log.Warning("%s proto.ports statement error: %s", logTag, err)
					return nil
				}
				exprList = append(exprList, *portsRule...)
			}

		}

	case exprs.NFT_QUOTA:
		exprQuota, err := exprs.NewQuota(expression.Statement.Values)
		if err != nil {
			log.Warning("%s quota statement error: %s", logTag, err)
			return nil
		}

		exprList = append(exprList, *exprQuota...)

	case exprs.NFT_NOTRACK:
		exprList = append(exprList, *exprs.NewNoTrack()...)

	case exprs.NFT_COUNTER:
		defaultCounterName := "opensnitch"
		counterObj := &nftables.CounterObj{
			Table:   &nftables.Table{Name: table, Family: nftables.TableFamilyIPv4},
			Name:    defaultCounterName,
			Bytes:   0,
			Packets: 0,
		}
		for _, counterOption := range expression.Statement.Values {
			switch counterOption.Key {
			case exprs.NFT_COUNTER_NAME:
				defaultCounterName = counterOption.Value
				counterObj.Name = defaultCounterName
			case exprs.NFT_COUNTER_BYTES:
				// TODO: allow to set initial bytes/packets?
				counterObj.Bytes = 1
			case exprs.NFT_COUNTER_PACKETS:
				counterObj.Packets = 1
			}
		}
		n.Conn.AddObj(counterObj)
		exprList = append(exprList, *exprs.NewExprCounter(defaultCounterName)...)
	}

	return &exprList
}
