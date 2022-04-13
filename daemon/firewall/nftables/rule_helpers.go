package nftables

import (
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// rules examples: https://github.com/google/nftables/blob/master/nftables_test.go

func (n *Nft) buildICMPRule(table, family string, icmpOptions []*config.ExprValues) *[]expr.Any {
	tbl := getTable(table, family)
	if tbl == nil {
		return nil
	}
	offset := uint32(0)
	setType := nftables.TypeICMPType

	exprICMP, _ := exprs.NewExprProtocol(exprs.NFT_PROTO_ICMP)
	ICMPrule := []expr.Any{}
	ICMPrule = append(ICMPrule, *exprICMP...)

	ICMPtemp := []expr.Any{}
	setElements := []nftables.SetElement{}
	for _, icmp := range icmpOptions {
		switch icmp.Key {
		case exprs.NFT_ICMP_TYPE:
			exprCmp := &expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{exprs.GetICMPType(icmp.Value)},
			}
			ICMPtemp = append(ICMPtemp, []expr.Any{exprCmp}...)

			// fill setElements. If there're more than 1 icmp type we'll use it later
			setElements = append(setElements,
				[]nftables.SetElement{
					{
						Key: []byte{exprs.GetICMPType(icmp.Value)},
					},
				}...)
		case exprs.NFT_ICMP_CODE:
			// TODO
			offset = 1
		}
	}

	ICMPrule = append(ICMPrule, []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       offset, // 0 type, 1 code
			Len:          1,
		},
	}...)

	if len(setElements) == 1 {
		ICMPrule = append(ICMPrule, ICMPtemp...)
	} else {
		set := &nftables.Set{
			Anonymous: true,
			Constant:  true,
			Table:     tbl,
			KeyType:   setType,
		}
		if err := n.conn.AddSet(set, setElements); err != nil {
			log.Warning("%s AddSet() error: %s", logTag, err)
			return nil
		}
		sysSets = append(sysSets, []*nftables.Set{set}...)

		ICMPrule = append(ICMPrule, []expr.Any{
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        set.Name,
				SetID:          set.ID,
			}}...)
	}

	return &ICMPrule
}

func (n *Nft) buildConntrackRule(table, chain string, ctOptions []*config.ExprValues) *[]expr.Any {
	exprList := []expr.Any{}

	setMark := false
	for _, ctOption := range ctOptions {
		switch ctOption.Key {
		// we expect to have multiple "state" keys:
		// { "state": "established", "state": "related" }
		case exprs.NFT_CT_STATE:
			ctExprState, err := exprs.NewExprCtState(ctOptions)
			if err != nil {
				log.Warning("%s ct set state error: %s", logTag, err)
				return nil
			}
			exprList = append(exprList, *ctExprState...)
			exprList = append(exprList,
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			)
			// we only need to iterate once here
			goto Exit
		case exprs.NFT_CT_SET_MARK:
			setMark = true
		case exprs.NFT_CT_MARK:
			ctExprMark, err := exprs.NewExprCtMark(setMark, ctOption.Value)
			if err != nil {
				log.Warning("%s ct mark error: %s", logTag, err)
				return nil
			}
			exprList = append(exprList, *ctExprMark...)
			goto Exit
		default:
			log.Warning("%s invalid conntrack option: %s", logTag, ctOption)
			return nil
		}
	}

Exit:
	return &exprList
}

func (n *Nft) buildProtocolRule(table, family, ports string, cmpOp *expr.CmpOp) *[]expr.Any {
	tbl := getTable(table, family)
	if tbl == nil {
		return nil
	}
	exprList := []expr.Any{}
	if strings.Index(ports, ",") != -1 {
		set := &nftables.Set{
			Anonymous: true,
			Constant:  true,
			Table:     tbl,
			KeyType:   nftables.TypeInetService,
		}
		setElements := exprs.NewExprPortSet(ports)
		if err := n.conn.AddSet(set, *setElements); err != nil {
			log.Warning("%s AddSet() error: %s", logTag, err)
		}
		exprList = append(exprList, &expr.Lookup{
			SourceRegister: 1,
			SetName:        set.Name,
			SetID:          set.ID,
		})
		sysSets = append(sysSets, []*nftables.Set{set}...)
	} else if strings.Index(ports, "-") != -1 {
		exprList = append(exprList, *exprs.NewExprPortRange(ports)...)
	} else {
		exprList = append(exprList, *exprs.NewExprPort(ports, cmpOp)...)
	}

	return &exprList
}
