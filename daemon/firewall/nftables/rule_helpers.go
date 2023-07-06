package nftables

import (
	"fmt"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// rules examples: https://github.com/google/nftables/blob/master/nftables_test.go

func (n *Nft) buildICMPRule(table, family string, icmpProtoVersion string, icmpOptions []*config.ExprValues) *[]expr.Any {
	tbl := n.GetTable(table, family)
	if tbl == nil {
		return nil
	}
	offset := uint32(0)
	icmpType := uint8(0)
	setType := nftables.SetDatatype{}

	switch icmpProtoVersion {
	case exprs.NFT_PROTO_ICMP:
		setType = nftables.TypeICMPType
	case exprs.NFT_PROTO_ICMPv6:
		setType = nftables.TypeICMP6Type
	default:
		return nil
	}

	exprICMP, _ := exprs.NewExprProtocol(icmpProtoVersion)
	ICMPrule := []expr.Any{}
	ICMPrule = append(ICMPrule, *exprICMP...)

	ICMPtemp := []expr.Any{}
	setElements := []nftables.SetElement{}
	for _, icmp := range icmpOptions {
		switch icmp.Key {
		case exprs.NFT_ICMP_TYPE:
			icmpTypeList := strings.Split(icmp.Value, ",")
			for _, icmpTypeStr := range icmpTypeList {
				if exprs.NFT_PROTO_ICMPv6 == icmpProtoVersion {
					icmpType = exprs.GetICMPv6Type(icmpTypeStr)
				} else {
					icmpType = exprs.GetICMPType(icmpTypeStr)
				}
				exprCmp := &expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     []byte{icmpType},
				}
				ICMPtemp = append(ICMPtemp, []expr.Any{exprCmp}...)

				// fill setElements. If there're more than 1 icmp type we'll use it later
				setElements = append(setElements,
					[]nftables.SetElement{
						{
							Key: []byte{icmpType},
						},
					}...)
			}
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
		if err := n.Conn.AddSet(set, setElements); err != nil {
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

func (n *Nft) buildConntrackRule(ctOptions []*config.ExprValues, cmpOp *expr.CmpOp) *[]expr.Any {
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
			ctExprMark, err := exprs.NewExprCtMark(setMark, ctOption.Value, cmpOp)
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

// buildL4ProtoRule helper builds a new protocol rule to match ports and protocols.
//
// nft --debug=netlink add rule filter input meta l4proto { tcp, udp }  th dport 53
//	__set%d filter 3 size 2
//	__set%d filter 0
//		element 00000006  : 0 [end]	element 00000011  : 0 [end]
//	ip filter input
//	  [ meta load l4proto => reg 1 ]
//	  [ lookup reg 1 set __set%d ]
//	  [ payload load 2b @ transport header + 2 => reg 1 ]
//	  [ cmp eq reg 1 0x00003500 ]
func (n *Nft) buildL4ProtoRule(table, family, l4prots string, cmpOp *expr.CmpOp) (*[]expr.Any, error) {
	tbl := n.GetTable(table, family)
	if tbl == nil {
		return nil, fmt.Errorf("Invalid table (%s, %s)", table, family)
	}
	exprList := []expr.Any{}
	if strings.Index(l4prots, ",") != -1 {
		set := &nftables.Set{
			Anonymous: true,
			Constant:  true,
			Table:     tbl,
			KeyType:   nftables.TypeInetProto,
		}
		protoSet := exprs.NewExprProtoSet(l4prots)
		if err := n.Conn.AddSet(set, *protoSet); err != nil {
			log.Warning("%s protoSet, AddSet() error: %s", logTag, err)
			return nil, err
		}
		exprList = append(exprList, &expr.Lookup{
			SourceRegister: 1,
			SetName:        set.Name,
			SetID:          set.ID,
		})
	} else {
		exprProto := exprs.NewExprL4Proto(l4prots, cmpOp)
		exprList = append(exprList, *exprProto...)
	}

	return &exprList, nil
}

func (n *Nft) buildPortsRule(table, family, ports string, cmpOp *expr.CmpOp) (*[]expr.Any, error) {
	tbl := n.GetTable(table, family)
	if tbl == nil {
		return nil, fmt.Errorf("Invalid table (%s, %s)", table, family)
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
		if err := n.Conn.AddSet(set, *setElements); err != nil {
			log.Warning("%s portSet, AddSet() error: %s", logTag, err)
			return nil, err
		}
		exprList = append(exprList, &expr.Lookup{
			SourceRegister: 1,
			SetName:        set.Name,
			SetID:          set.ID,
		})
		sysSets = append(sysSets, []*nftables.Set{set}...)
	} else if strings.Index(ports, "-") != -1 {
		portRange, err := exprs.NewExprPortRange(ports, cmpOp)
		if err != nil {
			log.Warning("%s invalid portRange: %s, %s", logTag, ports, err)
			return nil, err
		}
		exprList = append(exprList, *portRange...)
	} else {
		exprPort, err := exprs.NewExprPort(ports, cmpOp)
		if err != nil {
			return nil, err
		}
		exprList = append(exprList, *exprPort...)
	}

	return &exprList, nil
}
