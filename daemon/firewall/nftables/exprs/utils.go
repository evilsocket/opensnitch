package exprs

import (
	"strconv"

	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// GetICMPRejectCode returns the code by its name.
func GetICMPRejectCode(reason string) uint8 {
	switch reason {
	case ICMP_HOST_UNREACHABLE, ICMP_ADDR_UNREACHABLE:
		return layers.ICMPv4CodeHost
	case ICMP_PROT_UNREACHABLE:
		return layers.ICMPv4CodeProtocol
	case ICMP_PORT_UNREACHABLE:
		return layers.ICMPv4CodePort
	case ICMP_ADMIN_PROHIBITED:
		return layers.ICMPv4CodeCommAdminProhibited
	case ICMP_HOST_PROHIBITED:
		return layers.ICMPv4CodeHostAdminProhibited
	case ICMP_NET_PROHIBITED:
		return layers.ICMPv4CodeNetAdminProhibited
	}

	return layers.ICMPv4CodeNet
}

// GetICMPxRejectCode returns the code by its name.
func GetICMPxRejectCode(reason string) uint8 {
	// https://github.com/torvalds/linux/blob/master/net/netfilter/nft_reject.c#L96
	// https://github.com/google/gopacket/blob/3aa782ce48d4a525acaebab344cedabfb561f870/layers/icmp4.go#L37
	switch reason {
	case ICMP_HOST_UNREACHABLE, ICMP_NET_UNREACHABLE:
		return unix.NFT_REJECT_ICMP_UNREACH // results in -> net-unreachable???
	case ICMP_PROT_UNREACHABLE:
		return unix.NFT_REJECT_ICMPX_HOST_UNREACH // results in -> prot-unreachable???
	case ICMP_PORT_UNREACHABLE:
		return unix.NFT_REJECT_ICMPX_PORT_UNREACH // results in -> host-unreachable???
	case ICMP_NO_ROUTE:
		return unix.NFT_REJECT_ICMPX_NO_ROUTE // results in -> net-unreachable
	}

	return unix.NFT_REJECT_ICMP_UNREACH // results in -> net-unreachable???
}

// GetICMPType returns an ICMP type code
func GetICMPType(icmpType string) uint8 {
	switch icmpType {
	case ICMP_ECHO_REPLY:
		return layers.ICMPv4TypeEchoReply
	case ICMP_ECHO_REQUEST:
		return layers.ICMPv4TypeEchoRequest
	case ICMP_SOURCE_QUENCH:
		return layers.ICMPv4TypeSourceQuench
	case ICMP_DEST_UNREACHABLE:
		return layers.ICMPv4TypeDestinationUnreachable
	case ICMP_ROUTER_ADVERTISEMENT:
		return layers.ICMPv4TypeRouterAdvertisement
	case ICMP_ROUTER_SOLICITATION:
		return layers.ICMPv4TypeRouterSolicitation
	case ICMP_REDIRECT:
		return layers.ICMPv4TypeRedirect
	case ICMP_TIME_EXCEEDED:
		return layers.ICMPv4TypeTimeExceeded
	case ICMP_INFO_REQUEST:
		return layers.ICMPv4TypeInfoRequest
	case ICMP_INFO_REPLY:
		return layers.ICMPv4TypeInfoReply
	case ICMP_PARAMETER_PROBLEM:
		return layers.ICMPv4TypeParameterProblem
	case ICMP_TIMESTAMP_REQUEST:
		return layers.ICMPv4TypeTimestampRequest
	case ICMP_TIMESTAMP_REPLY:
		return layers.ICMPv4TypeTimestampReply
	case ICMP_ADDRESS_MASK_REQUEST:
		return layers.ICMPv4TypeAddressMaskRequest
	case ICMP_ADDRESS_MASK_REPLY:
		return layers.ICMPv4TypeAddressMaskReply
	}
	return 0
}

// GetICMPv6Type returns an ICMPv6 type code
func GetICMPv6Type(icmpType string) uint8 {
	switch icmpType {
	case ICMP_DEST_UNREACHABLE:
		return layers.ICMPv6TypeDestinationUnreachable
	case ICMP_PACKET_TOO_BIG:
		return layers.ICMPv6TypePacketTooBig
	case ICMP_TIME_EXCEEDED:
		return layers.ICMPv6TypeTimeExceeded
	case ICMP_PARAMETER_PROBLEM:
		return layers.ICMPv6TypeParameterProblem
	case ICMP_ECHO_REQUEST:
		return layers.ICMPv6TypeEchoRequest
	case ICMP_ECHO_REPLY:
		return layers.ICMPv6TypeEchoReply
	case ICMP_ROUTER_SOLICITATION:
		return layers.ICMPv6TypeRouterSolicitation
	case ICMP_ROUTER_ADVERTISEMENT:
		return layers.ICMPv6TypeRouterAdvertisement
	case ICMP_NEIGHBOUR_SOLICITATION:
		return layers.ICMPv6TypeNeighborSolicitation
	case ICMP_NEIGHBOUR_ADVERTISEMENT:
		return layers.ICMPv6TypeNeighborAdvertisement
	case ICMP_REDIRECT:
		return layers.ICMPv6TypeRedirect
	}
	return 0
}

// GetICMPv6RejectCode returns the code by its name.
func GetICMPv6RejectCode(reason string) uint8 {
	switch reason {
	case ICMP_HOST_UNREACHABLE, ICMP_NET_UNREACHABLE, ICMP_NO_ROUTE:
		return layers.ICMPv6CodeNoRouteToDst
	case ICMP_ADDR_UNREACHABLE:
		return layers.ICMPv6CodeAddressUnreachable
	case ICMP_PORT_UNREACHABLE:
		return layers.ICMPv6CodePortUnreachable
	case ICMP_REJECT_POLICY_FAIL:
		return layers.ICMPv6CodeSrcAddressFailedPolicy
	case ICMP_REJECT_ROUTE:
		return layers.ICMPv6CodeRejectRouteToDst
	}

	return layers.ICMPv6CodeNoRouteToDst
}

// getProtocolCode will try to return the code of the given protocol.
// If the protocol is not in our list, we'll use the value as decimal.
// So for example IPPROTO_ENCAP (0x62) must be specified as 98.
// https://pkg.go.dev/golang.org/x/sys/unix#pkg-constants
func getProtocolCode(value string) (byte, error) {
	switch value {
	case NFT_PROTO_TCP:
		return unix.IPPROTO_TCP, nil
	case NFT_PROTO_UDP:
		return unix.IPPROTO_UDP, nil
	case NFT_PROTO_UDPLITE:
		return unix.IPPROTO_UDPLITE, nil
	case NFT_PROTO_SCTP:
		return unix.IPPROTO_SCTP, nil
	case NFT_PROTO_DCCP:
		return unix.IPPROTO_DCCP, nil
	case NFT_PROTO_ICMP:
		return unix.IPPROTO_ICMP, nil
	case NFT_PROTO_ICMPv6:
		return unix.IPPROTO_ICMPV6, nil
	case NFT_PROTO_AH:
		return unix.IPPROTO_AH, nil
	case NFT_PROTO_ETHERNET:
		return unix.IPPROTO_ETHERNET, nil
	case NFT_PROTO_GRE:
		return unix.IPPROTO_GRE, nil
	case NFT_PROTO_IP:
		return unix.IPPROTO_IP, nil
	case NFT_PROTO_IPIP:
		return unix.IPPROTO_IPIP, nil
	case NFT_PROTO_L2TP:
		return unix.IPPROTO_L2TP, nil
	case NFT_PROTO_COMP:
		return unix.IPPROTO_COMP, nil
	case NFT_PROTO_IGMP:
		return unix.IPPROTO_IGMP, nil
	case NFT_PROTO_ESP:
		return unix.IPPROTO_ESP, nil
	case NFT_PROTO_RAW:
		return unix.IPPROTO_RAW, nil
	case NFT_PROTO_ENCAP:
		return unix.IPPROTO_ENCAP, nil
	}

	prot, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return byte(prot), nil
}
