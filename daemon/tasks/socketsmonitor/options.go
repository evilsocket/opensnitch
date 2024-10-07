package socketsmonitor

import (
	//"golang.org/x/sys/unix"
	"syscall"
)

// Protos holds valid combinations of protocols, families and socket types that can be created.
type Protos struct {
	Proto uint8
	Fam   uint8
}

var options = []Protos{
	{syscall.IPPROTO_DCCP, syscall.AF_INET},
	{syscall.IPPROTO_DCCP, syscall.AF_INET6},
	{syscall.IPPROTO_ICMPV6, syscall.AF_INET6},
	{syscall.IPPROTO_ICMP, syscall.AF_INET},
	{syscall.IPPROTO_IGMP, syscall.AF_INET},
	{syscall.IPPROTO_IGMP, syscall.AF_INET6},
	{syscall.IPPROTO_RAW, syscall.AF_INET},
	{syscall.IPPROTO_RAW, syscall.AF_INET6},
	{syscall.IPPROTO_SCTP, syscall.AF_INET},
	{syscall.IPPROTO_SCTP, syscall.AF_INET6},
	{syscall.IPPROTO_TCP, syscall.AF_INET},
	{syscall.IPPROTO_TCP, syscall.AF_INET6},
	{syscall.IPPROTO_UDP, syscall.AF_INET},
	{syscall.IPPROTO_UDP, syscall.AF_INET6},
	{syscall.IPPROTO_UDPLITE, syscall.AF_INET},
	{syscall.IPPROTO_UDPLITE, syscall.AF_INET6},
}
