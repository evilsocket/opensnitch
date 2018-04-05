go-netfilter-queue
==================
[![Build Status](https://travis-ci.org/AkihiroSuda/go-netfilter-queue.svg)](https://travis-ci.org/AkihiroSuda/go-netfilter-queue)
[![GoDoc](https://godoc.org/github.com/AkihiroSuda/go-netfilter-queue?status.svg)](https://godoc.org/github.com/AkihiroSuda/go-netfilter-queue)

Go bindings for libnetfilter_queue

_Forked from [openshift/geard@be0423a](https://github.com/openshift/geard/tree/be0423a67449bc4be1419e03e8bdf459ff0df07e/pkg/go-netfilter-queue)_ for supporting recent environments. I'm using Go 1.6 for testing.

This library provides access to packets in the IPTables netfilter queue (NFQUEUE).
The libnetfilter_queue library is part of the [Netfilter project| http://netfilter.org/projects/libnetfilter_queue/].

Example
=======

use IPTables to direct all outgoing Ping/ICMP requests to the queue 0:

    iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0

You can then use go-netfilter-queue to inspect the packets:

    package main
    
    import (
            "fmt"
            "github.com/AkihiroSuda/go-netfilter-queue"
            "os"
    )
    
    func main() {
            var err error
    
            nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
            if err != nil {
                    fmt.Println(err)
                    os.Exit(1)
            }
            defer nfq.Close()
            packets := nfq.GetPackets()
    
            for true {
                    select {
                    case p := <-packets:
                            fmt.Println(p.Packet)
                            p.SetVerdict(netfilter.NF_ACCEPT)
                    }
            }
    }

To inject a new or modified packet in the place of the original packet, use:

    p.SetVerdictWithPacket(netfilter.NF_ACCEPT, byte_slice)

Instead of:

    p.SetVerdict(netfilter.NF_ACCEPT)

To undo the IPTables redirect. Run:

    iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 0
