package iptables

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/vishvananda/netlink"
)

// RunRule inserts or deletes a firewall rule.
func (ipt *Iptables) RunRule(action Action, enable bool, logError bool, rule []string) (err4, err6 error) {
	if enable == false {
		action = "-D"
	}

	rule = append([]string{string(action)}, rule...)

	ipt.Lock()
	defer ipt.Unlock()

	if _, err4 = core.Exec(ipt.bin, rule); err4 != nil {
		if logError {
			log.Error("Error while running firewall rule, ipv4 err: %s", err4)
			log.Error("rule: %s", rule)
		}
	}

	// On some systems IPv6 is disabled
	if core.IPv6Enabled {
		if _, err6 = core.Exec(ipt.bin6, rule); err6 != nil {
			if logError {
				log.Error("Error while running firewall rule, ipv6 err: %s", err6)
				log.Error("rule: %s", rule)
			}
		}
	}

	return
}

// QueueDNSResponses redirects DNS responses to us, in order to keep a cache
// of resolved domains.
// INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
func (ipt *Iptables) QueueDNSResponses(enable bool, logError bool) (err4, err6 error) {
	return ipt.RunRule(INSERT, enable, logError, []string{
		"INPUT",
		"--protocol", "udp",
		"--sport", "53",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", ipt.QueueNum),
		"--queue-bypass",
	})
}

// QueueConnections inserts the firewall rule which redirects connections to us.
// Connections are queued until the user denies/accept them, or reaches a timeout.
// OUTPUT -t mangle -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass
func (ipt *Iptables) QueueConnections(enable bool, logError bool) (error, error) {
	err4, err6 := ipt.RunRule(ADD, enable, logError, []string{
		"OUTPUT",
		"-t", "mangle",
		"-m", "conntrack",
		"--ctstate", "NEW,RELATED",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", ipt.QueueNum),
		"--queue-bypass",
	})
	if enable {
		// flush conntrack as soon as netfilter rule is set. This ensures that already-established
		// connections will go to netfilter queue.
		if err := netlink.ConntrackTableFlush(netlink.ConntrackTable); err != nil {
			log.Error("error in ConntrackTableFlush %s", err)
		}
	}
	return err4, err6
}
