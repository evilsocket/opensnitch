package iptables

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/vishvananda/netlink"
)

// FirewallError is a type that holds both IPv4 and IPv6 errors.
type FirewallError struct {
	Err4 error
	Err6 error
}

// Error formats the errors for both IPv4 and IPv6 errors.
func (e *FirewallError) Error() string {
	return fmt.Sprintf("IPv4 error: %v, IPv6 error: %v", e.Err4, e.Err6)
}

// HasError simplifies error handling of the FirewallError type.
func (e *FirewallError) HasError() bool {
	return e.Err4 != nil || e.Err6 != nil
}

// RunRule inserts or deletes a firewall rule.
func (ipt *Iptables) RunRule(action Action, enable bool, logError bool, rule []string) *FirewallError {
	if enable == false {
		action = "-D"
	}

	rule = append([]string{string(action)}, rule...)

	ipt.Lock()
	defer ipt.Unlock()

	var err4, err6 error
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

	return &FirewallError{Err4: err4, Err6: err6}
}

// QueueDNSResponses redirects DNS responses to us, in order to keep a cache
// of resolved domains.
// INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
func (ipt *Iptables) QueueDNSResponses(enable bool, logError bool) *FirewallError {
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
func (ipt *Iptables) QueueConnections(enable bool, logError bool) *FirewallError {
	err := ipt.RunRule(ADD, enable, logError, []string{
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
		if ctErr := netlink.ConntrackTableFlush(netlink.ConntrackTable); ctErr != nil {
			log.Error("error in ConntrackTableFlush %s", ctErr)
		}
	}
	return err
}
