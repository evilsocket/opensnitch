package firewall

import (
	"fmt"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/core"
)

const DropMark = 0x18BA5

// make sure we don't mess with multiple rules
// at the same time
var lock = sync.Mutex{}

func RunRule(enable bool, rule []string) (err error) {
	action := "-A"
	if enable == false {
		action = "-D"
	}

	rule = append([]string{action}, rule...)

	lock.Lock()
	defer lock.Unlock()

	// fmt.Printf("iptables %s\n", rule)

	_, err = core.Exec("iptables", rule)
	return
}

// INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
func QueueDNSResponses(enable bool, queueNum int) (err error) {
	return RunRule(enable, []string{
		"INPUT",
		"--protocol", "udp",
		"--sport", "53",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
	})
}

// OUTPUT -t mangle -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0 --queue-bypass
func QueueConnections(enable bool, queueNum int) (err error) {
	return RunRule(enable, []string{
		"OUTPUT",
		"-t", "mangle",
		"-m", "conntrack",
		"--ctstate", "NEW",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", queueNum),
		"--queue-bypass",
	})
}

// Reject packets marked by OpenSnitch
// OUTPUT -m mark --mark 101285 -j DROP
func DropMarked(enable bool) (err error) {
	return RunRule(enable, []string{
		"OUTPUT",
		"-m", "mark",
		"--mark", fmt.Sprintf("%d", DropMark),
		"-j", "DROP",
	})
}
