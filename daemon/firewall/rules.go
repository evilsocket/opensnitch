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
	if err != nil {
		return
	}
	_, err = core.Exec("ip6tables", rule)
	if err != nil {
		return
	}

	return
}

// INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
func QueueDNSResponses(enable bool, queueNum int) (err error) {
	// If enable, we're going to insert as #1, not append
	if enable {
		// FIXME: this is basically copy/paste of RunRule() above b/c we can't
		// shoehorn "-I" with the boolean 'enable' switch
		rule := []string{
			"-I",
			"INPUT",
			"1",
			"--protocol", "udp",
			"--sport", "53",
			"-j", "NFQUEUE",
			"--queue-num", fmt.Sprintf("%d", queueNum),
			"--queue-bypass",
		}
		
		lock.Lock()
		defer lock.Unlock()
		
		_, err := core.Exec("iptables", rule)
		if err != nil {
			return err
		}
		_, err = core.Exec("ip6tables", rule)
		if err != nil {
			return err
		}

		return err
	}

	// Otherwise, it's going to be disable
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
