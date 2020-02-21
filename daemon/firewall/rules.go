package firewall

import (
	"fmt"
	"sync"
	"time"
	"regexp"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/core"
)

const DropMark = 0x18BA5

// make sure we don't mess with multiple rules
// at the same time
var (
	lock = sync.Mutex{}

	// check that rules are loaded every 5s
	rulesChecker = time.NewTicker(time.Second * 5)
	rulesCheckerChan = make(chan bool)
	regexRulesQuery, _ = regexp.Compile(`NFQUEUE.*ctstate NEW.*NFQUEUE num.*bypass`)
	regexDropQuery, _ = regexp.Compile(`DROP.*mark match 0x18ba5`)
)

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
	regexRulesQuery, _ = regexp.Compile(fmt.Sprint(`NFQUEUE.*ctstate NEW.*NFQUEUE num `, queueNum, ` bypass`))

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

func AreRulesLoaded() bool {
	lock.Lock()
	defer lock.Unlock()

	outDrop, err := core.Exec("iptables", []string{"-L", "OUTPUT"})
	if err != nil {
		return false
	}
	outDrop6, err := core.Exec("ip6tables", []string{"-L", "OUTPUT"})
	if err != nil {
		return false
	}
	outMangle, err := core.Exec("iptables", []string{"-L", "OUTPUT", "-t", "mangle"})
	if err != nil {
		return false
	}
	outMangle6, err := core.Exec("ip6tables", []string{"-L", "OUTPUT", "-t", "mangle"})
	if err != nil {
		return false
	}

	return regexRulesQuery.FindString(outMangle) != "" &&
		regexRulesQuery.FindString(outMangle6) != "" &&
		regexDropQuery.FindString(outDrop) != "" &&
		regexDropQuery.FindString(outDrop6) != ""
}

func StartCheckingRules(qNum int) {
	for {
		select {
		case <-rulesCheckerChan:
			fmt.Println("Stop checking rules")
			return
		case <-rulesChecker.C:
			rules := AreRulesLoaded()
			if rules == false {
				QueueConnections(false, qNum)
				DropMarked(false)
				QueueConnections(true, qNum)
				DropMarked(true)
			}
		}
	}
}

func StopCheckingRules() {
	rulesCheckerChan <- true
}
