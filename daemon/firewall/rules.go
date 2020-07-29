package firewall

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/gustavo-iniguez-goya/opensnitch/daemon/core"
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/log"
)

// DropMark is the mark we place on a connection when we deny it.
// The connection is dropped later on OUTPUT chain.
const DropMark = 0x18BA5

// Action is the modifier we apply to a rule.
type Action string

// Actions we apply to the firewall.
const (
	ADD    = Action("-A")
	INSERT = Action("-I")
	DELETE = Action("-D")
)

// make sure we don't mess with multiple rules
// at the same time
var (
	lock = sync.Mutex{}

	queueNum = 0
	running  = false
	// check that rules are loaded every 5s
	rulesChecker       = time.NewTicker(time.Second * 20)
	rulesCheckerChan   = make(chan bool)
	regexRulesQuery, _ = regexp.Compile(`NFQUEUE.*ctstate NEW,RELATED.*NFQUEUE num.*bypass`)
	regexDropQuery, _  = regexp.Compile(`DROP.*mark match 0x18ba5`)
)

// RunRule inserts or deletes a firewall rule.
func RunRule(action Action, enable bool, logError bool, rule []string) error {
	if enable == false {
		action = "-D"
	}

	rule = append([]string{string(action)}, rule...)

	lock.Lock()
	defer lock.Unlock()

	// fmt.Printf("iptables %s\n", rule)

	_, err4 := core.Exec("iptables", rule)
	_, err6 := core.Exec("ip6tables", rule)
	if err4 != nil && err6 != nil {
		if logError {
			log.Error("Error while running firewall rule, ipv4 err: %s, ipv6 err: %s", err4, err6)
			log.Error("rule: %s", rule)
		}
		return nil
	} else if err4 != nil {
		return err4
	} else if err6 != nil {
		return err6
	}

	return nil
}

// QueueDNSResponses redirects DNS responses to us, in order to keep a cache
// of resolved domains.
// INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
func QueueDNSResponses(enable bool, logError bool, qNum int) (err error) {
	return RunRule(INSERT, enable, logError, []string{
		"INPUT",
		"--protocol", "udp",
		"--sport", "53",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", qNum),
		"--queue-bypass",
	})
}

// QueueConnections inserts the firewall rule which redirects connections to us.
// They are queued until the user denies/accept them, or reaches a timeout.
// OUTPUT -t mangle -m conntrack --ctstate NEW,RELATED -j NFQUEUE --queue-num 0 --queue-bypass
func QueueConnections(enable bool, logError bool, qNum int) (err error) {
	return RunRule(ADD, enable, logError, []string{
		"OUTPUT",
		"-t", "mangle",
		"-m", "conntrack",
		"--ctstate", "NEW,RELATED",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", qNum),
		"--queue-bypass",
	})
}

// DropMarked rejects packets marked by OpenSnitch.
// OUTPUT -m mark --mark 101285 -j DROP
func DropMarked(enable bool, logError bool) (err error) {
	return RunRule(ADD, enable, logError, []string{
		"OUTPUT",
		"-m", "mark",
		"--mark", fmt.Sprintf("%d", DropMark),
		"-j", "DROP",
	})
}

// AreRulesLoaded checks if the firewall rules are loaded.
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

// StartCheckingRules checks periodically if the rules are loaded.
// If they're not, we insert them again.
func StartCheckingRules(qNum int) {
	for {
		select {
		case <-rulesCheckerChan:
			return
		case <-rulesChecker.C:
			if rules := AreRulesLoaded(); rules == false {
				QueueConnections(false, false, qNum)
				DropMarked(false, false)
				QueueConnections(true, true, qNum)
				DropMarked(true, true)
			}
		}
	}
}

// StopCheckingRules stops checking if the firewall rules are loaded.
func StopCheckingRules() {
	rulesCheckerChan <- true
}

// IsRunning returns if the firewall rules are loaded or not.
func IsRunning() bool {
	return running
}

// Stop deletes the firewall rules, allowing network traffic.
func Stop(qNum *int) {
	if running == false {
		return
	}
	if qNum != nil {
		queueNum = *qNum
	}

	StopCheckingRules()
	QueueDNSResponses(false, true, queueNum)
	QueueConnections(false, true, queueNum)
	DropMarked(false, true)

	running = false
}

// Init inserts the firewall rules.
func Init(qNum *int) {
	if running {
		return
	}
	if qNum != nil {
		queueNum = *qNum
	}

	if err := QueueDNSResponses(true, true, queueNum); err != nil {
		log.Error("Error while running DNS firewall rule: %s", err)
	} else if err = QueueConnections(true, true, queueNum); err != nil {
		log.Error("Error while running conntrack firewall rule: %s", err)
	} else if err = DropMarked(true, true); err != nil {
		log.Error("Error while running drop firewall rule: %s", err)
	}
	go StartCheckingRules(queueNum)

	running = true
}
