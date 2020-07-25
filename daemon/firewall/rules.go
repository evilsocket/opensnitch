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
func RunRule(action Action, enable bool, rule []string) (err error) {
	if enable == false {
		action = "-D"
	}

	rule = append([]string{string(action)}, rule...)

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

// QueueDNSResponses redirects DNS responses to us, in order to keep a cache
// of resolved domains.
// INPUT --protocol udp --sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
func QueueDNSResponses(enable bool, qNum int) (err error) {
	return RunRule(INSERT, enable, []string{
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
func QueueConnections(enable bool, qNum int) (err error) {
	return RunRule(ADD, enable, []string{
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
func DropMarked(enable bool) (err error) {
	return RunRule(ADD, enable, []string{
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
				QueueConnections(false, qNum)
				DropMarked(false)
				QueueConnections(true, qNum)
				DropMarked(true)
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
	QueueDNSResponses(false, queueNum)
	QueueConnections(false, queueNum)
	DropMarked(false)

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

	if err := QueueDNSResponses(true, queueNum); err != nil {
		log.Fatal("Error while running DNS firewall rule: %s", err)
	} else if err = QueueConnections(true, queueNum); err != nil {
		log.Fatal("Error while running conntrack firewall rule: %s", err)
	} else if err = DropMarked(true); err != nil {
		log.Fatal("Error while running drop firewall rule: %s", err)
	}
	go StartCheckingRules(queueNum)

	running = true
}
