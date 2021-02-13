package firewall

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/fsnotify/fsnotify"
)

// DropMark is the mark we place on a connection when we deny it.
// The connection is dropped later on OUTPUT chain.
const DropMark = 0x18BA5

// Action is the modifier we apply to a rule.
type Action string

// Actions we apply to the firewall.
const (
	ADD      = Action("-A")
	INSERT   = Action("-I")
	DELETE   = Action("-D")
	FLUSH    = Action("-F")
	NEWCHAIN = Action("-N")
	DELCHAIN = Action("-X")

	systemRulePrefix = "opensnitch-filter"
)

// make sure we don't mess with multiple rules
// at the same time
var (
	lock = sync.Mutex{}

	queueNum = 0
	running  = false
	// check that rules are loaded every 30s
	rulesChecker             *time.Ticker
	rulesCheckerChan         = make(chan bool)
	regexRulesQuery, _       = regexp.Compile(`NFQUEUE.*ctstate NEW,RELATED.*NFQUEUE num.*bypass`)
	regexSystemRulesQuery, _ = regexp.Compile(systemRulePrefix + ".*")

	systemChains = make(map[string]*fwRule)
)

// RunRule inserts or deletes a firewall rule.
func RunRule(action Action, enable bool, logError bool, rule []string) (err4, err6 error) {
	if enable == false {
		action = "-D"
	}

	rule = append([]string{string(action)}, rule...)

	lock.Lock()
	defer lock.Unlock()

	if _, err4 = core.Exec("iptables", rule); err4 != nil {
		if logError {
			log.Error("Error while running firewall rule, ipv4 err: %s", err4)
			log.Error("rule: %s", rule)
		}
	}

	if core.IPv6Enabled {
		if _, err6 = core.Exec("ip6tables", rule); err6 != nil {
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
func QueueDNSResponses(enable bool, logError bool, qNum int) (err4, err6 error) {
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
func QueueConnections(enable bool, logError bool, qNum int) (err4, err6 error) {
	return RunRule(INSERT, enable, logError, []string{
		"OUTPUT",
		"-t", "mangle",
		"-m", "conntrack",
		"--ctstate", "NEW,RELATED",
		"-j", "NFQUEUE",
		"--queue-num", fmt.Sprintf("%d", qNum),
		"--queue-bypass",
	})
}

// CreateSystemRule create the custom firewall chains and adds them to system.
func CreateSystemRule(rule *fwRule, logErrors bool) {
	chainName := systemRulePrefix + "-" + rule.Chain
	if _, ok := systemChains[rule.Table+"-"+chainName]; ok {
		return
	}
	RunRule(NEWCHAIN, true, logErrors, []string{chainName, "-t", rule.Table})

	// Insert the rule at the top of the chain
	if err4, err6 := RunRule(INSERT, true, logErrors, []string{rule.Chain, "-t", rule.Table, "-j", chainName}); err4 == nil && err6 == nil {
		systemChains[rule.Table+"-"+chainName] = rule
	}
}

// DeleteSystemRules deletes the system rules.
// If force is false and the rule has not been previously added,
// it won't try to delete the rules. Otherwise it'll try to delete them.
func DeleteSystemRules(force, logErrors bool) {
	for _, r := range fwConfig.SystemRules {
		chain := systemRulePrefix + "-" + r.Rule.Chain
		if _, ok := systemChains[r.Rule.Table+"-"+chain]; !ok && !force {
			continue
		}
		RunRule(FLUSH, true, logErrors, []string{chain, "-t", r.Rule.Table})
		RunRule(DELETE, false, logErrors, []string{r.Rule.Chain, "-t", r.Rule.Table, "-j", chain})
		RunRule(DELCHAIN, true, logErrors, []string{chain, "-t", r.Rule.Table})
		delete(systemChains, r.Rule.Table+"-"+chain)
	}
}

// AddSystemRule inserts a new rule.
func AddSystemRule(action Action, rule *fwRule, enable bool) (err4, err6 error) {
	chain := systemRulePrefix + "-" + rule.Chain
	if rule.Table == "" {
		rule.Table = "filter"
	}
	r := []string{chain, "-t", rule.Table}
	if rule.Parameters != "" {
		r = append(r, strings.Split(rule.Parameters, " ")...)
	}
	r = append(r, []string{"-j", rule.Target}...)
	if rule.TargetParameters != "" {
		r = append(r, strings.Split(rule.TargetParameters, " ")...)
	}

	return RunRule(action, enable, true, r)
}

// AreRulesLoaded checks if the firewall rules are loaded.
func AreRulesLoaded() bool {
	lock.Lock()
	defer lock.Unlock()

	var outMangle6 string

	outMangle, err := core.Exec("iptables", []string{"-n", "-L", "OUTPUT", "-t", "mangle"})
	if err != nil {
		return false
	}

	if core.IPv6Enabled {
		outMangle6, err = core.Exec("ip6tables", []string{"-n", "-L", "OUTPUT", "-t", "mangle"})
		if err != nil {
			return false
		}
	}

	systemRulesLoaded := true
	if len(systemChains) > 0 {
		for _, rule := range systemChains {
			if chainOut4, err4 := core.Exec("iptables", []string{"-n", "-L", rule.Chain, "-t", rule.Table}); err4 == nil {
				if regexSystemRulesQuery.FindString(chainOut4) == "" {
					systemRulesLoaded = false
					break
				}
			}
			if core.IPv6Enabled {
				if chainOut6, err6 := core.Exec("ip6tables", []string{"-n", "-L", rule.Chain, "-t", rule.Table}); err6 == nil {
					if regexSystemRulesQuery.FindString(chainOut6) == "" {
						systemRulesLoaded = false
						break
					}
				}
			}
		}
	}

	result := regexRulesQuery.FindString(outMangle) != "" &&
		systemRulesLoaded

	if core.IPv6Enabled {
		result = result && regexRulesQuery.FindString(outMangle6) != ""
	}

	return result
}

// StartCheckingRules checks periodically if the rules are loaded.
// If they're not, we insert them again.
func StartCheckingRules() {
	for {
		select {
		case <-rulesCheckerChan:
			goto Exit
		case <-rulesChecker.C:
			if rules := AreRulesLoaded(); rules == false {
				log.Important("firewall rules changed, reloading")
				CleanRules(log.GetLogLevel() == log.DEBUG)
				insertRules()
				loadDiskConfiguration(true)
			}
		}
	}

Exit:
	log.Info("exit checking fw rules")
}

// StopCheckingRules stops checking if the firewall rules are loaded.
func StopCheckingRules() {
	if rulesChecker != nil {
		rulesChecker.Stop()
	}
	rulesCheckerChan <- true
	if configWatcher != nil {
		rulesCheckerChan <- true
	}
}

// IsRunning returns if the firewall rules are loaded or not.
func IsRunning() bool {
	return running
}

// CleanRules deletes the rules we added.
func CleanRules(logErrors bool) {
	QueueDNSResponses(false, logErrors, queueNum)
	QueueConnections(false, logErrors, queueNum)
	DeleteSystemRules(true, logErrors)
}

func insertRules() {
	if err4, err6 := QueueDNSResponses(true, true, queueNum); err4 != nil || err6 != nil {
		log.Error("Error while running DNS firewall rule: %s %s", err4, err6)
	} else if err4, err6 = QueueConnections(true, true, queueNum); err4 != nil || err6 != nil {
		log.Fatal("Error while running conntrack firewall rule: %s %s", err4, err6)
	}
}

// Stop deletes the firewall rules, allowing network traffic.
func Stop(qNum *int) {
	if running == false {
		return
	}
	if qNum != nil {
		queueNum = *qNum
	}

	if configWatcher != nil {
		configWatcher.Remove(configFile)
		configWatcher.Close()
	}
	StopCheckingRules()
	CleanRules(log.GetLogLevel() == log.DEBUG)

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
	insertRules()

	var err error
	if configWatcher, err = fsnotify.NewWatcher(); err != nil {
		log.Warning("Error creating firewall config watcher: %s", err)
	}
	loadDiskConfiguration(false)

	rulesChecker = time.NewTicker(time.Second * 30)
	go StartCheckingRules()

	running = true
}
