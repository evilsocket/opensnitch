package iptables

import (
	"os/exec"
	"regexp"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// Action is the modifier we apply to a rule.
type Action string

const (
	// Name is the name that identifies this firewall
	Name = "iptables"
	// SystemRulePrefix prefix added to each system rule
	SystemRulePrefix = "opensnitch-filter"
)

// Actions we apply to the firewall.
const (
	ADD      = Action("-A")
	INSERT   = Action("-I")
	DELETE   = Action("-D")
	FLUSH    = Action("-F")
	NEWCHAIN = Action("-N")
	DELCHAIN = Action("-X")
)

// SystemChains holds the fw rules defined by the user
type SystemChains struct {
	sync.RWMutex
	Rules map[string]config.FwRule
}

// Iptables struct holds the fields of the iptables fw
type Iptables struct {
	sync.Mutex
	config.Config
	common.Common

	bin  string
	bin6 string

	regexRulesQuery       *regexp.Regexp
	regexSystemRulesQuery *regexp.Regexp

	chains SystemChains
}

// Fw initializes a new Iptables object
func Fw() (*Iptables, error) {
	if err := IsAvailable(); err != nil {
		return nil, err
	}

	reRulesQuery, _ := regexp.Compile(`NFQUEUE.*ctstate NEW,RELATED.*NFQUEUE num.*bypass`)
	reSystemRulesQuery, _ := regexp.Compile(SystemRulePrefix + ".*")

	ipt := &Iptables{
		bin:                   "iptables",
		bin6:                  "ip6tables",
		regexRulesQuery:       reRulesQuery,
		regexSystemRulesQuery: reSystemRulesQuery,
		chains:                SystemChains{Rules: make(map[string]config.FwRule)},
	}
	return ipt, nil
}

// Name returns the firewall name
func (ipt *Iptables) Name() string {
	return Name
}

// Init inserts the firewall rules and starts monitoring for firewall
// changes.
func (ipt *Iptables) Init(qNum *int) {
	if ipt.IsRunning() {
		return
	}
	ipt.SetQueueNum(qNum)

	// In order to clean up any existing firewall rule before start,
	// we need to load the fw configuration first.
	ipt.NewSystemFwConfig(ipt.preloadConfCallback)
	go ipt.MonitorSystemFw(ipt.AddSystemRules)
	ipt.LoadDiskConfiguration(false)

	// start from a clean state
	ipt.CleanRules(false)
	ipt.AddSystemRules()

	ipt.InsertRules()
	// start monitoring firewall rules to intercept network traffic
	ipt.NewRulesChecker(ipt.AreRulesLoaded, ipt.reloadRulesCallback)

	ipt.Running = true
}

// Stop deletes the firewall rules, allowing network traffic.
func (ipt *Iptables) Stop() {
	if ipt.Running == false {
		return
	}
	ipt.StopConfigWatcher()
	ipt.StopCheckingRules()
	ipt.CleanRules(log.GetLogLevel() == log.DEBUG)

	ipt.Running = false
}

// IsAvailable checks if iptables is installed in the system.
func IsAvailable() error {
	_, err := exec.Command("iptables", []string{"-V"}...).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

// InsertRules adds fw rules to intercept connections
func (ipt *Iptables) InsertRules() {
	if err4, err6 := ipt.QueueDNSResponses(true, true); err4 != nil || err6 != nil {
		log.Error("Error while running DNS firewall rule: %s %s", err4, err6)
	} else if err4, err6 = ipt.QueueConnections(true, true); err4 != nil || err6 != nil {
		log.Fatal("Error while running conntrack firewall rule: %s %s", err4, err6)
	}
}

// CleanRules deletes the rules we added.
func (ipt *Iptables) CleanRules(logErrors bool) {
	ipt.QueueDNSResponses(false, logErrors)
	ipt.QueueConnections(false, logErrors)
	ipt.DeleteSystemRules(true, logErrors)
}
