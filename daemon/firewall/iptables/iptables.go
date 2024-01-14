package iptables

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"github.com/golang/protobuf/jsonpb"
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
	POLICY   = Action("-P")

	DROP   = Action("DROP")
	ACCEPT = Action("ACCEPT")
)

// SystemRule blabla
type SystemRule struct {
	Rule  *config.FwRule
	Table string
	Chain string
}

// SystemChains keeps track of the fw rules that have been added to the system.
type SystemChains struct {
	Rules map[string]*SystemRule
	sync.RWMutex
}

// Iptables struct holds the fields of the iptables fw
type Iptables struct {
	regexRulesQuery       *regexp.Regexp
	regexSystemRulesQuery *regexp.Regexp
	bin                   string
	bin6                  string
	chains                SystemChains
	common.Common
	config.Config

	sync.Mutex
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
		chains: SystemChains{
			Rules: make(map[string]*SystemRule),
		},
	}
	return ipt, nil
}

// Name returns the firewall name
func (ipt *Iptables) Name() string {
	return Name
}

// Init inserts the firewall rules and starts monitoring for firewall
// changes.
func (ipt *Iptables) Init(qNum *int, configPath, monitorInterval string) {
	if ipt.IsRunning() {
		return
	}
	ipt.SetQueueNum(qNum)
	ipt.SetRulesCheckerInterval(monitorInterval)
	ipt.ErrChan = make(chan string, 100)

	// In order to clean up any existing firewall rule before start,
	// we need to load the fw configuration first to know what rules
	// were configured.
	ipt.NewSystemFwConfig(configPath, ipt.preloadConfCallback, ipt.reloadRulesCallback)
	ipt.LoadDiskConfiguration(!common.ReloadConf)

	// start from a clean state
	ipt.CleanRules(false)
	ipt.EnableInterception()
	ipt.AddSystemRules(!common.ReloadRules, common.BackupChains)

	ipt.Running = true
}

// Stop deletes the firewall rules, allowing network traffic.
func (ipt *Iptables) Stop() {
	ipt.ErrChan = make(chan string, 100)
	if ipt.Running == false {
		return
	}
	ipt.StopConfigWatcher()
	ipt.StopCheckingRules()
	ipt.CleanRules(log.GetLogLevel() == log.DEBUG)

	ipt.Running = false
}

// IsAvailable checks if iptables is installed in the system.
// If it's not, we'll default to nftables.
func IsAvailable() error {
	_, err := exec.Command("iptables", []string{"-V"}...).CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

// EnableInterception adds fw rules to intercept connections.
func (ipt *Iptables) EnableInterception() {
	if err4, err6 := ipt.QueueConnections(common.EnableRule, true); err4 != nil || err6 != nil {
		log.Fatal("Error while running conntrack firewall rule: %s %s", err4, err6)
	} else if err4, err6 = ipt.QueueDNSResponses(common.EnableRule, true); err4 != nil || err6 != nil {
		log.Error("Error while running DNS firewall rule: %s %s", err4, err6)
	}
	// start monitoring firewall rules to intercept network traffic
	ipt.NewRulesChecker(ipt.AreRulesLoaded, ipt.reloadRulesCallback)
}

// DisableInterception removes firewall rules to intercept outbound connections.
func (ipt *Iptables) DisableInterception(logErrors bool) {
	ipt.StopCheckingRules()
	ipt.QueueDNSResponses(!common.EnableRule, logErrors)
	ipt.QueueConnections(!common.EnableRule, logErrors)
}

// CleanRules deletes the rules we added.
func (ipt *Iptables) CleanRules(logErrors bool) {
	ipt.DisableInterception(logErrors)
	ipt.DeleteSystemRules(common.ForcedDelRules, common.BackupChains, logErrors)
}

// Serialize converts the configuration from json to protobuf
func (ipt *Iptables) Serialize() (*protocol.SysFirewall, error) {
	sysfw := &protocol.SysFirewall{}
	jun := jsonpb.Unmarshaler{
		AllowUnknownFields: true,
	}
	rawConfig, err := json.Marshal(&ipt.SysConfig)
	if err != nil {
		log.Error("nfables.Serialize() struct to string error: %s", err)
		return nil, err
	}
	// string to proto
	if err := jun.Unmarshal(strings.NewReader(string(rawConfig)), sysfw); err != nil {
		log.Error("nfables.Serialize() string to protobuf error: %s", err)
		return nil, err
	}

	return sysfw, nil
}

// Deserialize converts a protocolbuffer structure to json.
func (ipt *Iptables) Deserialize(sysfw *protocol.SysFirewall) ([]byte, error) {
	jun := jsonpb.Marshaler{
		OrigName:     true,
		EmitDefaults: false,
		Indent:       "  ",
	}

	var b bytes.Buffer
	if err := jun.Marshal(&b, sysfw); err != nil {
		log.Error("nfables.Deserialize() error 2: %s", err)
		return nil, err
	}
	return b.Bytes(), nil

	//return nil, fmt.Errorf("iptables.Deserialize() not implemented")
}
