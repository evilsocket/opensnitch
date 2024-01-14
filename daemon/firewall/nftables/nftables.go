package nftables

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"github.com/golang/protobuf/jsonpb"
	"github.com/google/nftables"
)

// Action is the modifier we apply to a rule.
type Action string

// Actions we apply to the firewall.
const (
	fwKey               = "opensnitch-key"
	InterceptionRuleKey = fwKey + "-interception"
	SystemRuleKey       = fwKey + "-system"
	Name                = "nftables"
)

var (
	filterTable = &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   exprs.NFT_CHAIN_FILTER,
	}

	mangleTable = &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   exprs.NFT_CHAIN_FILTER,
	}
)

// Nft holds the fields of our nftables firewall
type Nft struct {
	Conn   *nftables.Conn
	chains iptables.SystemChains

	common.Common
	config.Config
	sync.Mutex
}

// NewNft creates a new nftables object
func NewNft() *nftables.Conn {
	return &nftables.Conn{}
}

// Fw initializes a new nftables object
func Fw() (*Nft, error) {
	n := &Nft{
		chains: iptables.SystemChains{
			Rules: make(map[string]*iptables.SystemRule),
		},
	}
	return n, nil
}

// Name returns the name of the firewall
func (n *Nft) Name() string {
	return Name
}

// Init inserts the firewall rules and starts monitoring for firewall
// changes.
func (n *Nft) Init(qNum *int, configPath, monitorInterval string) {
	if n.IsRunning() {
		return
	}
	n.Conn = NewNft()
	n.ErrChan = make(chan string, 100)
	InitMapsStore()
	n.SetQueueNum(qNum)
	n.SetRulesCheckerInterval(monitorInterval)

	// In order to clean up any existing firewall rule before start,
	// we need to load the fw configuration first to know what rules
	// were configured.
	n.NewSystemFwConfig(configPath, n.PreloadConfCallback, n.ReloadConfCallback)
	n.LoadDiskConfiguration(!common.ReloadConf)

	// start from a clean state
	// The daemon may have exited unexpectedly, leaving residual fw rules, so we
	// need to clean them up to avoid duplicated rules.
	n.DelInterceptionRules()
	n.AddSystemRules(!common.ReloadRules, common.BackupChains)
	n.EnableInterception()

	n.Running = true
}

// Stop deletes the firewall rules, allowing network traffic.
func (n *Nft) Stop() {
	n.ErrChan = make(chan string, 100)
	if n.IsRunning() == false {
		return
	}
	n.StopConfigWatcher()
	n.StopCheckingRules()
	n.CleanRules(log.GetLogLevel() == log.DEBUG)

	n.Lock()
	n.Running = false
	n.Unlock()
}

// EnableInterception adds firewall rules to intercept connections
func (n *Nft) EnableInterception() {
	if err := n.AddInterceptionTables(); err != nil {
		log.Error("Error while adding interception tables: %s", err)
		return
	}
	if err := n.AddInterceptionChains(); err != nil {
		log.Error("Error while adding interception chains: %s", err)
		return
	}

	if err, _ := n.QueueDNSResponses(common.EnableRule, common.EnableRule); err != nil {
		log.Error("Error while running DNS nftables rule: %s", err)
	}
	if err, _ := n.QueueConnections(common.EnableRule, common.EnableRule); err != nil {
		log.Error("Error while running conntrack nftables rule: %s", err)
	}
	// start monitoring firewall rules to intercept network traffic.
	n.NewRulesChecker(n.AreRulesLoaded, n.ReloadRulesCallback)
}

// DisableInterception removes firewall rules to intercept outbound connections.
func (n *Nft) DisableInterception(logErrors bool) {
	n.StopCheckingRules()
	n.DelInterceptionRules()
}

// CleanRules deletes the rules we added.
func (n *Nft) CleanRules(logErrors bool) {
	n.DisableInterception(logErrors)
	n.DeleteSystemRules(common.ForcedDelRules, common.RestoreChains, logErrors)
}

// Commit applies the queued changes, creating new objects (tables, chains, etc).
// You add rules, chains or tables, and after calling to Flush() they're added to the system.
// NOTE: it's very important not to call Flush() without queued tasks.
func (n *Nft) Commit() bool {
	if err := n.Conn.Flush(); err != nil {
		log.Warning("%s error applying changes: %s", logTag, err)
		return false
	}
	return true
}

// Serialize converts the configuration from json to protobuf
func (n *Nft) Serialize() (*protocol.SysFirewall, error) {
	sysfw := &protocol.SysFirewall{}
	jun := jsonpb.Unmarshaler{
		AllowUnknownFields: true,
	}
	rawConfig, err := json.Marshal(&n.SysConfig)
	if err != nil {
		log.Error("nftables.Serialize() struct to string error: %s", err)
		return nil, err
	}
	// string to proto
	if err := jun.Unmarshal(strings.NewReader(string(rawConfig)), sysfw); err != nil {
		log.Error("nftables.Serialize() string to protobuf error: %s", err)
		return nil, err
	}

	return sysfw, nil
}

// Deserialize converts a protocolbuffer structure to byte array.
func (n *Nft) Deserialize(sysfw *protocol.SysFirewall) ([]byte, error) {
	jun := jsonpb.Marshaler{
		OrigName:     true,
		EmitDefaults: true,
		Indent:       "  ",
	}

	// NOTE: '<' and '>' characters are encoded to unicode (\u003c).
	// This has no effect on adding rules to nftables.
	// Users can still write "<" if they want to, rules are added ok.

	var b bytes.Buffer
	if err := jun.Marshal(&b, sysfw); err != nil {
		log.Error("nfables.Deserialize() error 2: %s", err)
		return nil, err
	}
	return b.Bytes(), nil
}
