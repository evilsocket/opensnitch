package nftables

import (
	"sync"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
)

const (
	// Name is the name that identifies this firewall
	Name = "nftables"

	mangleTableName = "mangle"
	filterTableName = "filter"
	// The following chains will be under our own mangle or filter tables.
	// There shouldn't be other chains with the same name here.
	outputChain = "output"
	inputChain  = "input"
	// key assigned to every fw rule we add, in order to get rules by this key.
	fwKey = "opensnitch-key"
)

var (
	filterTable = &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   filterTableName,
	}
	filterTable6 = &nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   filterTableName,
	}
	mangleTable = &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   mangleTableName,
	}
	mangleTable6 = &nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   mangleTableName,
	}
)

// Nft holds the fields of our nftables firewall
type Nft struct {
	sync.Mutex
	config.Config
	common.Common

	conn *nftables.Conn

	mangleTables []*nftables.Table
	filterTables []*nftables.Table
	outputChains map[*nftables.Table]*nftables.Chain
	inputChains  map[*nftables.Table]*nftables.Chain

	chains iptables.SystemChains
}

// NewNft creates a new nftables object
func NewNft() *nftables.Conn {
	return &nftables.Conn{}
}

// Fw initializes a new nftables object
func Fw() (*Nft, error) {
	n := &Nft{
		outputChains: make(map[*nftables.Table]*nftables.Chain),
		inputChains:  make(map[*nftables.Table]*nftables.Chain),
		chains:       iptables.SystemChains{Rules: make(map[string]config.FwRule)},
	}
	return n, nil
}

// Name returns the name of the firewall
func (n *Nft) Name() string {
	return Name
}

// Init inserts the firewall rules and starts monitoring for firewall
// changes.
func (n *Nft) Init(qNum *int) {
	if n.IsRunning() {
		return
	}
	n.SetQueueNum(qNum)
	n.conn = NewNft()

	// In order to clean up any existing firewall rule before start,
	// we need to load the fw configuration first.
	n.NewSystemFwConfig(n.preloadConfCallback)
	go n.MonitorSystemFw(n.AddSystemRules)
	n.LoadDiskConfiguration(false)

	// start from a clean state
	n.CleanRules(false)
	n.AddSystemRules()

	n.InsertRules()
	// start monitoring firewall rules to intercept network traffic.
	n.NewRulesChecker(n.AreRulesLoaded, n.reloadRulesCallback)

	n.Running = true
}

// Stop deletes the firewall rules, allowing network traffic.
func (n *Nft) Stop() {
	if n.IsRunning() == false {
		return
	}
	n.StopConfigWatcher()
	n.StopCheckingRules()
	n.CleanRules(log.GetLogLevel() == log.DEBUG)

	n.Running = false
}

// InsertRules adds fw rules to intercept connections
func (n *Nft) InsertRules() {
	n.delInterceptionRules()
	n.addGlobalTables()
	n.addGlobalChains()

	if err, _ := n.QueueDNSResponses(true, true); err != nil {
		log.Error("Error while Running DNS nftables rule: %s", err)
	} else if err, _ = n.QueueConnections(true, true); err != nil {
		log.Fatal("Error while Running conntrack nftables rule: %s", err)
	}
}

// CleanRules deletes the rules we added.
func (n *Nft) CleanRules(logErrors bool) {
	n.delInterceptionRules()
	err := n.conn.Flush()
	if err != nil && logErrors {
		log.Error("Error cleaning nftables tables: %s", err)
	}
	n.DeleteSystemRules(true, logErrors)
}
