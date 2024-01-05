package nftables

import (
	"fmt"
	"strings"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/uuid"
)

// store of tables added to the system
type sysTablesT struct {
	tables map[string]*nftables.Table
	sync.RWMutex
}

func (t *sysTablesT) Add(name string, tbl *nftables.Table) {
	t.Lock()
	defer t.Unlock()
	t.tables[name] = tbl
}

func (t *sysTablesT) Get(name string) *nftables.Table {
	t.RLock()
	defer t.RUnlock()
	return t.tables[name]
}

func (t *sysTablesT) List() map[string]*nftables.Table {
	t.RLock()
	defer t.RUnlock()
	return t.tables
}

func (t *sysTablesT) Del(name string) {
	t.Lock()
	defer t.Unlock()
	delete(t.tables, name)
}

var (
	logTag        = "nftables:"
	sysTables     *sysTablesT
	sysChains     *sync.Map
	origSysChains map[string]*nftables.Chain
	sysSets       []*nftables.Set
)

// InitMapsStore initializes internal stores of chains and maps.
func InitMapsStore() {
	sysTables = &sysTablesT{
		tables: make(map[string]*nftables.Table),
	}
	sysChains = &sync.Map{}
	origSysChains = make(map[string]*nftables.Chain)
}

// CreateSystemRule create the custom firewall chains and adds them to system.
// nft insert rule ip opensnitch-filter opensnitch-input udp dport 1153
func (n *Nft) CreateSystemRule(chain *config.FwChain, logErrors bool) bool {
	if chain.IsInvalid() {
		log.Warning("%s CreateSystemRule(), Chain's field Name and Family cannot be empty", logTag)
		return false
	}

	tableName := chain.Table
	n.AddTable(chain.Table, chain.Family)

	// regular chains doesn't have a hook, nor a type
	if chain.Hook == "" && chain.Type == "" {
		n.addRegularChain(chain.Name, tableName, chain.Family)
		return n.Commit()
	}

	chainPolicy := nftables.ChainPolicyAccept
	if iptables.Action(strings.ToLower(chain.Policy)) == exprs.VERDICT_DROP {
		chainPolicy = nftables.ChainPolicyDrop
	}

	chainHook := GetHook(chain.Hook)
	chainPrio, chainType := GetChainPriority(chain.Family, chain.Type, chain.Hook)
	if chainPrio == nil {
		log.Warning("%s Invalid system firewall combination: %s, %s", logTag, chain.Type, chain.Hook)
		return false
	}

	if ret := n.AddChain(chain.Name, chain.Table, chain.Family, chainPrio,
		chainType, chainHook, chainPolicy); ret == nil {
		log.Warning("%s error adding chain: %s, table: %s", logTag, chain.Name, chain.Table)
		return false
	}

	return n.Commit()
}

// AddSystemRules creates the system firewall from configuration.
func (n *Nft) AddSystemRules(reload, backupExistingChains bool) {
	n.SysConfig.RLock()
	defer n.SysConfig.RUnlock()

	if n.SysConfig.Enabled == false {
		log.Important("[nftables] AddSystemRules() fw disabled")
		return
	}
	if backupExistingChains {
		n.backupExistingChains()
	}

	for _, fwCfg := range n.SysConfig.SystemRules {
		for _, chain := range fwCfg.Chains {
			if !n.CreateSystemRule(chain, true) {
				log.Info("createSystem failed: %s %s", chain.Name, chain.Table)
				continue
			}
			for i := len(chain.Rules) - 1; i >= 0; i-- {
				if chain.Rules[i].UUID == "" {
					uuid := uuid.New()
					chain.Rules[i].UUID = uuid.String()
				}
				if chain.Rules[i].Enabled {
					if err4, _ := n.AddSystemRule(chain.Rules[i], chain); err4 != nil {
						n.SendError(fmt.Sprintf("%s (%s)", err4, chain.Rules[i].UUID))
					}
				}
			}
		}
	}
}

// DeleteSystemRules deletes the system rules.
// If force is false and the rule has not been previously added,
// it won't try to delete the tables and chains. Otherwise it'll try to delete them.
func (n *Nft) DeleteSystemRules(force, restoreExistingChains, logErrors bool) {
	n.Lock()
	defer n.Unlock()

	if err := n.delRulesByKey(SystemRuleKey); err != nil {
		log.Warning("error deleting interception rules: %s", err)
	}

	if restoreExistingChains {
		n.restoreBackupChains()
	}
	if force {
		n.DelSystemTables()
	}
}

// AddSystemRule inserts a new rule.
func (n *Nft) AddSystemRule(rule *config.FwRule, chain *config.FwChain) (err4, err6 error) {
	n.Lock()
	defer n.Unlock()
	exprList := []expr.Any{}

	for _, expression := range rule.Expressions {
		exprsOfRule := n.parseExpression(chain.Table, chain.Name, chain.Family, expression)
		if exprsOfRule == nil {
			return fmt.Errorf("%s invalid rule parameters: %v", rule.UUID, expression), nil
		}
		exprList = append(exprList, *exprsOfRule...)
	}
	if len(exprList) > 0 {
		exprVerdict := exprs.NewExprVerdict(rule.Target, rule.TargetParameters)
		if exprVerdict == nil {
			return fmt.Errorf("%s invalid verdict %s %s", rule.UUID, rule.Target, rule.TargetParameters), nil
		}
		exprList = append(exprList, *exprVerdict...)
		if err := n.InsertRule(chain.Name, chain.Table, chain.Family, rule.Position, &exprList); err != nil {
			return err, nil
		}
	}

	return nil, nil
}
