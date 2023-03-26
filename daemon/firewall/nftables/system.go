package nftables

import (
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/firewall/nftables/exprs"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/uuid"
)

var (
	logTag        = "nftables:"
	sysTables     map[string]*nftables.Table
	sysChains     map[string]*nftables.Chain
	origSysChains map[string]*nftables.Chain
	sysSets       []*nftables.Set
)

func initMapsStore() {
	sysTables = make(map[string]*nftables.Table)
	sysChains = make(map[string]*nftables.Chain)
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

	chainHook := getHook(chain.Hook)
	chainPrio, chainType := getChainPriority(chain.Family, chain.Type, chain.Hook)
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
	n.SysConfig.GetSystemRules()

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
					n.AddSystemRule(chain.Rules[i], chain)
				}
			}
		}
	}
}

// DeleteSystemRules deletes the system rules.
// If force is false and the rule has not been previously added,
// it won't try to delete the tables and chains. Otherwise it'll try to delete them.
func (n *Nft) DeleteSystemRules(force, restoreExistingChains, logErrors bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if err := n.delRulesByKey(systemRuleKey); err != nil {
		log.Warning("error deleting interception rules: %s", err)
	}

	if restoreExistingChains {
		n.restoreBackupChains()
	}
	if force {
		n.delSystemTables()
	}
}

// AddSystemRule inserts a new rule.
func (n *Nft) AddSystemRule(rule *config.FwRule, chain *config.FwChain) *common.FirewallError {
	n.mu.Lock()
	defer n.mu.Unlock()
	exprList := []expr.Any{}

	for _, expression := range rule.Expressions {
		if exprsOfRule := n.parseExpression(chain.Table, chain.Name, chain.Family, expression); exprsOfRule != nil {
			exprList = append(exprList, *exprsOfRule...)
		}
	}
	if len(exprList) > 0 {
		exprVerdict := exprs.NewExprVerdict(rule.Target, rule.TargetParameters)
		exprList = append(exprList, *exprVerdict...)
		if err := n.insertRule(chain.Name, chain.Table, chain.Family, rule.Position, &exprList); err != nil {
			log.Warning("error adding rule: %v", rule)
		}
	}

	return nil
}
