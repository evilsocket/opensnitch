package iptables

import (
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/firewall/config"
)

// CreateSystemRule creates the custom firewall chains and adds them to the system.
func (ipt *Iptables) CreateSystemRule(rule *config.FwRule, table, chain, hook string, logErrors bool) bool {
	ipt.chains.Lock()
	defer ipt.chains.Unlock()
	if rule == nil {
		return false
	}
	if table == "" {
		table = "filter"
	}
	if hook == "" {
		hook = rule.Chain
	}

	chainName := SystemRulePrefix + "-" + hook
	if _, ok := ipt.chains.Rules[table+"-"+chainName]; ok {
		return false
	}
	ipt.RunRule(NEWCHAIN, common.EnableRule, logErrors, []string{chainName, "-t", table})

	// Insert the rule at the top of the chain
	if err4, err6 := ipt.RunRule(INSERT, common.EnableRule, logErrors, []string{hook, "-t", table, "-j", chainName}); err4 == nil && err6 == nil {
		ipt.chains.Rules[table+"-"+chainName] = &SystemRule{
			Table: table,
			Chain: chain,
			Rule:  rule,
		}
	}
	return true

}

// AddSystemRules creates the system firewall from configuration.
func (ipt *Iptables) AddSystemRules(reload, backupExistingChains bool) {
	// Version 0 has no Enabled field, so it'd be always false
	if ipt.SysConfig.Enabled == false && ipt.SysConfig.Version > 0 {
		return
	}

	for _, cfg := range ipt.SysConfig.SystemRules {
		if cfg.Rule != nil {
			ipt.CreateSystemRule(cfg.Rule, cfg.Rule.Table, cfg.Rule.Chain, cfg.Rule.Chain, common.EnableRule)
			ipt.AddSystemRule(ADD, cfg.Rule, cfg.Rule.Table, cfg.Rule.Chain, common.EnableRule)
			continue
		}

		if cfg.Chains != nil {
			for _, chn := range cfg.Chains {
				if chn.Hook != "" && chn.Type != "" {
					ipt.ConfigureChainPolicy(chn.Type, chn.Hook, chn.Policy, true)
				}
			}
		}
	}
}

// DeleteSystemRules deletes the system rules.
// If force is false and the rule has not been previously added,
// it won't try to delete the rules. Otherwise it'll try to delete them.
func (ipt *Iptables) DeleteSystemRules(force, backupExistingChains, logErrors bool) {
	ipt.chains.Lock()
	defer ipt.chains.Unlock()

	for _, fwCfg := range ipt.SysConfig.SystemRules {
		if fwCfg.Rule == nil {
			continue
		}
		chain := SystemRulePrefix + "-" + fwCfg.Rule.Chain
		if _, ok := ipt.chains.Rules[fwCfg.Rule.Table+"-"+chain]; !ok && !force {
			continue
		}
		ipt.RunRule(FLUSH, common.EnableRule, false, []string{chain, "-t", fwCfg.Rule.Table})
		ipt.RunRule(DELETE, !common.EnableRule, logErrors, []string{fwCfg.Rule.Chain, "-t", fwCfg.Rule.Table, "-j", chain})
		ipt.RunRule(DELCHAIN, common.EnableRule, false, []string{chain, "-t", fwCfg.Rule.Table})
		delete(ipt.chains.Rules, fwCfg.Rule.Table+"-"+chain)

		for _, chn := range fwCfg.Chains {
			if chn.Table == "" {
				chn.Table = "filter"
			}
			chain := SystemRulePrefix + "-" + chn.Hook
			if _, ok := ipt.chains.Rules[chn.Type+"-"+chain]; !ok && !force {
				continue
			}

			ipt.RunRule(FLUSH, common.EnableRule, logErrors, []string{chain, "-t", chn.Type})
			ipt.RunRule(DELETE, !common.EnableRule, logErrors, []string{chn.Hook, "-t", chn.Type, "-j", chain})
			ipt.RunRule(DELCHAIN, common.EnableRule, logErrors, []string{chain, "-t", chn.Type})
			delete(ipt.chains.Rules, chn.Type+"-"+chain)

		}
	}
}

// DeleteSystemRule deletes a new rule.
func (ipt *Iptables) DeleteSystemRule(action Action, rule *config.FwRule, table, chain string, enable bool) (err4, err6 error) {
	chainName := SystemRulePrefix + "-" + chain
	if table == "" {
		table = "filter"
	}
	r := []string{chainName, "-t", table}
	if rule.Parameters != "" {
		r = append(r, strings.Split(rule.Parameters, " ")...)
	}
	r = append(r, []string{"-j", rule.Target}...)
	if rule.TargetParameters != "" {
		r = append(r, strings.Split(rule.TargetParameters, " ")...)
	}

	return ipt.RunRule(action, enable, true, r)
}

// AddSystemRule inserts a new rule.
func (ipt *Iptables) AddSystemRule(action Action, rule *config.FwRule, table, chain string, enable bool) (err4, err6 error) {
	if rule == nil {
		return nil, nil
	}
	ipt.RLock()
	defer ipt.RUnlock()

	chainName := SystemRulePrefix + "-" + chain
	if table == "" {
		table = "filter"
	}
	r := []string{chainName, "-t", table}
	if rule.Parameters != "" {
		r = append(r, strings.Split(rule.Parameters, " ")...)
	}
	r = append(r, []string{"-j", rule.Target}...)
	if rule.TargetParameters != "" {
		r = append(r, strings.Split(rule.TargetParameters, " ")...)
	}

	return ipt.RunRule(ADD, enable, true, r)
}

// ConfigureChainPolicy configures chains policy.
func (ipt *Iptables) ConfigureChainPolicy(table, hook, policy string, logError bool) {
	// TODO: list all policies before modify them, and restore the original state on exit.
	// still, if we exit abruptly, we might left the system badly configured.
	ipt.RunRule(POLICY, true, logError, []string{
		hook,
		strings.ToUpper(policy),
		"-t", table,
	})
}
