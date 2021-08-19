package iptables

import (
	"strings"

	"github.com/evilsocket/opensnitch/daemon/firewall/config"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// CreateSystemRule creates the custom firewall chains and adds them to the system.
func (ipt *Iptables) CreateSystemRule(rule *config.FwRule, logErrors bool) {
	ipt.chains.Lock()
	defer ipt.chains.Unlock()
	if rule == nil {
		return
	}

	chainName := SystemRulePrefix + "-" + rule.Chain
	if _, ok := ipt.chains.Rules[rule.Table+"-"+chainName]; ok {
		return
	}
	ipt.RunRule(NEWCHAIN, true, logErrors, []string{chainName, "-t", rule.Table})

	// Insert the rule at the top of the chain
	if err4, err6 := ipt.RunRule(INSERT, true, logErrors, []string{rule.Chain, "-t", rule.Table, "-j", chainName}); err4 == nil && err6 == nil {
		ipt.chains.Rules[rule.Table+"-"+chainName] = *rule
	}
}

// DeleteSystemRules deletes the system rules.
// If force is false and the rule has not been previously added,
// it won't try to delete the rules. Otherwise it'll try to delete them.
func (ipt *Iptables) DeleteSystemRules(force, logErrors bool) {
	ipt.chains.Lock()
	defer ipt.chains.Unlock()

	for _, r := range ipt.SysConfig.SystemRules {
		if r.Rule == nil {
			continue
		}
		chain := SystemRulePrefix + "-" + r.Rule.Chain
		if _, ok := ipt.chains.Rules[r.Rule.Table+"-"+chain]; !ok && !force {
			continue
		}
		ipt.RunRule(FLUSH, true, false, []string{chain, "-t", r.Rule.Table})
		ipt.RunRule(DELETE, false, logErrors, []string{r.Rule.Chain, "-t", r.Rule.Table, "-j", chain})
		ipt.RunRule(DELCHAIN, true, false, []string{chain, "-t", r.Rule.Table})
		delete(ipt.chains.Rules, r.Rule.Table+"-"+chain)
	}
}

// AddSystemRule inserts a new rule.
func (ipt *Iptables) AddSystemRule(rule *config.FwRule, enable bool) (err4, err6 error) {
	if rule == nil {
		return nil, nil
	}
	rule.RLock()
	defer rule.RUnlock()

	chain := SystemRulePrefix + "-" + rule.Chain
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

	return ipt.RunRule(ADD, enable, true, r)
}

// AddSystemRules creates the system firewall from configuration.
func (ipt *Iptables) AddSystemRules() {
	ipt.DeleteSystemRules(true, false)

	for _, r := range ipt.SysConfig.SystemRules {
		ipt.CreateSystemRule(r.Rule, true)
		ipt.AddSystemRule(r.Rule, true)
	}
}

// preloadConfCallback gets called before the fw configuration is reloaded
func (ipt *Iptables) preloadConfCallback() {
	ipt.DeleteSystemRules(true, log.GetLogLevel() == log.DEBUG)
}
