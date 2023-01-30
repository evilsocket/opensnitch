package iptables

import (
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/firewall/common"
	"github.com/evilsocket/opensnitch/daemon/log"
)

// AreRulesLoaded checks if the firewall rules for intercept traffic are loaded.
func (ipt *Iptables) AreRulesLoaded() bool {
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
	ipt.chains.RLock()
	if len(ipt.chains.Rules) > 0 {
		for _, rule := range ipt.chains.Rules {
			if chainOut4, err4 := core.Exec("iptables", []string{"-n", "-L", rule.Chain, "-t", rule.Table}); err4 == nil {
				if ipt.regexSystemRulesQuery.FindString(chainOut4) == "" {
					systemRulesLoaded = false
					break
				}
			}
			if core.IPv6Enabled {
				if chainOut6, err6 := core.Exec("ip6tables", []string{"-n", "-L", rule.Chain, "-t", rule.Table}); err6 == nil {
					if ipt.regexSystemRulesQuery.FindString(chainOut6) == "" {
						systemRulesLoaded = false
						break
					}
				}
			}
		}
	}
	ipt.chains.RUnlock()

	result := ipt.regexRulesQuery.FindString(outMangle) != "" &&
		systemRulesLoaded

	if core.IPv6Enabled {
		result = result && ipt.regexRulesQuery.FindString(outMangle6) != ""
	}

	return result
}

// reloadRulesCallback gets called when the interception rules are not present or after the configuration file changes.
func (ipt *Iptables) reloadRulesCallback() {
	log.Important("firewall rules changed, reloading")
	ipt.CleanRules(false)
	ipt.AddSystemRules(common.ReloadRules, common.BackupChains)
	ipt.EnableInterception()
}

// preloadConfCallback gets called before the fw configuration is reloaded
func (ipt *Iptables) preloadConfCallback() {
	log.Info("iptables config changed, reloading")
	ipt.DeleteSystemRules(common.ForcedDelRules, common.BackupChains, log.GetLogLevel() == log.DEBUG)
}
