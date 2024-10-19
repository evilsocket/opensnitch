package ui

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/firewall/iptables"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
)

var (
	defaultConfig = &config.Config{
		ProcMonitorMethod: procmon.MethodProc,
		DefaultAction:     "allow",
		DefaultDuration:   "once",
		InterceptUnknown:  false,
		Firewall:          "nftables",
		Rules: config.RulesOptions{
			Path: "/etc/opensnitchd/rules",
		},
	}
)

func restoreConfigFile(t *testing.T) {
	// start from a clean state
	if _, err := core.Exec("cp", []string{
		// unmodified default config
		"./testdata/default-config.json.orig",
		// config will be modified by some tests
		"./testdata/default-config.json",
	}); err != nil {
		t.Errorf("error copying default config file: %s", err)
	}
}

func validateConfig(t *testing.T, uiClient *Client, cfg *config.Config) {
	if uiClient.ProcMonitorMethod() != cfg.ProcMonitorMethod || procmon.GetMonitorMethod() != uiClient.ProcMonitorMethod() {
		t.Errorf("not expected ProcMonitorMethod value: %s, expected: %s, procmon.MonitorMethod: %s", uiClient.ProcMonitorMethod(), cfg.ProcMonitorMethod, procmon.GetMonitorMethod())
	}
	if uiClient.GetFirewallType() != cfg.Firewall {
		t.Errorf("not expected FirewallType value: %s, expected: %s", uiClient.GetFirewallType(), cfg.Firewall)
	}
	if uiClient.InterceptUnknown() != cfg.InterceptUnknown {
		t.Errorf("not expected InterceptUnknown value: %v, expected: %v", uiClient.InterceptUnknown(), cfg.InterceptUnknown)
	}
	if uiClient.DefaultAction() != rule.Action(cfg.DefaultAction) {
		t.Errorf("not expected DefaultAction value: %s, expected: %s", clientDisconnectedRule.Action, cfg.DefaultAction)
	}
}

func TestClientConfigReloading(t *testing.T) {
	restoreConfigFile(t)
	cfgFile := "./testdata/default-config.json"

	rules, err := rule.NewLoader(false)
	if err != nil {
		log.Fatal("")
	}

	stats := statistics.New(rules)
	loggerMgr := loggers.NewLoggerManager()
	uiClient := NewClient("unix:///tmp/osui.sock", cfgFile, stats, rules, loggerMgr)

	t.Run("validate-load-config", func(t *testing.T) {
		validateConfig(t, uiClient, defaultConfig)
	})

	t.Run("validate-reload-config", func(t *testing.T) {
		reloadConfig := *defaultConfig
		//reloadConfig.ProcMonitorMethod = procmon.MethodProc
		reloadConfig.DefaultAction = string(rule.Deny)
		reloadConfig.InterceptUnknown = true
		reloadConfig.Firewall = iptables.Name
		reloadConfig.FwOptions.QueueBypass = true
		reloadConfig.Server.Address = "unix:///run/user/1000/opensnitch/osui.sock"

		plainJSON, err := json.Marshal(reloadConfig)
		if err != nil {
			t.Errorf("Error marshalling config: %s", err)
		}
		if err = config.Save(configFile, string(plainJSON)); err != nil {
			t.Errorf("error saving config to disk: %s", err)
		}
		// wait for the config to load
		time.Sleep(time.Second * 10)

		validateConfig(t, uiClient, &reloadConfig)
	})
}
