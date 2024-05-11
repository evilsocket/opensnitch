package ui

import (
	"fmt"
	"reflect"
	"strings"

	"runtime/debug"

	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/procmon/monitor"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
)

func (c *Client) getSocketPath(socketPath string) string {
	c.Lock()
	defer c.Unlock()

	if strings.HasPrefix(socketPath, "unix:") == true {
		c.isUnixSocket = true
		c.unixSockPrefix = "unix"
		return socketPath[5:]
	}
	if strings.HasPrefix(socketPath, "unix-abstract:") == true {
		c.isUnixSocket = true
		c.unixSockPrefix = "unix-abstract"
		return socketPath[14:]
	}

	c.isUnixSocket = false
	return socketPath
}

func (c *Client) setSocketPath(socketPath string) {
	c.Lock()
	defer c.Unlock()

	c.socketPath = socketPath
}

func (c *Client) isProcMonitorEqual(newMonitorMethod string) bool {
	c.RLock()
	defer c.RUnlock()

	return newMonitorMethod == c.config.ProcMonitorMethod
}

func (c *Client) loadDiskConfiguration(reload bool) {
	raw, err := config.Load(configFile)
	if err != nil || len(raw) == 0 {
		// Sometimes we may receive 2 Write events on monitorConfigWorker,
		// Which may lead to read 0 bytes.
		log.Warning("Error loading configuration from disk %s: %s", configFile, err)
		return
	}

	err = c.loadConfiguration(reload, raw)
	if err == nil {
		if err := c.configWatcher.Add(configFile); err != nil {
			log.Error("Could not watch path: %s", err)
			return
		}
	} else {
		log.Error("[client] error loading config file: %s", err.Error())
		c.SendWarningAlert(err.Error())
	}

	if reload {
		return
	}
	go c.monitorConfigWorker()
}

func (c *Client) loadConfiguration(reload bool, rawConfig []byte) error {
	var err error
	newConfig, err := config.Parse(rawConfig)
	if err != nil {
		return fmt.Errorf("parsing configuration %s: %s", configFile, err)
	}

	if err := c.reloadConfiguration(reload, newConfig); err != nil {
		return fmt.Errorf("reloading configuration: %s", err.Msg)
	}
	c.Lock()
	c.config = newConfig
	c.Unlock()
	return nil
}

func (c *Client) reloadConfiguration(reload bool, newConfig config.Config) *monitor.Error {

	// firstly load config level, to detect further errors if any
	if newConfig.LogLevel != nil {
		log.SetLogLevel(int(*newConfig.LogLevel))
	}
	log.SetLogUTC(newConfig.LogUTC)
	log.SetLogMicro(newConfig.LogMicro)
	if newConfig.Server.LogFile != "" {
		log.Debug("[config] using config.server.logfile: %s", newConfig.Server.LogFile)
		log.Close()
		log.OpenFile(newConfig.Server.LogFile)
	}
	if !reflect.DeepEqual(c.config.Server.Loggers, newConfig.Server.Loggers) {
		log.Debug("[config] reloading config.server.loggers")
		c.loggers.Stop()
		c.loggers.Load(newConfig.Server.Loggers)
		c.stats.SetLoggers(c.loggers)
	} else {
		log.Debug("[config] config.server.loggers not changed")
	}

	if !reflect.DeepEqual(newConfig.Stats, c.config.Stats) {
		log.Debug("[config] reloading config.stats")
		c.stats.SetLimits(newConfig.Stats)
	} else {
		log.Debug("[config] config.stats not changed")
	}

	reconnect := newConfig.Server.Authentication.Type != c.config.Server.Authentication.Type ||
		!reflect.DeepEqual(newConfig.Server.Authentication.TLSOptions, c.config.Server.Authentication.TLSOptions)

	if newConfig.Server.Address != "" {
		tempSocketPath := c.getSocketPath(newConfig.Server.Address)
		log.Debug("[config] using config.server.address: %s", newConfig.Server.Address)
		if tempSocketPath != c.socketPath {
			// disconnect, and let the connection poller reconnect to the new address
			reconnect = true
		}
		c.setSocketPath(tempSocketPath)
	}

	if reconnect {
		log.Debug("[config] config.server.address.* changed, reconnecting to %s", c.socketPath)
		c.disconnect()
	}

	if newConfig.DefaultAction != "" {
		clientDisconnectedRule.Action = rule.Action(newConfig.DefaultAction)
		clientErrorRule.Action = rule.Action(newConfig.DefaultAction)
		// TODO: reconfigure connected rule if changed, but not save it to disk.
		//clientConnectedRule.Action = rule.Action(newConfig.DefaultAction)
	}

	if newConfig.DefaultDuration != "" {
		clientDisconnectedRule.Duration = rule.Duration(newConfig.DefaultDuration)
		clientErrorRule.Duration = rule.Duration(newConfig.DefaultDuration)
	}

	if newConfig.Internal.GCPercent > 0 && newConfig.Internal.GCPercent != c.config.Internal.GCPercent {
		oldgcpercent := debug.SetGCPercent(newConfig.Internal.GCPercent)
		log.Debug("[config] GC percent set to %d, previously was %d", newConfig.Internal.GCPercent, oldgcpercent)
	} else {
		log.Debug("[config] config.internal.gcpercent not changed")
	}

	c.rules.EnableChecksums(newConfig.Rules.EnableChecksums)
	if c.config.Rules.Path != newConfig.Rules.Path {
		c.rules.Reload(newConfig.Rules.Path)
		log.Debug("[config] reloading config.rules.path: %s", newConfig.Rules.Path)
	} else {
		log.Debug("[config] config.rules.path not changed")
	}

	if reload && c.GetFirewallType() != newConfig.Firewall ||
		newConfig.FwOptions.ConfigPath != c.config.FwOptions.ConfigPath ||
		newConfig.FwOptions.MonitorInterval != c.config.FwOptions.MonitorInterval {
		log.Debug("[config] reloading config.firewall")

		firewall.Reload(
			newConfig.Firewall,
			newConfig.FwOptions.ConfigPath,
			newConfig.FwOptions.MonitorInterval,
		)
	} else {
		log.Debug("[config] config.firewall not changed")
	}

	reloadProc := false
	if c.config.ProcMonitorMethod == "" ||
		newConfig.ProcMonitorMethod != c.config.ProcMonitorMethod {
		log.Debug("[config] reloading config.ProcMonMethod, old: %s -> new: %s", c.config.ProcMonitorMethod, newConfig.ProcMonitorMethod)
		reloadProc = true
	} else {
		log.Debug("[config] config.ProcMonMethod not changed")
	}

	if reload && procmon.MethodIsEbpf() && newConfig.Ebpf.ModulesPath != "" && c.config.Ebpf.ModulesPath != newConfig.Ebpf.ModulesPath {
		log.Debug("[config] reloading config.Ebpf.ModulesPath: %s", newConfig.Ebpf.ModulesPath)
		reloadProc = true
	} else {
		log.Debug("[config] config.Ebpf.ModulesPath not changed")
	}
	if reloadProc {
		err := monitor.ReconfigureMonitorMethod(newConfig.ProcMonitorMethod, newConfig.Ebpf.ModulesPath)
		if err != nil && err.What > monitor.NoError {
			return err
		}
	} else {
		log.Debug("[config] config.procmon not changed")
	}

	return nil
}
