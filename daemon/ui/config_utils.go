package ui

import (
	"fmt"
	"reflect"
	"strings"

	"runtime/debug"

	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netlink"
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

func (c *Client) getCurrentSocketPath() string {
	c.RLock()
	defer c.RUnlock()

	return c.socketPath
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
	// https://pkg.go.dev/github.com/fsnotify/fsnotify#Watcher.Add
	// "A watch will be automatically removed if the watched path is deleted or renamed"
	// "A path can only be watched once; watching it more than once is a no-op and will not return an error"
	//
	// Add the config file every time we read the file, to survive:
	// - malformed json file
	// - intermediate file removal (when writing we receive 2 write events, one of 0 bytes)
	if err := c.configWatcher.Add(configFile); err != nil {
		log.Error("Could not watch path: %s", err)
	}

	raw, err := config.Load(configFile)
	if err != nil || len(raw) == 0 {
		// Sometimes we may receive 2 Write events on monitorConfigWorker,
		// Which may lead to read 0 bytes.
		log.Warning("Error loading configuration from disk %s: %s", configFile, err)
		return
	}

	err = c.loadConfiguration(reload, raw)
	if err != nil {
		log.Error("[client] error loading config file: %s", err.Error())
		c.SendWarningAlert(err.Error())
		return
	}

	if reload {
		return
	}
	go c.monitorConfigWorker()
}

func (c *Client) loadConfiguration(reload bool, rawConfig []byte) (errf error) {
	newConfig, err := config.Parse(rawConfig)
	if err != nil {
		return fmt.Errorf("parsing configuration %s: %s", configFile, err)
	}

	if err := c.reloadConfiguration(reload, &newConfig); err != nil {
		errf = fmt.Errorf("%s", err.Msg)
	}
	// We need to use the new config, even if some of the new options failed,
	// to avoid ending up running with an empty config.
	// On reloadConfig we should fall back to a default option if anything fails.
	c.Lock()
	c.config = newConfig
	c.Unlock()
	return errf
}

func (c *Client) reloadConfiguration(reload bool, newConfig *config.Config) (err *monitor.Error) {

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

	// 1. disconnect from the server (GUI) if the new server addr is empty.
	// 2. connect to the server (GUI) if the new server addr is not empty, and previous addr was empty.
	// 3. reconnect if:
	//   - Auth options changed.
	//   - previous addr was not empty, new addr is not empty and new addr has changed.
	reconnect := newConfig.Server.Authentication.Type != c.config.Server.Authentication.Type ||
		!reflect.DeepEqual(newConfig.Server.Authentication.TLSOptions, c.config.Server.Authentication.TLSOptions)
	connect := false

	if newConfig.Server.Address == "" {
		log.Debug("[config] config.server.address changed, disconnecting from %s", c.socketPath)
		c.setSocketPath("")
	}
	if newConfig.Server.Address != "" && newConfig.Server.Address != c.config.Server.Address {
		tempSocketPath := c.getSocketPath(newConfig.Server.Address)
		log.Debug("[config] using new config.server.address: %s -> %s", c.config.Server.Address, newConfig.Server.Address)
		if tempSocketPath != c.socketPath {
			// disconnect, and let the connection poller reconnect to the new address
			reconnect = true
		}
		c.setSocketPath(tempSocketPath)
		// if we were not connected (i.e.: connection poller stopped), connect again.
		if c.config.Server.Address == "" {
			log.Debug("[config] previous address was empty, connected: %v, connecting to %s", c.Connected(), tempSocketPath)
			c.config.Server.Address = newConfig.Server.Address
			connect = true
		}
	}
	log.Debug("[config] server.address old: %s, new: %s, reconnect: %v, connect: %v", c.config.Server.Address, newConfig.Server.Address, reconnect, connect)

	if reconnect {
		log.Debug("[config] config.server.address.* changed, disconnecting from %s", c.config.Server.Address)
		c.disconnect()
	}
	if connect {
		log.Debug("[config] config.server. changed, connecting to %s", c.socketPath)
		c.Connect()
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

	// 1. load rules
	c.rules.EnableChecksums(newConfig.Rules.EnableChecksums)
	if newConfig.Rules.Path == "" || c.config.Rules.Path != newConfig.Rules.Path {
		c.rules.Reload(newConfig.Rules.Path)
		log.Debug("[config] reloading config.rules.path, old: <%s> new: <%s>", c.config.Rules.Path, newConfig.Rules.Path)
	} else {
		log.Debug("[config] config.rules.path not changed")
	}

	// 2. load proc mon method
	reloadProc := false
	if c.config.ProcMonitorMethod == "" ||
		newConfig.ProcMonitorMethod != c.config.ProcMonitorMethod {
		log.Debug("[config] reloading config.ProcMonMethod, old: %s -> new: %s", c.config.ProcMonitorMethod, newConfig.ProcMonitorMethod)
		reloadProc = true
	} else {
		log.Debug("[config] config.ProcMonMethod not changed")
	}

	if reload && procmon.MethodIsEbpf() &&
		!reflect.DeepEqual(newConfig.Ebpf, c.config.Ebpf) {
		log.Debug("[config] reloading config.Ebpf: %v", newConfig.Ebpf)
		reloadProc = true
	} else {
		log.Debug("[config] config.Ebpf.ModulesPath not changed")
	}

	if reload && procmon.MethodIsAudit() &&
		!reflect.DeepEqual(newConfig.Audit, c.config.Audit) {
		log.Debug("[config] reloading config.Audit: %v", newConfig.Audit)
		reloadProc = true
	} else {
		log.Debug("[config] config.Audit not changed")
	}

	// 3. load fw
	reloadFw := false
	if c.GetFirewallType() != newConfig.Firewall ||
		newConfig.FwOptions.ConfigPath != c.config.FwOptions.ConfigPath ||
		newConfig.FwOptions.QueueNum != c.config.FwOptions.QueueNum ||
		newConfig.FwOptions.MonitorInterval != c.config.FwOptions.MonitorInterval ||
		newConfig.FwOptions.QueueBypass != c.config.FwOptions.QueueBypass {
		log.Debug("[config] reloading config.firewall")
		reloadFw = true

		if err := firewall.Reload(
			newConfig.Firewall,
			newConfig.FwOptions.ConfigPath,
			newConfig.FwOptions.MonitorInterval,
			newConfig.FwOptions.QueueBypass,
			newConfig.FwOptions.QueueNum,
		); err != nil {
			log.Error("[config] firewall reload error: %s", err)
		}
	} else {
		log.Debug("[config] config.firewall not changed")
	}

	// 4. reload procmon if needed
	if reloadProc {
		err = monitor.ReconfigureMonitorMethod(newConfig.ProcMonitorMethod, newConfig.Ebpf, newConfig.Audit)
		// override newConfig's procMon with the one configured on Reconfig,
		// which should be the last known good one (or proc by default).
		if err != nil && (err.What == monitor.EbpfErr || err.What == monitor.AuditdErr) {
			newConfig.ProcMonitorMethod = procmon.GetMonitorMethod()
		}
	} else {
		log.Debug("[config] config.procmon not changed")
	}

	if (reloadProc || reloadFw) && newConfig.Internal.FlushConnsOnStart {
		log.Debug("[config] flushing established connections")
		netlink.FlushConnections()
	} else {
		log.Debug("[config] not flushing established connections")
	}

	return err
}
