/*   Copyright (C) 2018      Simone Margaritelli
//                 2021      themighty1
//                 2022      calesanz
//                 2019-2022 Gustavo Iñiguez Goia
//
//   This file is part of OpenSnitch.
//
//   OpenSnitch is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   OpenSnitch is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	golog "log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"syscall"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/dns/systemd"
	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/evilsocket/opensnitch/daemon/procmon/ebpf"
	"github.com/evilsocket/opensnitch/daemon/procmon/monitor"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui"
	"github.com/evilsocket/opensnitch/daemon/ui/config"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
)

var (
	showVersion       = false
	checkRequirements = false
	procmonMethod     = ""
	logFile           = ""
	logUTC            = true
	logMicro          = false
	rulesPath         = "/etc/opensnitchd/rules/"
	configFile        = "/etc/opensnitchd/default-config.json"
	fwConfigFile      = "/etc/opensnitchd/system-fw.json"
	ebpfModPath       = "" // /usr/lib/opensnitchd/ebpf
	noLiveReload      = false
	queueNum          = 0
	repeatQueueNum    int //will be set later to queueNum + 1
	workers           = 16
	debug             = false
	warning           = false
	important         = false
	errorlog          = false

	uiSocket = ""
	uiClient = (*ui.Client)(nil)

	cpuProfile = ""
	memProfile = ""
	traceFile  = ""
	memFile    *os.File

	ctx           = (context.Context)(nil)
	cancel        = (context.CancelFunc)(nil)
	err           = (error)(nil)
	rules         = (*rule.Loader)(nil)
	stats         = (*statistics.Statistics)(nil)
	queue         = (*netfilter.Queue)(nil)
	repeatQueue   = (*netfilter.Queue)(nil)
	repeatPktChan = (<-chan netfilter.Packet)(nil)
	pktChan       = (<-chan netfilter.Packet)(nil)
	wrkChan       = (chan netfilter.Packet)(nil)
	sigChan       = (chan os.Signal)(nil)
	exitChan      = (chan bool)(nil)
	loggerMgr     *loggers.LoggerManager
	resolvMonitor *systemd.ResolvedMonitor
)

func init() {
	flag.BoolVar(&showVersion, "version", debug, "Show daemon version of this executable and exit.")
	flag.BoolVar(&checkRequirements, "check-requirements", debug, "Check system requirements for incompatibilities.")

	flag.StringVar(&procmonMethod, "process-monitor-method", procmonMethod, "How to search for processes path. Options: ftrace, audit (experimental), ebpf (experimental), proc (default)")
	flag.StringVar(&uiSocket, "ui-socket", uiSocket, "Path the UI gRPC service listener (https://github.com/grpc/grpc/blob/master/doc/naming.md).")
	flag.IntVar(&queueNum, "queue-num", queueNum, "Netfilter queue number.")
	flag.IntVar(&workers, "workers", workers, "Number of concurrent workers.")
	flag.BoolVar(&noLiveReload, "no-live-reload", debug, "Disable rules live reloading.")

	flag.StringVar(&rulesPath, "rules-path", rulesPath, "Path to load JSON rules from.")
	flag.StringVar(&configFile, "config-file", configFile, "Path to the daemon configuration file.")
	flag.StringVar(&fwConfigFile, "fw-config-file", fwConfigFile, "Path to the system fw configuration file.")
	//flag.StringVar(&ebpfModPath, "ebpf-modules-path", ebpfModPath, "Path to the directory with the eBPF modules.")
	flag.StringVar(&logFile, "log-file", logFile, "Write logs to this file instead of the standard output.")
	flag.BoolVar(&logUTC, "log-utc", logUTC, "Write logs output with UTC timezone (enabled by default).")
	flag.BoolVar(&logMicro, "log-micro", logMicro, "Write logs output with microsecond timestamp (disabled by default).")
	flag.BoolVar(&debug, "debug", debug, "Enable debug level logs.")
	flag.BoolVar(&warning, "warning", warning, "Enable warning level logs.")
	flag.BoolVar(&important, "important", important, "Enable important level logs.")
	flag.BoolVar(&errorlog, "error", errorlog, "Enable error level logs.")

	flag.StringVar(&cpuProfile, "cpu-profile", cpuProfile, "Write CPU profile to this file.")
	flag.StringVar(&memProfile, "mem-profile", memProfile, "Write memory profile to this file.")
	flag.StringVar(&traceFile, "trace-file", traceFile, "Write trace file to this file.")
}

// Load configuration file from disk, by default from /etc/opensnitchd/default-config.json,
// or from the path specified by configFile.
// This configuration will be loaded again by uiClient(), in order to monitor it for changes.
func loadDiskConfiguration() (*config.Config, error) {
	if configFile == "" {
		return nil, fmt.Errorf("Configuration file cannot be empty")
	}

	raw, err := config.Load(configFile)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("Error loading configuration %s: %s", configFile, err)
	}
	clientConfig, err := config.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("Error parsing configuration %s: %s", configFile, err)
	}

	log.Info("Loading configuration file %s ...", configFile)
	return &clientConfig, nil
}

func overwriteLogging() bool {
	return debug || warning || important || errorlog || logFile != "" || logMicro
}

func setupQueues() {
	// prepare the queue
	var err error
	queue, err = netfilter.NewQueue(uint16(queueNum))
	if err != nil {
		msg := fmt.Sprintf("Error creating queue #%d: %s", queueNum, err)
		uiClient.SendWarningAlert(msg)
		log.Warning("Is opensnitchd already running?")
		log.Fatal(msg)
	}
	pktChan = queue.Packets()

	repeatQueueNum = queueNum + 1

	repeatQueue, err = netfilter.NewQueue(uint16(repeatQueueNum))
	if err != nil {
		msg := fmt.Sprintf("Error creating repeat queue #%d: %s", repeatQueueNum, err)
		uiClient.SendErrorAlert(msg)
		log.Warning("Is opensnitchd already running?")
		log.Warning(msg)
	}
	repeatPktChan = repeatQueue.Packets()
}

func setupLogging() {
	golog.SetOutput(ioutil.Discard)
	if debug {
		log.SetLogLevel(log.DEBUG)
	} else if warning {
		log.SetLogLevel(log.WARNING)
	} else if important {
		log.SetLogLevel(log.IMPORTANT)
	} else if errorlog {
		log.SetLogLevel(log.ERROR)
	} else {
		log.SetLogLevel(log.INFO)
	}

	log.SetLogUTC(logUTC)
	log.SetLogMicro(logMicro)

	var logFileToUse string
	if logFile == "" {
		logFileToUse = log.StdoutFile
	} else {
		logFileToUse = logFile
	}
	log.Close()
	if err := log.OpenFile(logFileToUse); err != nil {
		log.Error("Error opening user defined log: %s %s", logFileToUse, err)
	}
}

func setupProfiling() {
	if traceFile != "" {
		log.Info("setup trace profile: %s", traceFile)
		f, err := os.Create(traceFile)
		if err != nil {
			log.Fatal("could not create trace profile: %s", err)
		}
		trace.Start(f)
	}
	if memProfile != "" {
		log.Info("setup mem profile: %s", memProfile)
		var err error
		memFile, err = os.Create(memProfile)
		if err != nil {
			log.Fatal("could not create memory profile: %s", err)
		}
	}
	if cpuProfile != "" {
		log.Info("setup cpu profile: %s", cpuProfile)
		if f, err := os.Create(cpuProfile); err != nil {
			log.Fatal("%s", err)
		} else if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("%s", err)
		}
	}
}

func setupSignals() {
	sigChan = make(chan os.Signal, 1)
	exitChan = make(chan bool, workers+1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		log.Raw("\n")
		log.Important("Got signal: %v", sig)
		cancel()
		time.AfterFunc(10*time.Second, func() {
			log.Error("[REVIEW] closing due to timeout")
			os.Exit(0)
		})
	}()
}

func worker(id int) {
	log.Debug("Worker #%d started.", id)
	for true {
		select {
		case <-ctx.Done():
			goto Exit
		default:
			pkt, ok := <-wrkChan
			if !ok {
				log.Debug("worker channel closed %d", id)
				goto Exit
			}
			onPacket(pkt)
		}
	}
Exit:
	log.Debug("worker #%d exit", id)
}

func setupWorkers() {
	log.Debug("Starting %d workers ...", workers)
	// setup the workers
	wrkChan = make(chan netfilter.Packet)
	for i := 0; i < workers; i++ {
		go worker(i)
	}
}

// Listen to events sent from other modules
func listenToEvents() {
	for i := 0; i < 5; i++ {
		go func(uiClient *ui.Client) {
			for evt := range ebpf.Events() {
				// for loop vars are per-loop, not per-item
				evt := evt
				uiClient.PostAlert(
					protocol.Alert_WARNING,
					protocol.Alert_KERNEL_EVENT,
					protocol.Alert_SHOW_ALERT,
					protocol.Alert_MEDIUM,
					evt)
			}
		}(uiClient)
	}
}

func initSystemdResolvedMonitor() {
	resolvMonitor, err := systemd.NewResolvedMonitor()
	if err != nil {
		log.Debug("[DNS] Unable to use systemd-resolved monitor: %s", err)
		return
	}
	_, err = resolvMonitor.Connect()
	if err != nil {
		log.Debug("[DNS] Connecting to systemd-resolved: %s", err)
		return
	}
	err = resolvMonitor.Subscribe()
	if err != nil {
		log.Debug("[DNS] Subscribing to systemd-resolved DNS events: %s", err)
		return
	}
	go func() {
		var ip net.IP
		for {
			select {
			case exit := <-resolvMonitor.Exit():
				if exit == nil {
					log.Info("[DNS] systemd-resolved monitor stopped")
					return
				}
				log.Debug("[DNS] systemd-resolved monitor disconnected. Reconnecting...")
			case response := <-resolvMonitor.GetDNSResponses():
				if response.State != systemd.SuccessState {
					log.Debug("[DNS] systemd-resolved monitor response error: %v", response)
					continue
				}
				/*for i, q := range response.Question {
					log.Debug("%d SYSTEMD RESPONSE Q: %s", i, q.Name)
				}*/
				for i, a := range response.Answer {
					if a.RR.Key.Type != systemd.DNSTypeA &&
						a.RR.Key.Type != systemd.DNSTypeAAAA &&
						a.RR.Key.Type != systemd.DNSTypeCNAME {
						log.Debug("systemd-resolved, excluding answer: %#v", a)
						continue
					}
					ip = net.IP(a.RR.Address)
					log.Debug("%d systemd-resolved monitor response: %s -> %s", i, a.RR.Key.Name, ip)
					if a.RR.Key.Type == systemd.DNSTypeCNAME {
						log.Debug("systemd-resolved CNAME >> %s -> %s", a.RR.Name, a.RR.Key.Name)
						dns.Track(a.RR.Name, a.RR.Key.Name /*domain*/)
					} else {
						dns.Track(ip.String(), a.RR.Key.Name /*domain*/)
					}
				}
			}
		}
	}()
}

func doCleanup(queue, repeatQueue *netfilter.Queue) {
	log.Info("Cleaning up ...")
	firewall.Stop()
	monitor.End()
	uiClient.Close()
	if resolvMonitor != nil {
		resolvMonitor.Close()
	}

	if cpuProfile != "" {
		pprof.StopCPUProfile()
	}

	if memProfile != "" {
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(memFile); err != nil {
			log.Error("Could not write memory profile: %s", err)
		}
		log.Info("Writing mem profile to %s", memProfile)
		memFile.Close()
	}
	if traceFile != "" {
		trace.Stop()
	}

	repeatQueue.Close()
	queue.Close()
}

func onPacket(packet netfilter.Packet) {
	// DNS response, just parse, track and accept.
	if dns.TrackAnswers(packet.Packet) == true {
		packet.SetVerdictAndMark(netfilter.NF_ACCEPT, packet.Mark)
		stats.OnDNSResponse()
		return
	}

	// Parse the connection state
	con := conman.Parse(packet, uiClient.InterceptUnknown())
	if con == nil {
		applyDefaultAction(&packet)
		return
	}
	// accept our own connections
	if con.Process.ID == os.Getpid() {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	// search a match in preloaded rules
	r := acceptOrDeny(&packet, con)

	if r != nil && r.Nolog {
		return
	}
	// XXX: if a connection is not intercepted due to InterceptUnknown == false,
	// it's not sent to the server, which leads to miss information.
	stats.OnConnectionEvent(con, r, r == nil)
}

func applyDefaultAction(packet *netfilter.Packet) {
	if uiClient.DefaultAction() == rule.Allow {
		packet.SetVerdictAndMark(netfilter.NF_ACCEPT, packet.Mark)
	} else {
		packet.SetVerdict(netfilter.NF_DROP)
	}
}

func acceptOrDeny(packet *netfilter.Packet, con *conman.Connection) *rule.Rule {
	r := rules.FindFirstMatch(con)
	if r == nil {
		// no rule matched
		// Note that as soon as we set a verdict on a packet, the next packet in the netfilter queue
		// will begin to be processed even if this function hasn't yet returned

		// send a request to the UI client if
		// 1) connected and running and 2) we are not already asking
		if uiClient.Connected() == false || uiClient.GetIsAsking() == true {
			applyDefaultAction(packet)
			log.Debug("UI is not running or busy, connected: %v, running: %v", uiClient.Connected(), uiClient.GetIsAsking())
			return nil
		}

		uiClient.SetIsAsking(true)
		defer uiClient.SetIsAsking(false)

		// In order not to block packet processing, we send our packet to a different netfilter queue
		// and then immediately pull it back out of that queue
		packet.SetRequeueVerdict(uint16(repeatQueueNum))

		var o bool
		var pkt netfilter.Packet
		// don't wait for the packet longer than 1 sec
		select {
		case pkt, o = <-repeatPktChan:
			if !o {
				log.Debug("error while receiving packet from repeatPktChan")
				return nil
			}
		case <-time.After(1 * time.Second):
			log.Debug("timed out while receiving packet from repeatPktChan")
			return nil
		}

		//check if the pulled out packet is the same we put in
		if res := bytes.Compare(packet.Packet.Data(), pkt.Packet.Data()); res != 0 {
			log.Error("The packet which was requeued has changed abruptly. This should never happen. Please report this incident to the Opensnitch developers. %v %v ", packet, pkt)
			return nil
		}
		packet = &pkt

		// Update the hostname again.
		// This is required due to a race between the ebpf dns hook and the actual first packet beeing sent
		if con.DstHost == "" {
			con.DstHost = dns.HostOr(con.DstIP, con.DstHost)
		}

		r = uiClient.Ask(con)
		if r == nil {
			log.Error("Invalid rule received, applying default action")
			applyDefaultAction(packet)
			return nil
		}
		ok := false
		pers := ""
		action := string(r.Action)
		if r.Action == rule.Allow {
			action = log.Green(action)
		} else {
			action = log.Red(action)
		}

		// check if and how the rule needs to be saved
		if r.Duration == rule.Always {
			pers = "Saved"
			// add to the loaded rules and persist on disk
			if err := rules.Add(r, true); err != nil {
				log.Error("Error while saving rule: %s", err)
			} else {
				ok = true
			}
		} else {
			pers = "Added"
			// add to the rules but do not save to disk
			if err := rules.Add(r, false); err != nil {
				log.Error("Error while adding rule: %s", err)
			} else {
				ok = true
			}
		}

		if ok {
			log.Important("%s new rule: %s if %s", pers, action, r.Operator.String())
		}

	}
	if packet == nil {
		log.Debug("Packet nil after processing rules")
		return r
	}

	if r.Enabled == false {
		applyDefaultAction(packet)
		ruleName := log.Green(r.Name)
		log.Info("DISABLED (%s) %s %s -> %s:%d (%s)", uiClient.DefaultAction(), log.Bold(log.Green("✔")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort, ruleName)

	} else if r.Action == rule.Allow {
		packet.SetVerdictAndMark(netfilter.NF_ACCEPT, packet.Mark)
		ruleName := log.Green(r.Name)
		if r.Operator.Operand == rule.OpTrue {
			ruleName = log.Dim(r.Name)
		}
		log.Debug("%s %s -> %d:%s => %s:%d, mark: %x (%s)", log.Bold(log.Green("✔")), log.Bold(con.Process.Path), con.SrcPort, log.Bold(con.SrcIP.String()), log.Bold(con.To()), con.DstPort, packet.Mark, ruleName)
	} else {
		if r.Action == rule.Reject {
			netlink.KillSocket(con.Protocol, con.SrcIP, con.SrcPort, con.DstIP, con.DstPort)
		}
		packet.SetVerdict(netfilter.NF_DROP)

		log.Debug("%s %s -> %d:%s => %s:%d, mark: %x (%s)", log.Bold(log.Red("✘")), log.Bold(con.Process.Path), con.SrcPort, log.Bold(con.SrcIP.String()), log.Bold(con.To()), con.DstPort, packet.Mark, log.Red(r.Name))
	}

	return r
}

func main() {
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	flag.Parse()

	if showVersion {
		fmt.Println(core.Version)
		os.Exit(0)
	}
	if checkRequirements {
		core.CheckSysRequirements()
		os.Exit(0)
	}

	setupLogging()
	setupProfiling()

	log.Important("Starting %s v%s", core.Name, core.Version)

	cfg, err := loadDiskConfiguration()
	if err != nil {
		log.Fatal("%s", err)
	}

	if err == nil && cfg.Rules.Path != "" {
		rulesPath = cfg.Rules.Path
	}
	if rulesPath == "" {
		log.Fatal("rules path cannot be empty")
	}

	rulesPath, err := core.ExpandPath(rulesPath)
	if err != nil {
		log.Fatal("Error accessing rules path (does it exist?): %s", err)
	}

	setupSignals()

	log.Info("Loading rules from %s ...", rulesPath)
	rules, err = rule.NewLoader(!noLiveReload)
	if err != nil {
		log.Fatal("%s", err)
	} else if err = rules.Load(rulesPath); err != nil {
		log.Fatal("%s", err)
	}
	stats = statistics.New(rules)
	loggerMgr = loggers.NewLoggerManager()
	uiClient = ui.NewClient(uiSocket, configFile, stats, rules, loggerMgr)

	setupWorkers()
	setupQueues()

	fwConfigPath := fwConfigFile
	if fwConfigPath == "" {
		fwConfigPath = cfg.FwOptions.ConfigPath
	}
	log.Info("Using system fw configuration %s ...", fwConfigPath)
	// queue is ready, run firewall rules and start intercepting connections
	if err = firewall.Init(
		uiClient.GetFirewallType(),
		fwConfigPath,
		cfg.FwOptions.MonitorInterval,
		&queueNum); err != nil {
		log.Warning("%s", err)
		uiClient.SendWarningAlert(err)
	}

	uiClient.Connect()
	listenToEvents()

	if overwriteLogging() {
		setupLogging()
	}
	// overwrite monitor method from configuration if the user has passed
	// the option via command line.
	if procmonMethod != "" {
		if err := monitor.ReconfigureMonitorMethod(procmonMethod, cfg.Ebpf.ModulesPath); err != nil {
			msg := fmt.Sprintf("Unable to set process monitor method via parameter: %v", err)
			uiClient.SendWarningAlert(msg)
			log.Warning(msg)
		}
	}

	go func(uiClient *ui.Client, ebpfPath string) {
		if err := dns.ListenerEbpf(ebpfPath); err != nil {
			msg := fmt.Sprintf("EBPF-DNS: Unable to attach ebpf listener: %s", err)
			log.Warning(msg)
			// don't display an alert, since this module is not critical
			uiClient.PostAlert(
				protocol.Alert_ERROR,
				protocol.Alert_GENERIC,
				protocol.Alert_SAVE_TO_DB,
				protocol.Alert_MEDIUM,
				msg)

		}
	}(uiClient, cfg.Ebpf.ModulesPath)

	initSystemdResolvedMonitor()

	log.Info("Running on netfilter queue #%d ...", queueNum)
	for {
		select {
		case <-ctx.Done():
			goto Exit
		case pkt, ok := <-pktChan:
			if !ok {
				goto Exit
			}
			wrkChan <- pkt
		}
	}
Exit:
	close(wrkChan)
	doCleanup(queue, repeatQueue)
	os.Exit(0)
}
