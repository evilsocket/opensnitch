package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	golog "log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/netfilter"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/procmon/monitor"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/statistics"
	"github.com/evilsocket/opensnitch/daemon/ui"
)

var (
	showVersion    = false
	procmonMethod  = ""
	logFile        = ""
	rulesPath      = "rules"
	noLiveReload   = false
	queueNum       = 0
	repeatQueueNum int //will be set later to queueNum + 1
	workers        = 16
	debug          = false
	warning        = false
	important      = false
	errorlog       = false

	uiSocket = ""
	uiClient = (*ui.Client)(nil)

	cpuProfile = ""
	memProfile = ""

	ctx           = (context.Context)(nil)
	cancel        = (context.CancelFunc)(nil)
	err           = (error)(nil)
	rules         = (*rule.Loader)(nil)
	stats         = (*statistics.Statistics)(nil)
	queue         = (*netfilter.Queue)(nil)
	repeatPktChan = (<-chan netfilter.Packet)(nil)
	pktChan       = (<-chan netfilter.Packet)(nil)
	wrkChan       = (chan netfilter.Packet)(nil)
	sigChan       = (chan os.Signal)(nil)
	exitChan      = (chan bool)(nil)
)

func init() {
	flag.BoolVar(&showVersion, "version", debug, "Show daemon version of this executable and exit.")

	flag.StringVar(&procmonMethod, "process-monitor-method", procmonMethod, "How to search for processes path. Options: ftrace, audit (experimental), ebpf (experimental), proc (default)")
	flag.StringVar(&uiSocket, "ui-socket", uiSocket, "Path the UI gRPC service listener (https://github.com/grpc/grpc/blob/master/doc/naming.md).")
	flag.StringVar(&rulesPath, "rules-path", rulesPath, "Path to load JSON rules from.")
	flag.IntVar(&queueNum, "queue-num", queueNum, "Netfilter queue number.")
	flag.IntVar(&workers, "workers", workers, "Number of concurrent workers.")
	flag.BoolVar(&noLiveReload, "no-live-reload", debug, "Disable rules live reloading.")

	flag.StringVar(&logFile, "log-file", logFile, "Write logs to this file instead of the standard output.")
	flag.BoolVar(&debug, "debug", debug, "Enable debug level logs.")
	flag.BoolVar(&warning, "warning", warning, "Enable warning level logs.")
	flag.BoolVar(&important, "important", important, "Enable important level logs.")
	flag.BoolVar(&errorlog, "error", errorlog, "Enable error level logs.")

	flag.StringVar(&cpuProfile, "cpu-profile", cpuProfile, "Write CPU profile to this file.")
	flag.StringVar(&memProfile, "mem-profile", memProfile, "Write memory profile to this file.")
}

func overwriteLogging() bool {
	return debug || warning || important || errorlog || logFile != ""
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

func doCleanup(queue, repeatQueue *netfilter.Queue) {
	log.Info("Cleaning up ...")
	firewall.Stop()
	monitor.End()
	uiClient.Close()
	queue.Close()
	repeatQueue.Close()

	if cpuProfile != "" {
		pprof.StopCPUProfile()
	}

	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			fmt.Printf("Could not create memory profile: %s\n", err)
			return
		}
		defer f.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			fmt.Printf("Could not write memory profile: %s\n", err)
		}
	}
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

	if r.Enabled == false {
		applyDefaultAction(packet)
		ruleName := log.Green(r.Name)
		log.Info("DISABLED (%s) %s %s -> %s:%d (%s)", uiClient.DefaultAction(), log.Bold(log.Green("✔")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort, ruleName)

	} else if r.Action == rule.Allow {
		if packet != nil {
			packet.SetVerdictAndMark(netfilter.NF_ACCEPT, packet.Mark)
		}
		ruleName := log.Green(r.Name)
		if r.Operator.Operand == rule.OpTrue {
			ruleName = log.Dim(r.Name)
		}
		log.Debug("%s %s -> %s:%d (%s)", log.Bold(log.Green("✔")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort, ruleName)
	} else {
		if packet != nil {
			packet.SetVerdict(netfilter.NF_DROP)
		}

		log.Debug("%s %s -> %s:%d (%s)", log.Bold(log.Red("✘")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort, log.Red(r.Name))
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

	setupLogging()

	if cpuProfile != "" {
		if f, err := os.Create(cpuProfile); err != nil {
			log.Fatal("%s", err)
		} else if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("%s", err)
		}
	}

	log.Important("Starting %s v%s", core.Name, core.Version)

	rulesPath, err := core.ExpandPath(rulesPath)
	if err != nil {
		log.Fatal("%s", err)
	}

	setupSignals()

	log.Info("Loading rules from %s ...", rulesPath)
	if rules, err = rule.NewLoader(!noLiveReload); err != nil {
		log.Fatal("%s", err)
	} else if err = rules.Load(rulesPath); err != nil {
		log.Fatal("%s", err)
	}
	stats = statistics.New(rules)

	// prepare the queue
	setupWorkers()
	queue, err := netfilter.NewQueue(uint16(queueNum))
	if err != nil {
		log.Warning("Is opensnitchd already running?")
		log.Fatal("Error while creating queue #%d: %s", queueNum, err)
	}
	pktChan = queue.Packets()

	repeatQueueNum = queueNum + 1
	repeatQueue, rqerr := netfilter.NewQueue(uint16(repeatQueueNum))
	if rqerr != nil {
		log.Warning("Is opensnitchd already running?")
		log.Fatal("Error while creating queue #%d: %s", repeatQueueNum, rqerr)
	}
	repeatPktChan = repeatQueue.Packets()

	uiClient = ui.NewClient(uiSocket, stats, rules)
	stats.SetConfig(uiClient.GetStatsConfig())

	// queue is ready, run firewall rules
	firewall.Init(uiClient.GetFirewallType(), &queueNum)

	if overwriteLogging() {
		setupLogging()
	}
	// overwrite monitor method from configuration if the user has passed
	// the option via command line.
	if procmonMethod != "" {
		procmon.SetMonitorMethod(procmonMethod)
	}
	monitor.Init()

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
