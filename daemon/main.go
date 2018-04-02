package main

import (
	"flag"
	"io/ioutil"
	golog "log"
	"os"
	"os/signal"
	"syscall"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/dns"
	"github.com/evilsocket/opensnitch/daemon/firewall"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/rule"
	"github.com/evilsocket/opensnitch/daemon/ui"

	"github.com/evilsocket/go-netfilter-queue"
)

var (
	rulesPath = "rules"
	queueNum  = 0
	workers   = 16
	debug     = false

	uiSocketPath = "osui.sock"
	uiClient     = (*ui.Client)(nil)

	err     = (error)(nil)
	rules   = rule.NewLoader()
	queue   = (*netfilter.NFQueue)(nil)
	pktChan = (<-chan netfilter.NFPacket)(nil)
	wrkChan = (chan netfilter.NFPacket)(nil)
	sigChan = (chan os.Signal)(nil)
)

func init() {
	flag.StringVar(&uiSocketPath, "ui-socket-path", uiSocketPath, "UNIX socket of the UI gRPC service.")
	flag.StringVar(&rulesPath, "rules-path", rulesPath, "Path to load JSON rules from.")
	flag.IntVar(&queueNum, "queue-num", queueNum, "Netfilter queue number.")
	flag.IntVar(&workers, "workers", workers, "Number of concurrent workers.")
	flag.BoolVar(&debug, "debug", debug, "Enable debug logs.")
}

func setupSignals() {
	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		log.Raw("\n")
		log.Important("Got signal: %v", sig)
		doCleanup()
		os.Exit(0)
	}()
}

func worker(id int) {
	log.Debug("Worker #%d started.", id)
	for true {
		select {
		case pkt := <-wrkChan:
			onPacket(pkt)
		}
	}
}

func setupWorkers() {
	log.Debug("Starting %d workers ...", workers)
	// setup the workers
	wrkChan = make(chan netfilter.NFPacket)
	for i := 0; i < workers; i++ {
		go worker(i)
	}
}

func doCleanup() {
	log.Info("Cleaning up ...")
	firewall.QueueDNSResponses(false, queueNum)
	firewall.QueueConnections(false, queueNum)
	firewall.RejectMarked(false)
}

func onPacket(packet netfilter.NFPacket) {
	// DNS response, just parse, track and accept.
	if dns.TrackAnswers(packet.Packet) == true {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	// Parse the connection state
	con := conman.Parse(packet)
	if con == nil {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		return
	}

	r := rules.FindFirstMatch(con)
	// no rule matched, prompt the user
	if r == nil {
		r = uiClient.Ask(con)
	}

	if r.Action == rule.Allow {
		packet.SetVerdict(netfilter.NF_ACCEPT)
		ruleName := log.Green(r.Name)
		if r.Rule.What == rule.OpTrue {
			ruleName = log.Dim(r.Name)
		}

		log.Info("%s %s -> %s:%d (%s)", log.Bold(log.Green("✔")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort, ruleName)
		return
	}

	packet.SetVerdict(netfilter.NF_DROP)

	log.Warning("%s %s -> %s:%d (%s)", log.Bold(log.Red("✘")), log.Bold(con.Process.Path), log.Bold(con.To()), con.DstPort, log.Red(r.Name))
}

func main() {
	golog.SetOutput(ioutil.Discard)
	flag.Parse()

	if debug {
		log.MinLevel = log.DEBUG
	} else {
		log.MinLevel = log.INFO
	}

	log.Important("Starting %s v%s", core.Name, core.Version)

	rulesPath, err := core.ExpandPath(rulesPath)
	if err != nil {
		log.Fatal("%s", err)
	}

	uiSocketPath, err = core.ExpandPath(uiSocketPath)
	if err != nil {
		log.Fatal("%s", err)
	}

	setupSignals()
	setupWorkers()

	// prepare the queue
	queue, err := netfilter.NewNFQueue(uint16(queueNum), 4096, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatal("Error while creating queue #%d: %s", queueNum, err)
	}
	pktChan = queue.GetPackets()

	// queue is ready, run firewall rules
	if err = firewall.QueueDNSResponses(true, queueNum); err != nil {
		log.Fatal("Error while running DNS firewall rule: %s", err)
	} else if err = firewall.QueueConnections(true, queueNum); err != nil {
		log.Fatal("Error while running conntrack firewall rule: %s", err)
	} else if err = firewall.RejectMarked(true); err != nil {
		log.Fatal("Error while running reject firewall rule: %s", err)
	}

	log.Info("Loading rules from %s ...", rulesPath)
	if err := rules.Load(rulesPath); err != nil {
		log.Fatal("%s", err)
	}
	uiClient = ui.NewClient(uiSocketPath)

	log.Info("Running on netfilter queue #%d ...", queueNum)
	for true {
		select {
		case pkt := <-pktChan:
			wrkChan <- pkt
		}
	}
}
