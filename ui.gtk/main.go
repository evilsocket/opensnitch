package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/net/context"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	protocol "github.com/evilsocket/opensnitch/ui.proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

var (
	socketPath = "opensnitch-ui.sock"
	uiBuilder  = (*gtk.Builder)(nil)
	askWindow  = (*gtk.Window)(nil)
	listener   = (net.Listener)(nil)
	server     = (*grpc.Server)(nil)
	err        = (error)(nil)
	sigChan    = (chan os.Signal)(nil)
	isClosing  = (bool)(false)
)

type service struct{}

func (s *service) Ping(ctx context.Context, ping *protocol.PingRequest) (*protocol.PingReply, error) {
	log.Debug("Got ping 0x%x", ping.Id)
	return &protocol.PingReply{Id: ping.Id}, nil
}

func (s *service) AskRule(ctx context.Context, req *protocol.RuleRequest) (*protocol.RuleReply, error) {
	log.Info("Got rule request: %v", req)

	glib.IdleAdd(func() bool {
		askWindow.Show()
		return false
	})

	return &protocol.RuleReply{
		Name:     "user.choice",
		Action:   "allow",
		Duration: "always",
		What:     "process.path",
		With:     req.ProcessPath,
	}, nil
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
		isClosing = true
		log.Raw("\n")
		log.Important("Got signal: %v", sig)

		if listener != nil {
			listener.Close()
		}
		os.Exit(0)
	}()
}

// TODO: this will be loaded from compiled resources
const uiGladeFile = "ui.gtk/glade/ask_window.glade"

func setupGtk() {
	gtk.Init(&os.Args)

	if uiBuilder, err = gtk.BuilderNew(); err != nil {
		log.Fatal("Error while creating GTK builder: %s", err)
	} else if err = uiBuilder.AddFromFile(uiGladeFile); err != nil {
		log.Fatal("Error while loading %s: %s", uiGladeFile, err)
	}

	obj, err := uiBuilder.GetObject("askWindow")
	if err != nil {
		log.Fatal("Error while getting window: %s", err)
	}

	var ok bool
	askWindow, ok = obj.(*gtk.Window)
	if !ok {
		log.Fatal("Could not cast window object.")
	}

	askWindow.SetTitle("OpenSnitch v" + Version)
	go func() {
		gtk.Main()
	}()
}

func init() {
	flag.StringVar(&socketPath, "socket-path", socketPath, "UNIX socket for this gRPC service.")
}

func main() {
	flag.Parse()

	socketPath, err = core.ExpandPath(socketPath)
	if err != nil {
		log.Fatal("%s", err)
	}

	setupSignals()
	setupGtk()

	log.Important("Starting %s v%s on socket %s", Name, Version, socketPath)

	listener, err = net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal("%s", err)
	}

	server = grpc.NewServer()
	protocol.RegisterUIServer(server, &service{})
	reflection.Register(server)

	if err := server.Serve(listener); err != nil {
		if isClosing == false {
			log.Fatal("Failed to start: %s", err)
		}
	}
}
