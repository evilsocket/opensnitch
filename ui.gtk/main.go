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
)

var (
	socketPath = "opensnitch-ui.sock"
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
