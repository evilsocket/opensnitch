package main

import (
	"flag"
	"net"

	"golang.org/x/net/context"

	"github.com/evilsocket/opensnitch/ui.test.service/core"

	"github.com/evilsocket/opensnitch/daemon/log"
	protocol "github.com/evilsocket/opensnitch/ui.proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	socketPath = "osui.sock"
	listener   = (net.Listener)(nil)
	server     = (*grpc.Server)(nil)
	err        = (error)(nil)
)

type service struct{}

func (s *service) Ping(ctx context.Context, ping *protocol.PingRequest) (*protocol.PingReply, error) {
	log.Info("Got ping 0x%x", ping.Id)
	return &protocol.PingReply{Id: ping.Id}, nil
}

func (s *service) AskRule(ctx context.Context, req *protocol.RuleRequest) (*protocol.RuleReply, error) {
	log.Info("Got rule request: %v", req)
	return &protocol.RuleReply{
		Name:     "user.choice",
		Action:   "allow",
		Duration: "once",
		What:     "process.path",
		With:     req.ProcessPath,
	}, nil
}

func init() {
	flag.StringVar(&socketPath, "socket-path", socketPath, "UNIX socket for this gRPC service.")
}

func main() {
	flag.Parse()

	log.Important("Starting %s v%s", core.Name, core.Version)

	log.Info("Creating listener on unix://%s", socketPath)
	listener, err = net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal("%s", err)
	}

	server = grpc.NewServer()
	protocol.RegisterUIServer(server, &service{})
	reflection.Register(server)

	if err := server.Serve(listener); err != nil {
		log.Fatal("Failed to start: %s", err)
	}
}
