package loggers

import (
	"context"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/formats"
)

const (
	LOGGER_REMOTE = "remote"
)

// Remote defines a logger that writes events to a generic remote server.
// It can write to a local or a remote daemon, UDP or TCP.
// It supports writing events in RFC5424, RFC3164, CSV and JSON formats.
type Remote struct {
	mu        *sync.RWMutex
	Writer    *syslog.Writer
	cfg       LoggerConfig
	ctx       context.Context
	cancel    context.CancelFunc
	logFormat formats.LoggerFormat

	netConn net.Conn

	// Name of the logger
	Name string

	// channel used to write mesages
	writerChan chan string

	Tag string

	// Name of the host where the daemon is running
	Hostname string

	// Write timeouts
	Timeout time.Duration

	// Connect timeout
	ConnectTimeout time.Duration

	status uint32
}

// NewRemote returns a new object that manipulates and prints outbound connections
// to a remote server, with the given format (RFC5424 by default)
func NewRemote(cfg LoggerConfig) (*Remote, error) {
	var err error
	log.Info("NewRemote logger: %v", cfg)

	sys := &Remote{
		mu: &sync.RWMutex{},
	}
	sys.Name = LOGGER_REMOTE
	sys.cfg = cfg
	sys.ctx, sys.cancel = context.WithCancel(context.Background())

	// list of allowed formats for this logger
	sys.logFormat = formats.NewRfc5424()
	if cfg.Format == formats.RFC3164 {
		sys.logFormat = formats.NewRfc3164()
	} else if cfg.Format == formats.JSON {
		sys.logFormat = formats.NewJSON()
	} else if cfg.Format == formats.CSV {
		sys.logFormat = formats.NewCSV()
	}

	sys.Tag = logTag
	if cfg.Tag != "" {
		sys.Tag = cfg.Tag
	}
	sys.Hostname, err = os.Hostname()
	if err != nil {
		sys.Hostname = "localhost"
	}
	sys.Timeout, err = time.ParseDuration(cfg.WriteTimeout)
	if err != nil || cfg.WriteTimeout == "" {
		sys.Timeout = writeTimeout
	}

	sys.ConnectTimeout, err = time.ParseDuration(cfg.ConnectTimeout)
	if err != nil || cfg.ConnectTimeout == "" {
		sys.ConnectTimeout = connTimeout
	}

	// initial connection test
	if err = sys.Open(); err != nil {
		log.Error("Error loading logger [%s]: %s", sys.Name, err)
		return nil, err
	}
	log.Info("[%s] initialized: %v", sys.Name, cfg)

	sys.writerChan = make(chan string)
	if sys.cfg.Workers == 0 {
		sys.cfg.Workers = 1
	}
	for i := 0; i < sys.cfg.Workers; i++ {
		go writerWorker(i, *sys, sys.writerChan, sys.ctx.Done())
	}

	return sys, err
}

// Open opens a new connection with a server or with the daemon.
func (s *Remote) Open() (err error) {
	if s.cfg.Server == "" {
		return fmt.Errorf("[%s] Server address must not be empty", s.Name)
	}
	s.mu.Lock()
	s.netConn, err = s.Dial(s.cfg.Protocol, s.cfg.Server, s.ConnectTimeout)
	s.mu.Unlock()

	if err == nil {
		atomic.StoreUint32(&s.status, CONNECTED)
	}
	return err
}

// Dial opens a new connection with a remote server.
func (s *Remote) Dial(proto, addr string, connTimeout time.Duration) (netConn net.Conn, err error) {
	switch proto {
	case "udp", "tcp":
		netConn, err = net.DialTimeout(proto, addr, connTimeout)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("[%s] Network protocol %s not supported (use 'tcp' or 'udp')", s.Name, proto)
	}

	return netConn, nil
}

// Close closes the writer object
func (s *Remote) Close() (err error) {
	if s.netConn != nil {
		err = s.netConn.Close()
		s.netConn = nil
	}
	s.cancel()
	atomic.StoreUint32(&s.status, DISCONNECTED)
	return
}

// ReOpen tries to reestablish the connection with the writer
func (s *Remote) ReOpen() {
	if atomic.LoadUint32(&s.status) == CONNECTING {
		return
	}
	atomic.StoreUint32(&s.status, CONNECTING)
	if err := s.Close(); err != nil {
		log.Debug("[%s] error closing Close(): %s", s.Name, err)
	}

	if err := s.Open(); err != nil {
		log.Debug("[%s] ReOpen() error: %s", s.Name, err)
	} else {
		log.Debug("[%s] ReOpen() ok", s.Name)
	}
}

// Transform transforms data for proper ingestion.
func (s *Remote) Transform(args ...interface{}) (out string) {
	if s.logFormat != nil {
		args = append(args, s.Hostname)
		args = append(args, s.Tag)
		out = s.logFormat.Transform(args...)
	}
	return
}

func (s *Remote) Write(msg string) {
	s.writerChan <- msg
}

func (s *Remote) formatLine(msg string) string {
	nl := ""
	if !strings.HasSuffix(msg, "\n") {
		nl = "\n"
	}
	return core.ConcatStrings(msg, nl)
}

// each worker opens a new connection with the remote server, and waits for
// incoming messages to be forwarded to the server.
func writerWorker(id int, sys Remote, msgs <-chan string, done <-chan struct{}) {
	errors := 0
	conn, err := sys.Dial(sys.cfg.Protocol, sys.cfg.Server, sys.ConnectTimeout)
	if err != nil {
		log.Error("[%s] Error opening connection, worker %d", sys.Name, id)
		return
	}
	log.Debug("[%s] worker %d, connection opened", sys.Name, id)

	for {
		select {
		case <-done:
			goto Exit
		case msg := <-msgs:
			log.Trace("[%s] %d writing writes", sys.Name, id)

			// define a write timeout for this operation from Now.
			deadline := time.Now().Add(sys.Timeout)
			conn.SetWriteDeadline(deadline)
			b, err := conn.Write([]byte(msg))
			if err != nil {
				log.Trace("[%s] error writing via writer %d (%d): %s", sys.Name, id, b, err)
				// TODO: reopen the connection on max errors
				errors++
				if errors > maxAllowedErrors {
					log.Important("[%s] writer %d: too much errors, review the configuration and / or connectivity with the remote server", sys.Name, id)
					goto Exit
				}
			}
		}
	}
Exit:
	log.Debug("[%s] %d connection closed (errors: %d)", sys.Name, id, errors)
	conn.Close()
}
