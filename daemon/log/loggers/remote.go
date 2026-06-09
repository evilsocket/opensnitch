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

	// restart syslog connection after these amount of errors
	maxAllowedErrors = 10
)

var (
	// default write / connect timeouts
	writeTimeout, _   = time.ParseDuration("1s")
	connTimeout, _    = time.ParseDuration("5s")
	reopenInterval, _ = time.ParseDuration("5s")
)

// connection status
const (
	DISCONNECTED = iota
	CONNECTED
	CONNECTING
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

	// Name of the logger
	Name string

	// channel used to write messages
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

	sys.writerChan = make(chan string)
	if sys.cfg.Workers == 0 {
		sys.cfg.Workers = 1
	}
	for i := 0; i < sys.cfg.Workers; i++ {
		go writerWorker(i, sys, sys.writerChan, sys.ctx.Done())
	}

	return sys, err
}

// Open establishes a connection with a remote server.
// It'll try to reopen the connection based on the configuration provided:
// If MaxConnectAttempts is 0, indefinitely. Otherwise the amount of attempts specified.
func (s *Remote) Open() (net.Conn, bool) {
	atomic.StoreUint32(&s.status, DISCONNECTED)
	connRetries := uint16(0)

Reopen:

	select {
	case <-s.ctx.Done():
		log.Info("[%s] %s worker stopped", s.Name, s.cfg.Server)
		return nil, false
	default:
	}
	log.Debug("[%s] %s trying to connect", s.Name, s.cfg.Server)

	conn, err := s.Dial(s.cfg.Protocol, s.cfg.Server, s.ConnectTimeout)
	if err != nil {
		log.Debug("[%s] Error opening connection (%s), retrying... (%d/%d)", s.Name, s.cfg.Server, connRetries, s.cfg.MaxConnectAttempts)
		connRetries++
		if s.cfg.MaxConnectAttempts > 0 && connRetries > s.cfg.MaxConnectAttempts {
			log.Info("[%s] %s, Max connections attempts reached, giving up", s.Name, s.cfg.Server)
			return nil, false
		}

		// wait time before reopen attempt
		time.Sleep(reopenInterval)
		goto Reopen
	}
	connRetries = 0
	atomic.StoreUint32(&s.status, CONNECTED)

	log.Info("[%s] connected to %s", s.Name, s.cfg.Server)

	return conn, true
}

// Dial opens a new connection with a remote server.
func (s *Remote) Dial(proto, addr string, connTimeout time.Duration) (netConn net.Conn, err error) {
	atomic.StoreUint32(&s.status, DISCONNECTED)
	switch proto {
	case "udp", "tcp":
		netConn, err = net.DialTimeout(proto, addr, connTimeout)
		if err != nil {
			log.Debug("remote.Dial() %s error: %s", s.cfg.Server, err)
			return nil, err
		}
	default:
		return nil, fmt.Errorf("[%s] Network protocol %s not supported (use 'tcp' or 'udp')", s.Name, proto)
	}

	atomic.StoreUint32(&s.status, CONNECTED)
	return netConn, nil
}

// Close closes the writer object
func (s *Remote) Close() (err error) {
	s.cancel()
	atomic.StoreUint32(&s.status, DISCONNECTED)
	return
}

func (s *Remote) isConnected() bool {
	status := atomic.LoadUint32(&s.status)
	return status == CONNECTED
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
	if !s.isConnected() {
		log.Trace("[%s] %s not connected", s.Name, s.cfg.Server)
		return
	}
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
func writerWorker(id int, sys *Remote, msgs <-chan string, done <-chan struct{}) {
	errors := 0

Reopen:
	conn, reconnected := sys.Open()
	if !reconnected {
		goto Exit
	}

	for {
		select {
		case <-done:
			goto Exit
		case msg := <-msgs:
			//log.Trace("[%s] %d writing", sys.Name, id)

			// define a write timeout for this operation from Now.
			deadline := time.Now().Add(sys.Timeout)
			conn.SetWriteDeadline(deadline)
			_, err := conn.Write([]byte(msg))
			if err != nil {
				log.Debug("[%s] error writing via writer %d: %s", sys.Name, id, err)
				errors++
				if errors > maxAllowedErrors {
					log.Warning("[%s] writer %d: too much errors, review the configuration and / or connectivity with the remote server", sys.Name, id)
					goto Reopen
				}
			}
		}
	}

Exit:
	log.Info("[%s logger] %d connection closed (errors: %d)", sys.Name, id, errors)
	if conn != nil {
		conn.Close()
	}
	sys.Close()
}
