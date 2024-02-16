package loggers

import (
	"fmt"
	"log/syslog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/formats"
)

const (
	LOGGER_REMOTE = "remote"
)

// Remote defines the logger that writes events to a generic remote server.
// It can write to the local or a remote daemon, UDP or TCP.
// It supports writing events in RFC5424, RFC3164, CSV and JSON formats.
type Remote struct {
	mu        *sync.RWMutex
	Writer    *syslog.Writer
	cfg       *LoggerConfig
	logFormat formats.LoggerFormat
	netConn   net.Conn
	Name      string
	Tag       string
	Hostname  string
	Timeout   time.Duration
	errors    uint32
	maxErrors uint32
	status    uint32
}

// NewRemote returns a new object that manipulates and prints outbound connections
// to a remote syslog server, with the given format (RFC5424 by default)
func NewRemote(cfg *LoggerConfig) (*Remote, error) {
	var err error
	log.Info("NewRemote logger: %v", cfg)

	sys := &Remote{
		mu: &sync.RWMutex{},
	}
	sys.Name = LOGGER_REMOTE
	sys.cfg = cfg

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
	if cfg.WriteTimeout == "" {
		cfg.WriteTimeout = writeTimeout
	}
	sys.Timeout = (time.Second * 15)

	if err = sys.Open(); err != nil {
		log.Error("Error loading logger: %s", err)
		return nil, err
	}
	log.Info("[%s] initialized: %v", sys.Name, cfg)

	return sys, err
}

// Open opens a new connection with a server or with the daemon.
func (s *Remote) Open() (err error) {
	atomic.StoreUint32(&s.errors, 0)
	if s.cfg.Server == "" {
		return fmt.Errorf("[%s] Server address must not be empty", s.Name)
	}
	s.mu.Lock()
	s.netConn, err = s.Dial(s.cfg.Protocol, s.cfg.Server, s.Timeout*5)
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
		return nil, fmt.Errorf("[%s] Network protocol %s not supported", s.Name, proto)
	}

	return netConn, nil
}

// Close closes the writer object
func (s *Remote) Close() (err error) {
	s.mu.RLock()
	if s.netConn != nil {
		err = s.netConn.Close()
		//s.netConn.conn = nil
	}
	s.mu.RUnlock()
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
	deadline := time.Now().Add(s.Timeout)

	// BUG: it's fairly common to have write timeouts via udp/tcp.
	// Reopening the connection with the server helps to resume sending events to the server,
	// and have a continuous stream of events. Otherwise it'd stop working.
	// I haven't figured out yet why these write errors ocurr.
	s.mu.Lock()
	s.netConn.SetWriteDeadline(deadline)
	_, err := s.netConn.Write([]byte(msg))
	s.mu.Unlock()
	if err == nil {
		return
	}

	log.Debug("[%s] %s write error: %v", s.Name, s.cfg.Protocol, err.(net.Error))
	atomic.AddUint32(&s.errors, 1)
	if atomic.LoadUint32(&s.errors) > maxAllowedErrors {
		s.ReOpen()
		return
	}
}

func (s *Remote) formatLine(msg string) string {
	nl := ""
	if !strings.HasSuffix(msg, "\n") {
		nl = "\n"
	}
	return fmt.Sprintf("%s%s", msg, nl)
}
