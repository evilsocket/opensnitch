package loggers

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/formats"
)

const (
	LOGGER_REMOTE_SYSLOG = "remote_syslog"
	writeTimeout         = "1s"
	// restart syslog connection after these amount of errors
	maxAllowedErrors = 10
)

// connection status
const (
	DISCONNECTED = iota
	CONNECTED
	CONNECTING
)

// RemoteSyslog defines the logger that writes traces to the syslog.
// It can write to the local or a remote daemon.
type RemoteSyslog struct {
	Syslog
	mu       *sync.RWMutex
	netConn  net.Conn
	Hostname string
	Timeout  time.Duration
	errors   uint32
	status   uint32
}

// NewRemoteSyslog returns a new object that manipulates and prints outbound connections
// to a remote syslog server, with the given format (RFC5424 by default)
func NewRemoteSyslog(cfg *LoggerConfig) (*RemoteSyslog, error) {
	var err error
	log.Info("NewSyslog logger: %v", cfg)

	sys := &RemoteSyslog{
		mu: &sync.RWMutex{},
	}
	sys.Name = LOGGER_REMOTE_SYSLOG
	sys.cfg = cfg

	// list of allowed formats for this logger
	sys.logFormat = formats.NewRfc5424()
	if cfg.Format == formats.RFC3164 {
		sys.logFormat = formats.NewRfc3164()
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
	sys.Timeout, _ = time.ParseDuration(cfg.WriteTimeout)

	if err = sys.Open(); err != nil {
		log.Error("Error loading logger: %s", err)
		return nil, err
	}
	log.Info("[%s] initialized: %v", sys.Name, cfg)

	return sys, err
}

// Open opens a new connection with a server or with the daemon.
func (s *RemoteSyslog) Open() (err error) {
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

// Dial opens a new connection with a syslog server.
func (s *RemoteSyslog) Dial(proto, addr string, connTimeout time.Duration) (netConn net.Conn, err error) {
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
func (s *RemoteSyslog) Close() (err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.netConn != nil {
		err = s.netConn.Close()
		//s.netConn.conn = nil
	}
	atomic.StoreUint32(&s.status, DISCONNECTED)
	return
}

// ReOpen tries to reestablish the connection with the writer
func (s *RemoteSyslog) ReOpen() {
	if atomic.LoadUint32(&s.status) == CONNECTING {
		return
	}
	atomic.StoreUint32(&s.status, CONNECTING)
	if err := s.Close(); err != nil {
		log.Debug("[%s] error closing Close(): %s", s.Name, err)
	}

	if err := s.Open(); err != nil {
		log.Debug("[%s] ReOpen() error: %s", s.Name, err)
		return
	}
}

// Transform transforms data for proper ingestion.
func (s *RemoteSyslog) Transform(args ...interface{}) (out string) {
	if s.logFormat != nil {
		args = append(args, s.Hostname)
		args = append(args, s.Tag)
		out = s.logFormat.Transform(args...)
	}
	return
}

func (s *RemoteSyslog) Write(msg string) {
	deadline := time.Now().Add(s.Timeout)

	// BUG: it's fairly common to have write timeouts via udp/tcp.
	// Reopening the connection with the server helps to resume sending events to syslog,
	// and have a continuous stream of events. Otherwise it'd stop working.
	// I haven't figured out yet why these write errors ocurr.
	s.mu.RLock()
	s.netConn.SetWriteDeadline(deadline)
	_, err := s.netConn.Write([]byte(msg))
	s.mu.RUnlock()

	if err != nil {
		log.Debug("[%s] %s write error: %v", s.Name, s.cfg.Protocol, err.(net.Error))
		atomic.AddUint32(&s.errors, 1)
		if atomic.LoadUint32(&s.errors) > maxAllowedErrors {
			s.ReOpen()
			return
		}
	}
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/log/syslog/syslog.go;l=286;drc=0a1a092c4b56a1d4033372fbd07924dad8cbb50b
func (s *RemoteSyslog) formatLine(msg string) string {
	return msg
}
