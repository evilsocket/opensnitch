package loggers

import (
	"log/syslog"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/formats"
)

const (
	logTag        = "opensnitch"
	LOGGER_SYSLOG = "syslog"
)

// Syslog defines the logger that writes traces to the syslog.
// It can write to the local or a remote daemon.
type Syslog struct {
	Name      string
	Writer    *syslog.Writer
	Tag       string
	logFormat formats.LoggerFormat
	cfg       *LoggerConfig
}

// NewSyslog returns a new object that manipulates and prints outbound connections
// to syslog (local or remote), with the given format (RFC5424 by default)
func NewSyslog(cfg *LoggerConfig) (*Syslog, error) {
	var err error
	log.Info("NewSyslog logger: %v", cfg)

	sys := &Syslog{cfg: cfg}

	sys.logFormat = formats.NewRfc5424()
	if cfg.Format == formats.CSV {
		sys.logFormat = formats.NewCSV()
	}

	sys.Tag = logTag
	if cfg.Tag != "" {
		sys.Tag = cfg.Tag
	}

	if err = sys.Open(); err != nil {
		log.Error("Error loading logger: %s", err)
		return nil, err
	}
	log.Debug("[syslog logger] initialized: %v", cfg)

	return sys, err
}

// Open opens a new connection with a server or with the daemon.
func (s *Syslog) Open() error {
	var err error
	if s.cfg.Server != "" {
		s.Writer, err = syslog.Dial(s.cfg.Protocol, s.cfg.Server, syslog.LOG_NOTICE|syslog.LOG_DAEMON, s.Tag)
	} else {
		s.Writer, err = syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, logTag)
	}

	return err
}

// Close closes the writer object
func (s *Syslog) Close() error {
	return s.Writer.Close()
}

// Reopen tries to reestablish the connection with the writer
func (s *Syslog) Reopen() {
	println(">>> REOPENING syslog connection <<<")
	s.Close()
	s.Open()
}

// Transform transforms data for proper ingestion.
func (s *Syslog) Transform(args ...interface{}) (out string) {
	if s.logFormat != nil {
		out = s.logFormat.Transform(args...)
	}
	return
}

func (s *Syslog) Write(msg string) {
	if err := s.Writer.Notice(msg); err != nil {
		log.Error("[syslog] write error: %s", err)
		s.Reopen()
	}
}
