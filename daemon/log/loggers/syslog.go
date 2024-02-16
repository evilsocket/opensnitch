package loggers

import (
	"log/syslog"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/formats"
)

const (
	LOGGER_SYSLOG = "syslog"
)

// Syslog defines the logger that writes traces to the syslog.
// It can write to the local or a remote daemon.
type Syslog struct {
	cfg       *LoggerConfig
	Writer    *syslog.Writer
	logFormat formats.LoggerFormat
	Name      string
	Tag       string
}

// NewSyslog returns a new object that manipulates and prints outbound connections
// to syslog (local or remote), with the given format (RFC5424 by default)
func NewSyslog(cfg *LoggerConfig) (*Syslog, error) {
	var err error
	log.Info("NewSyslog logger: %v", cfg)

	sys := &Syslog{
		Name: LOGGER_SYSLOG,
		cfg:  cfg,
	}

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
	log.Info("[%s logger] initialized: %v", sys.Name, cfg)

	return sys, err
}

// Open opens a new connection with a server or with the daemon.
func (s *Syslog) Open() error {
	var err error
	s.Writer, err = syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, logTag)

	return err
}

// Close closes the writer object
func (s *Syslog) Close() error {
	return s.Writer.Close()
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
		log.Error("[%s] write error: %s", s.Name, err)
	}
}
