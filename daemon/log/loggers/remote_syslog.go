package loggers

import (
	"github.com/evilsocket/opensnitch/daemon/log"
)

const (
	LOGGER_REMOTE_SYSLOG = "remote_syslog"
)

type RemoteSyslog struct {
	Remote
}

// NewRemoteSyslog returns a new object that manipulates and prints outbound connections
// to a remote syslog server, with the given format (RFC5424 by default)
func NewRemoteSyslog(cfg LoggerConfig) (*RemoteSyslog, error) {
	log.Info("NewRemoteSyslog logger: %v", cfg)

	r, err := NewRemote(cfg)
	r.Name = LOGGER_REMOTE_SYSLOG
	rs := &RemoteSyslog{
		Remote: *r,
	}

	return rs, err
}

// https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/log/syslog/syslog.go;l=286;drc=0a1a092c4b56a1d4033372fbd07924dad8cbb50b
func (rs *RemoteSyslog) formatLine(msg string) string {
	return msg
}
