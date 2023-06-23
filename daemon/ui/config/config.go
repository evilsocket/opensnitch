package config

import (
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/statistics"
)

type serverTLSOptions struct {
	CACert     string `json:"CACert"`
	ServerCert string `json:"ServerCert"`
	ServerKey  string `json:"ServerKey"`
	ClientCert string `json:"ClientCert"`
	ClientKey  string `json:"ClientKey"`
	// https://pkg.go.dev/crypto/tls#Config
	SkipVerify bool `json:"SkipVerify"`
	//https://pkg.go.dev/crypto/tls#ClientAuthType
	ClientAuthType string `json:"ClientAuthType"`

	// https://pkg.go.dev/crypto/tls#Conn.VerifyHostname
	//VerifyHostname bool
	// https://pkg.go.dev/crypto/tls#example-Config-VerifyConnection
	// VerifyConnection bool
	// VerifyPeerCertificate bool
}

type serverAuth struct {
	// token?, google?, simple-tls, mutual-tls
	Type       string           `json:"Type"`
	TLSOptions serverTLSOptions `json:"TLSOptions"`
}

type serverConfig struct {
	Address        string                 `json:"Address"`
	Authentication serverAuth             `json:"Authentication"`
	LogFile        string                 `json:"LogFile"`
	Loggers        []loggers.LoggerConfig `json:"Loggers"`
}

// Config holds the values loaded from configFile
type Config struct {
	sync.RWMutex
	Server            serverConfig           `json:"Server"`
	DefaultAction     string                 `json:"DefaultAction"`
	DefaultDuration   string                 `json:"DefaultDuration"`
	InterceptUnknown  bool                   `json:"InterceptUnknown"`
	ProcMonitorMethod string                 `json:"ProcMonitorMethod"`
	LogLevel          *uint32                `json:"LogLevel"`
	LogUTC            bool                   `json:"LogUTC"`
	LogMicro          bool                   `json:"LogMicro"`
	Firewall          string                 `json:"Firewall"`
	Stats             statistics.StatsConfig `json:"Stats"`
}
