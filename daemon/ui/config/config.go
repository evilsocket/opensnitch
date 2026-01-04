package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/log/loggers"
	"github.com/evilsocket/opensnitch/daemon/procmon/audit"
	"github.com/evilsocket/opensnitch/daemon/procmon/ebpf"
	"github.com/evilsocket/opensnitch/daemon/statistics"
)

type (
	// ServerTLSOptions struct
	ServerTLSOptions struct {
		CACert     string `json:"CACert"`
		ServerCert string `json:"ServerCert"`
		ServerKey  string `json:"ServerKey"`
		ClientCert string `json:"ClientCert"`
		ClientKey  string `json:"ClientKey"`
		// https://pkg.go.dev/crypto/tls#ClientAuthType
		ClientAuthType string `json:"ClientAuthType"`
		// https://pkg.go.dev/crypto/tls#Config
		SkipVerify bool `json:"SkipVerify"`
		// https://pkg.go.dev/crypto/tls#Conn.VerifyHostname
		// VerifyHostname bool
		// https://pkg.go.dev/crypto/tls#example-Config-VerifyConnection
		// VerifyConnection bool
		// VerifyPeerCertificate bool
	}

	// ServerAuth struct
	ServerAuth struct {
		// token?, google?, simple-tls, mutual-tls
		Type       string           `json:"Type"`
		TLSOptions ServerTLSOptions `json:"TLSOptions"`
	}

	// ServerConfig struct
	ServerConfig struct {
		Address        string                 `json:"Address"`
		Authentication ServerAuth             `json:"Authentication"`
		LogFile        string                 `json:"LogFile"`
		Loggers        []loggers.LoggerConfig `json:"Loggers"`
	}

	// RulesOptions struct
	RulesOptions struct {
		Path            string `json:"Path"`
		EnableChecksums bool   `json:"EnableChecksums"`
		// EvaluationMode determines how rules are matched:
		// - "deny-priority" (default): deny/reject rules always win over allow
		// - "first-match": first matching rule wins (RouterOS-style)
		EvaluationMode string `json:"EvaluationMode"`
	}

	// FwOptions struct
	FwOptions struct {
		Firewall        string `json:"Firewall"`
		ConfigPath      string `json:"ConfigPath"`
		MonitorInterval string `json:"MonitorInterval"`
		QueueNum        uint16 `json:"QueueNum"`
		QueueBypass     bool   `json:"QueueBypass"`
	}

	TasksOptions struct {
		ConfigPath string `json:"ConfigPath"`
	}

	// InternalOptions struct
	InternalOptions struct {
		GCPercent         int  `json:"GCPercent"`
		FlushConnsOnStart bool `json:"FlushConnsOnStart"`
	}
)

// Config holds the values loaded from configFile
type Config struct {
	LogLevel          *int32                 `json:"LogLevel"`
	Firewall          string                 `json:"Firewall"`
	DefaultAction     string                 `json:"DefaultAction"`
	DefaultDuration   string                 `json:"DefaultDuration"`
	ProcMonitorMethod string                 `json:"ProcMonitorMethod"`
	FwOptions         FwOptions              `json:"FwOptions"`
	Audit             audit.Config           `json:"Audit"`
	Ebpf              ebpf.Config            `json:"Ebpf"`
	Server            ServerConfig           `json:"Server"`
	Rules             RulesOptions           `json:"Rules"`
	Internal          InternalOptions        `json:"Internal"`
	Stats             statistics.StatsConfig `json:"Stats"`
	TasksOptions      TasksOptions           `json:"Tasks"`

	InterceptUnknown bool `json:"InterceptUnknown"`
	LogUTC           bool `json:"LogUTC"`
	LogMicro         bool `json:"LogMicro"`
}

// Parse determines if the given configuration is ok.
func Parse(rawConfig interface{}) (conf Config, err error) {
	if vt := reflect.ValueOf(rawConfig).Kind(); vt == reflect.String {
		err = json.Unmarshal([]byte((rawConfig.(string))), &conf)
	} else {
		err = json.Unmarshal(rawConfig.([]uint8), &conf)
	}
	return conf, err
}

func Marshal(conf Config) ([]byte, error) {
	return json.Marshal(conf)
}

// Load loads the content of a file from disk.
func Load(configFile string) ([]byte, error) {
	raw, err := ioutil.ReadFile(configFile)
	if err != nil || len(raw) == 0 {
		return nil, err
	}

	return raw, nil
}

// Save writes daemon configuration to disk.
func Save(configFile, rawConfig string) (err error) {
	if _, err = Parse(rawConfig); err != nil {
		return fmt.Errorf("Error parsing configuration %s: %s", rawConfig, err)
	}

	if err = os.Chmod(configFile, 0600); err != nil {
		log.Warning("unable to set permissions to default config: %s", err)
	}
	if err = ioutil.WriteFile(configFile, []byte(rawConfig), 0644); err != nil {
		log.Error("writing configuration to disk: %s", err)
		return err
	}
	return nil
}
