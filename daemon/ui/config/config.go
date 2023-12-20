package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"sync"

	"github.com/evilsocket/opensnitch/daemon/log"
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

type rulesOptions struct {
	Path            string `json:"Path"`
	EnableChecksums bool   `json:"EnableChecksums"`
}

type fwOptions struct {
	Firewall         string `json:"Firewall"`
	ConfigPath       string `json:"ConfigPath"`
	ActionOnOverflow string `json:"ActionOnOverflow"`
	MonitorInterval  string `json:"MonitorInterval"`
}

// Config holds the values loaded from configFile
type Config struct {
	sync.RWMutex
	Server            serverConfig           `json:"Server"`
	Stats             statistics.StatsConfig `json:"Stats"`
	DefaultAction     string                 `json:"DefaultAction"`
	DefaultDuration   string                 `json:"DefaultDuration"`
	ProcMonitorMethod string                 `json:"ProcMonitorMethod"`
	Rules             rulesOptions           `json:"Rules"`
	Firewall          string                 `json:"Firewall"`
	FwOptions         fwOptions              `json:"FwOptions"`
	LogLevel          *int32                 `json:"LogLevel"`
	InterceptUnknown  bool                   `json:"InterceptUnknown"`
	LogUTC            bool                   `json:"LogUTC"`
	LogMicro          bool                   `json:"LogMicro"`
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
