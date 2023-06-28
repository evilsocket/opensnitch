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

// Parse determines if the given configuration is ok.
func Parse(rawConfig interface{}) (conf Config, err error) {
	if vt := reflect.ValueOf(rawConfig).Kind(); vt == reflect.String {
		err = json.Unmarshal([]byte((rawConfig.(string))), &conf)
	} else {
		err = json.Unmarshal(rawConfig.([]uint8), &conf)
	}
	return conf, err
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
