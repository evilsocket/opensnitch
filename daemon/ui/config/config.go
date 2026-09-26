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

	// PortScanBlockOptions is the JSON form of the port scan response policy.
	PortScanBlockOptions struct {
		// Policy is "never", "ask" or "auto".
		//
		// The default is "ask". Three independent projects refuse automatic
		// blocking by default -- scanlogd ("Don't take any action against the
		// source of attacks unless other evidence is available"), PortSentry
		// (BLOCK_TCP="0", with an explicit denial-of-service warning) and psad
		// (ENABLE_AUTO_IDS "N") -- because the source address of a scan is
		// forgeable. nmap -D with well-chosen decoys otherwise makes the
		// victim block its own gateway and DNS servers.
		Policy string `json:"Policy"`
		// Duration is a Go duration such as "4h".
		Duration string `json:"Duration"`
		// MaxBlockedSources caps simultaneous blocks; the oldest is released
		// when the cap is reached. This bounds the damage of a decoy scan.
		// A pointer so an explicit 0 is distinguishable from an absent key: an
		// operator writing 0 to mean "no blocking" must not silently get 128.
		MaxBlockedSources *int `json:"MaxBlockedSources,omitempty"`
		// RequireTCPEvidence refuses to block a source that sent no TCP
		// evidence (a SYN, or flags without ACK).
		RequireTCPEvidence bool `json:"RequireTCPEvidence"`
		// NeverBlock lists CIDR prefixes that must never be blocked, on top of
		// the ones that are always enforced (loopback, link-local, multicast,
		// broadcast, this host's own addresses, its gateways and resolvers).
		NeverBlock []string `json:"NeverBlock"`
	}

	// PortScanOptions is the JSON form of the port scan detection settings.
	//
	// Durations are strings ("10s", "4h") rather than numbers: a JSON number
	// of nanoseconds is unreadable and unwritable by hand, and this file is
	// meant to be edited.
	PortScanOptions struct {
		Enabled bool `json:"Enabled"`
		// Source selects the packet source: "auto" (eBPF, falling back to
		// AF_PACKET), "ebpf" or "afpacket".
		Source string `json:"Source"`
		// Interfaces restricts detection; empty means every interface except
		// loopback.
		Interfaces []string `json:"Interfaces"`

		DetectTCP          bool `json:"DetectTCP"`
		DetectUDP          bool `json:"DetectUDP"`
		DetectProtocolScan bool `json:"DetectProtocolScan"`
		// DetectICMPSweep turns the ICMP host-sweep detector on or off.
		//
		// Every field of portscan.Config needs its counterpart here:
		// ToPortScanConfig builds a fresh Config field by field, so one
		// missing from this struct is left at its zero value whatever the
		// configuration file says.
		DetectICMPSweep bool `json:"DetectICMPSweep"`

		ScoreThreshold uint32 `json:"ScoreThreshold"`
		DecayInterval  string `json:"DecayInterval"`
		MaxSources     int    `json:"MaxSources"`
		IdleExpiry     string `json:"IdleExpiry"`
		// StartupGrace ignores TCP carrying ACK for a while after start-up,
		// so that packets of connections opened before the daemon began
		// tracking are not mistaken for probes.
		StartupGrace          string `json:"StartupGrace"`
		ProtoScanMinProtocols uint16 `json:"ProtoScanMinProtocols"`
		ICMPSweepMinTypes     uint16 `json:"ICMPSweepMinTypes"`

		AlertsPerMinute int    `json:"AlertsPerMinute"`
		ReportCooldown  string `json:"ReportCooldown"`
		// A pointer so an explicit [] ("exclude nothing") is distinguishable
		// from an absent key ("use the shipped list").
		ExcludedPorts *[]int `json:"ExcludedPorts,omitempty"`

		// NeverCount suppresses detection entirely for these CIDR prefixes.
		// Distinct from Block.NeverBlock, which only forbids a firewall rule.
		NeverCount []string `json:"NeverCount"`

		Block PortScanBlockOptions `json:"Block"`
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

	// PortScan configures inbound port scan detection.
	//
	// It is a pointer so that an absent "PortScan" key is distinguishable from
	// one that was written out with zero values. An absent key means "use the
	// shipped defaults"; a present one is taken literally, because silently
	// substituting a default for a threshold the operator set to zero would
	// leave them believing a limit is in force when it is not.
	PortScan *PortScanOptions `json:"PortScan,omitempty"`

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
