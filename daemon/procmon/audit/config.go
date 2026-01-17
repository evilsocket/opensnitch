package audit

import "github.com/evilsocket/opensnitch/daemon/log"

// Config holds the configuration to customize ebpf module behaviour.
type Config struct {
	AudispSocketPath string `json:"AudispSocketPath"`
}

func setConfig(auditOpts Config) {
	auditCfg = auditOpts

	log.Debug("[audit] config loaded: %v", auditOpts)
}
