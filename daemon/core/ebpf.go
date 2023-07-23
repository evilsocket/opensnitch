package core

import (
	"fmt"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/iovisor/gobpf/elf"
)

// LoadEbpfModule loads the given eBPF module
// It'll try to load from several paths.
func LoadEbpfModule(module string) (m *elf.Module, err error) {
	var (
		modulesDir = "/opensnitchd/ebpf"
		paths      = []string{
			fmt.Sprint("/usr/local/lib", modulesDir),
			fmt.Sprint("/usr/lib", modulesDir),
			fmt.Sprint("/etc/opensnitchd"), // Deprecated: will be removed in future versions.
		}
	)
	modulePath := ""
	moduleError := fmt.Errorf(`Module not found (%s) in any of the paths.
You may need to install the corresponding package`, module)

	for _, p := range paths {
		modulePath = fmt.Sprint(p, "/", module)
		log.Debug("[eBPF] trying to load %s", modulePath)
		if !Exists(modulePath) {
			continue
		}
		m = elf.NewModule(modulePath)

		if m.Load(nil) == nil {
			log.Info("[eBPF] module loaded: %s", modulePath)
			return m, nil
		}
		moduleError = fmt.Errorf(`
unable to load eBPF module (%s). Your kernel version (%s) might not be compatible.
If this error persists, change process monitor method to 'proc'`, module, GetKernelVersion())
	}

	return m, moduleError
}
