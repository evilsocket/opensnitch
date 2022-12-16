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
			fmt.Sprint("/etc/opensnitchd"), // deprecated
		}
	)
	modulesPath := ""
	for _, p := range paths {
		modulesPath = p
		m = elf.NewModule(fmt.Sprint(modulesPath, "/", module))

		if err = m.Load(nil); err == nil {
			log.Info("[eBPF] module loaded: %s/%s", modulesPath, module)
			return m, nil
		}
		log.Debug("ebpf module not found: %s, %s/%s", err, modulesPath, module)
	}

	return m, fmt.Errorf(`
unable to load eBPF module (%s). Your kernel version (%s) might not be compatible.
If this error persists, change process monitor method to 'proc'`, module, GetKernelVersion())
}
