// +build linux

// (c) 2018 ShiftLeft GmbH <suchakra@shiftleft.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elf

import (
	"testing"
)

const prefixedKallsymsSymbols = `
0000000000000000 W __x32_compat_sys_open_by_handle_at
0000000000000000 T do_sys_open
0000000000000000 T __x64_sys_open
0000000000000000 T __ia32_sys_open
0000000000000000 T __x64_sys_openat
0000000000000000 T __ia32_sys_openat
0000000000000000 T __ia32_compat_sys_open
0000000000000000 T __ia32_compat_sys_openat
0000000000000000 T __x64_sys_open_by_handle_at
0000000000000000 T __ia32_sys_open_by_handle_at
0000000000000000 T __ia32_compat_sys_open_by_handle_at
0000000000000000 t proc_sys_open
0000000000000000 t _eil_addr___ia32_compat_sys_openat
0000000000000000 t _eil_addr___ia32_compat_sys_open
0000000000000000 t _eil_addr___ia32_sys_openat
0000000000000000 t _eil_addr___x64_sys_openat
0000000000000000 t _eil_addr___ia32_sys_open
0000000000000000 t _eil_addr___x64_sys_open
0000000000000000 t _eil_addr___ia32_compat_sys_open_by_handle_at
0000000000000000 t _eil_addr___ia32_sys_open_by_handle_at
0000000000000000 t _eil_addr___x64_sys_open_by_handle_at
`

const kallsymsSymbols = `
0000000000000000 T dentry_open
0000000000000000 T filp_clone_open
0000000000000000 T file_open_name
0000000000000000 T filp_open
0000000000000000 T do_sys_open
0000000000000000 T SyS_open
0000000000000000 T sys_open
0000000000000000 T SyS_openat
0000000000000000 T sys_openat
0000000000000000 T compat_SyS_open
0000000000000000 T compat_sys_open
0000000000000000 T compat_SyS_openat
0000000000000000 T compat_sys_openat
0000000000000000 T SyS_creat
0000000000000000 T sys_creat
0000000000000000 T sys_vhangup
`

func TestGetSyscallFnName(t *testing.T) {
	fnName, err := getSyscallFnNameWithKallsyms("open", prefixedKallsymsSymbols)
	if err != nil && fnName != "__x64_sys_open" {
		t.Errorf("expected __x64_sys_open : %s", err)
	}
	fnName, err = getSyscallFnNameWithKallsyms("open", kallsymsSymbols)
	if err != nil {
		if fnName != "SyS_open" {
			t.Errorf("expected SyS_open :%s", err)
		}
	}
}
