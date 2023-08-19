// +build linux

// (c) 2018 Suchakra Sharma <suchakra@shiftleft.io>
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
	"errors"
	"io/ioutil"
	"regexp"
	"runtime"
)

const defaultSymFile = "/proc/kallsyms"

// Returns the qualified syscall named by going through '/proc/kallsyms' on the
// system on which its executed. It allows BPF programs that may have been compiled
// for older syscall functions to run on newer kernels
func GetSyscallFnName(name string) (string, error) {
	// Get kernel symbols
	syms, err := ioutil.ReadFile(defaultSymFile)
	if err != nil {
		return "", err
	}
	return getSyscallFnNameWithKallsyms(name, string(syms))
}

func getSyscallFnNameWithKallsyms(name string, kallsymsContent string) (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "386":
		arch = "ia32"
	default:
		arch = "x64"
	}

	// We should search for new syscall function like "__x64__sys_open"
	// Note the start of word boundary. Should return exactly one string
	regexStr := `(\b__` + arch + `_[Ss]y[sS]_` + name + `\b)`
	fnRegex := regexp.MustCompile(regexStr)

	match := fnRegex.FindAllString(kallsymsContent, -1)

	// If nothing found, search for old syscall function to be sure
	if len(match) == 0 {
		newRegexStr := `(\b[Ss]y[sS]_` + name + `\b)`
		fnRegex = regexp.MustCompile(newRegexStr)
		newMatch := fnRegex.FindAllString(kallsymsContent, -1)

		// If we get something like 'sys_open' or 'SyS_open', return
		// either (they have same addr) else, just return original string
		if len(newMatch) >= 1 {
			return newMatch[0], nil
		} else {
			return "", errors.New("could not find a valid syscall name")
		}
	}

	return match[0], nil
}
