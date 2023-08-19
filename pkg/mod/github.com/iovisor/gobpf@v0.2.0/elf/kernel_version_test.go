// +build linux

// Copyright 2017 Kinvolk
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

var testData = []struct {
	succeed       bool
	releaseString string
	kernelVersion uint32
}{
	{true, "4.1.2-3", 262402},
	{true, "4.8.14-200.fc24.x86_64", 264206},
	{true, "4.1.2-3foo", 262402},
	{true, "4.1.2foo-1", 262402},
	{true, "4.1.2-rkt-v1", 262402},
	{true, "4.1.2rkt-v1", 262402},
	{true, "4.1.2-3 foo", 262402},
	{false, "foo 4.1.2-3", 0},
	{true, "4.1.2", 262402},
	{false, ".4.1.2", 0},
	{false, "4.1.", 0},
	{false, "4.1", 0},
}

func TestKernelVersionFromReleaseString(t *testing.T) {
	for _, test := range testData {
		version, err := KernelVersionFromReleaseString(test.releaseString)
		if err != nil && test.succeed {
			t.Errorf("expected %q to succeed: %s", test.releaseString, err)
		} else if err == nil && !test.succeed {
			t.Errorf("expected %q to fail", test.releaseString)
		}
		if version != test.kernelVersion {
			t.Errorf("expected kernel version %d, got %d", test.kernelVersion, version)
		}
	}
}

func TestParseDebianVersion(t *testing.T) {
	for _, tc := range []struct {
		succeed       bool
		releaseString string
		kernelVersion uint32
	}{
		// 4.9.168
		{true, "Linux version 4.9.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 6.3.0 20170516 (Debian 6.3.0-18+deb9u1) ) #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16)", 264616},
		// 4.9.88
		{true, "Linux ip-10-0-75-49 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64 GNU/Linux", 264536},
		// 3.0.4
		{true, "Linux version 3.16.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u2) ) #1 SMP Debian 3.16.68-1 (2019-05-22)", 200772},
		// Invalid
		{false, "Linux version 4.9.125-linuxkit (root@659b6d51c354) (gcc version 6.4.0 (Alpine 6.4.0) ) #1 SMP Fri Sep 7 08:20:28 UTC 2018", 0},
	} {
		version, err := parseDebianVersion(tc.releaseString)
		if err != nil && tc.succeed {
			t.Errorf("expected %q to succeed: %s", tc.releaseString, err)
		} else if err == nil && !tc.succeed {
			t.Errorf("expected %q to fail", tc.releaseString)
		}
		if version != tc.kernelVersion {
			t.Errorf("expected kernel version %d, got %d", tc.kernelVersion, version)
		}
	}
}
