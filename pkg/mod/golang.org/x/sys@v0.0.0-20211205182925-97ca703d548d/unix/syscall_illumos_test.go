// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build illumos
// +build illumos

package unix_test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLifreqSetName(t *testing.T) {
	var l unix.Lifreq
	err := l.SetName("12345678901234356789012345678901234567890")
	if err == nil {
		t.Fatal(`Lifreq.SetName should reject names that are too long`)
	}
	err = l.SetName("tun0")
	if err != nil {
		t.Errorf(`Lifreq.SetName("tun0") failed: %v`, err)
	}
}

func TestLifreqGetMTU(t *testing.T) {
	// Find links and their MTU using CLI tooling
	// $ dladm show-link -p -o link,mtu
	// net0:1500
	out, err := exec.Command("dladm", "show-link", "-p", "-o", "link,mtu").Output()
	if err != nil {
		t.Fatalf("unable to use dladm to find data links: %v", err)
	}
	lines := strings.Split(string(out), "\n")
	tc := make(map[string]string)
	for _, line := range lines {
		v := strings.Split(line, ":")
		if len(v) == 2 {
			tc[v[0]] = v[1]
		}
	}
	ip_fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("could not open udp socket: %v", err)
	}
	// SIOCGLIFMTU is negative which confuses the compiler if used inline:
	// Using "unix.IoctlLifreq(ip_fd, unix.SIOCGLIFMTU, &l)" results in
	// "constant -1065850502 overflows uint"
	reqnum := int(unix.SIOCGLIFMTU)
	var l unix.Lifreq
	for link, mtu := range tc {
		err = l.SetName(link)
		if err != nil {
			t.Fatalf("Lifreq.SetName(%q) failed: %v", link, err)
		}
		if err = unix.IoctlLifreq(ip_fd, uint(reqnum), &l); err != nil {
			t.Fatalf("unable to SIOCGLIFMTU: %v", err)
		}
		m := l.GetLifruUint()
		if fmt.Sprintf("%d", m) != mtu {
			t.Errorf("unable to read MTU correctly: expected %s, got %d", mtu, m)
		}
	}
}
