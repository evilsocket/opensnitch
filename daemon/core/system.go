package core

import (
	"io/ioutil"
	"strings"
)

var (
	// IPv6Enabled indicates if IPv6 protocol is enabled in the system
	IPv6Enabled = Exists("/proc/sys/net/ipv6")
)

// GetHostname returns the name of the host where the daemon is running.
func GetHostname() string {
	hostname, _ := ioutil.ReadFile("/proc/sys/kernel/hostname")
	return strings.Replace(string(hostname), "\n", "", -1)
}

// GetKernelVersion returns the name of the host where the daemon is running.
func GetKernelVersion() string {
	version, _ := ioutil.ReadFile("/proc/sys/kernel/version")
	return strings.Replace(string(version), "\n", "", -1)
}
