package core

import (
	"io/ioutil"
	"strings"
)

// GetHostname returns the name of the host where the damon is running.
func GetHostname() string {
	hostname, _ := ioutil.ReadFile("/proc/sys/kernel/hostname")
	return strings.Replace(string(hostname), "\n", "", -1)
}

// GetKernelVersion returns the name of the host where the damon is running.
func GetKernelVersion() string {
	version, _ := ioutil.ReadFile("/proc/sys/kernel/version")
	return strings.Replace(string(version), "\n", "", -1)
}
