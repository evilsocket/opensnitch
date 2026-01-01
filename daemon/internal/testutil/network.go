//go:build linux

/*
Package testutil provides test infrastructure for OpenSnitch integration tests.

Network Test Harness

TestNetwork provides a safe way to run integration tests that require network
operations, iptables rules, or other privileged actions.

Testing Modes:

  Namespaced (default, safe on host):
    sudo go test -v ./daemon/netfilter/
    sudo go test -v ./daemon/procmon/ebpf/

  Native (for VMs, requires disposable system):
    sudo TEST_NATIVE=1 go test -v ./daemon/netfilter/
    sudo TEST_NATIVE=1 go test -v ./daemon/procmon/ebpf/

Why Root/Capabilities?

Different tests require different capabilities:

  eBPF tests (daemon/procmon/ebpf/):
    - CAP_BPF: load eBPF programs
    - CAP_PERFMON: attach to tracepoints and perf events
    - CAP_SYS_ADMIN: attach kprobes, access kernel memory
    - CAP_NET_ADMIN: network namespace operations (for tunnel tests)

  Netfilter tests (daemon/netfilter/):
    - CAP_NET_ADMIN: create/bind netfilter queues, modify iptables rules
    - CAP_NET_RAW: send/receive raw packets for testing
    - Note: Test binary is re-executed inside namespace, so nfqueue works
      normally without cross-namespace complications

System Safety:

Tests using this infrastructure will not mess up your system:

  - Network tests run inside an isolated network namespace by default
  - Use TEST_NATIVE=1 only in disposable VMs
  - Network connection tests use local loopback (no external connections)
  - Tunnel tests (IPIP, VXLAN) run inside isolated namespace
  - All iptables rules and queues are cleaned up after tests complete
  - eBPF programs are unloaded when tests complete
  - No persistent changes are made to the system
*/
package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// TestNetwork abstracts network setup for integration tests.
// Allows running in namespace (safe on host) or native (in VM).
type TestNetwork interface {
	Setup() error
	Exec(name string, args ...string) ([]byte, error)
	ExecPassthrough(name string, args ...string) error
	Cleanup()
	IsNative() bool
	NamespaceName() string
}

// NativeNetwork runs commands directly on the system.
// Use in disposable VMs only.
type NativeNetwork struct {
	cleanupCmds [][]string
}

func (n *NativeNetwork) Setup() error {
	return nil
}

func (n *NativeNetwork) Exec(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func (n *NativeNetwork) ExecPassthrough(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func (n *NativeNetwork) NamespaceName() string {
	return "" // Native mode has no namespace
}

// AddCleanup registers a cleanup command to run when Cleanup() is called.
func (n *NativeNetwork) AddCleanup(name string, args ...string) {
	n.cleanupCmds = append(n.cleanupCmds, append([]string{name}, args...))
}

func (n *NativeNetwork) Cleanup() {
	// Run cleanup commands in reverse order
	for i := len(n.cleanupCmds) - 1; i >= 0; i-- {
		cmd := n.cleanupCmds[i]
		exec.Command(cmd[0], cmd[1:]...).Run()
	}
}

func (n *NativeNetwork) IsNative() bool {
	return true
}

// NamespacedNetwork runs commands in an isolated network namespace.
// Safe to use on host systems.
type NamespacedNetwork struct {
	nsName string
}

func (n *NamespacedNetwork) Setup() error {
	n.nsName = fmt.Sprintf("test-%d", os.Getpid())
	out, err := exec.Command("ip", "netns", "add", n.nsName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create namespace: %v: %s", err, out)
	}

	// Bring up loopback interface in namespace
	out, err = n.Exec("ip", "link", "set", "lo", "up")
	if err != nil {
		exec.Command("ip", "netns", "del", n.nsName).Run()
		return fmt.Errorf("failed to bring up loopback: %v: %s", err, out)
	}

	return nil
}

func (n *NamespacedNetwork) Exec(name string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"netns", "exec", n.nsName, name}, args...)
	cmd := exec.Command("ip", fullArgs...)
	return cmd.CombinedOutput()
}

func (n *NamespacedNetwork) ExecPassthrough(name string, args ...string) error {
	fullArgs := append([]string{"netns", "exec", n.nsName, name}, args...)
	cmd := exec.Command("ip", fullArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func (n *NamespacedNetwork) NamespaceName() string {
	return n.nsName
}

func (n *NamespacedNetwork) Cleanup() {
	if n.nsName != "" {
		exec.Command("ip", "netns", "del", n.nsName).Run()
	}
}

func (n *NamespacedNetwork) IsNative() bool {
	return false
}

// NewTestNetwork creates the appropriate network abstraction.
// Set TEST_NATIVE=1 to run without namespace (for VMs).
func NewTestNetwork() TestNetwork {
	if os.Getenv("TEST_NATIVE") == "1" {
		return &NativeNetwork{}
	}
	return &NamespacedNetwork{}
}

// Subprocess Test Isolation
//
// These helpers support running each test in a separate subprocess to ensure
// fresh global state. This is needed when C code has global variables that
// aren't reset between tests (e.g., netfilter's `stop` flag).
//
// Usage in TestMain:
//
//	func TestMain(m *testing.M) {
//	    if testutil.IsSubprocess() {
//	        os.Exit(m.Run())
//	    }
//	    if os.Getenv("TEST_NATIVE") == "1" {
//	        os.Exit(m.Run())
//	    }
//	    if os.Getuid() != 0 {
//	        fmt.Fprintln(os.Stderr, "requires root")
//	        os.Exit(1)
//	    }
//	    testNet := testutil.NewTestNetwork()
//	    testNet.Setup()
//	    defer testNet.Cleanup()
//	    os.Exit(testutil.RunTestsIsolated(testNet, allTests, os.Args))
//	}

// IsSubprocess returns true if running inside a test subprocess.
func IsSubprocess() bool {
	return os.Getenv("IN_TEST_NS") == "1"
}

// GetTestRunPattern extracts the -test.run pattern from command line args.
// Returns empty string if no pattern specified.
func GetTestRunPattern(args []string) string {
	for i, arg := range args {
		if arg == "-test.run" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "-test.run=") {
			return strings.TrimPrefix(arg, "-test.run=")
		}
	}
	return ""
}

// RunTestsIsolated runs each test in a separate subprocess inside the namespace.
// This ensures fresh global state for each test.
// If a -test.run pattern is specified, runs matching tests in a single subprocess.
// Returns exit code (0 for success, 1 for failure).
func RunTestsIsolated(testNet TestNetwork, tests []string, args []string) int {
	testBinary := args[0]

	// Check if user specified a test pattern
	if pattern := GetTestRunPattern(args); pattern != "" {
		// Run with user's pattern in single subprocess
		os.Setenv("IN_TEST_NS", "1")
		if err := testNet.ExecPassthrough(testBinary, args[1:]...); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				return exitErr.ExitCode()
			}
			return 1
		}
		return 0
	}

	// No pattern - run each test in its own subprocess
	exitCode := 0
	for _, testName := range tests {
		testArgs := buildSubprocessArgs(testName, args[1:])
		os.Setenv("IN_TEST_NS", "1")
		if err := testNet.ExecPassthrough(testBinary, testArgs...); err != nil {
			exitCode = 1
		}
	}
	return exitCode
}

// buildSubprocessArgs creates args for running a single test in subprocess
func buildSubprocessArgs(testName string, originalArgs []string) []string {
	args := []string{"-test.run=^" + testName + "$"}
	for _, arg := range originalArgs {
		// Pass through relevant test flags
		if strings.HasPrefix(arg, "-test.v") ||
			strings.HasPrefix(arg, "-test.timeout") ||
			strings.HasPrefix(arg, "-test.count") ||
			strings.HasPrefix(arg, "-test.short") {
			args = append(args, arg)
		}
	}
	return args
}
