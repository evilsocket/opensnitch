package core

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/evilsocket/opensnitch/daemon/log"
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

// GetKernelVersion returns the kernel version.
func GetKernelVersion() string {
	version, _ := ioutil.ReadFile("/proc/sys/kernel/osrelease")
	return strings.Replace(string(version), "\n", "", -1)
}

// CheckSysRequirements checks system features we need to work properly
func CheckSysRequirements() {
	type checksT struct {
		RegExps []string
		Reason  string
	}
	type ReqsList struct {
		Item   string
		Checks checksT
	}
	kVer := GetKernelVersion()

	log.Raw("\n\t%sChecking system requirements for kernel version %s%s\n", log.FG_WHITE+log.BG_LBLUE, kVer, log.RESET)
	log.Raw("%s------------------------------------------------------------------------------%s\n\n", log.FG_WHITE+log.BG_LBLUE, log.RESET)

	confFile := fmt.Sprint("/boot/config-", kVer)
	var fileContent []byte
	var err error
	if Exists(confFile) {
		fileContent, err = ioutil.ReadFile(confFile)
	} else {
		confFile = "/proc/config.gz"
		fileContent, err = ReadGzipFile(confFile)
	}
	if err != nil {
		log.Error("%s not found", confFile)
		return
	}

	// TODO: check loaded/configured modules (nfnetlink, nfnetlink_queue, xt_NFQUEUE, etc)
	// Other items to check:
	// CONFIG_NETFILTER_NETLINK
	// CONFIG_NETFILTER_NETLINK_QUEUE
	const reqsList = `
[
{
    "Item": "kprobes",
    "Checks": {
        "Regexps": [
            "CONFIG_KPROBES=y",
            "CONFIG_KPROBES_ON_FTRACE=y",
            "CONFIG_KPROBES_ON_FTRACE=y",
            "CONFIG_HAVE_KPROBES=y",
            "CONFIG_HAVE_KPROBES_ON_FTRACE=y",
            "CONFIG_KPROBE_EVENTS=y"
            ],
        "Reason": " - KPROBES not fully supported by this kernel."
    }
},
{
    "Item": "uprobes",
    "Checks": {
        "Regexps": [
            "CONFIG_UPROBES=y",
            "CONFIG_UPROBE_EVENTS=y"
            ],
        "Reason": " * UPROBES not supported. Common error => cannot open uprobe_events: open /sys/kernel/debug/tracing/uprobe_events"
    }
},
{
    "Item": "ftrace",
    "Checks": {
        "Regexps": [
            "CONFIG_FTRACE=y"
            ],
        "Reason": " - CONFIG_TRACE=y not set. Common error => Error while loading kprobes: invalid argument."
    }
},
{
    "Item": "syscalls",
    "Checks": {
        "Regexps": [
            "CONFIG_HAVE_SYSCALL_TRACEPOINTS=y",
            "CONFIG_FTRACE_SYSCALLS=y"
            ],
        "Reason": " - CONFIG_FTRACE_SYSCALLS or CONFIG_HAVE_SYSCALL_TRACEPOINTS not set. Common error => error enabling tracepoint tracepoint/syscalls/sys_enter_execve: cannot read tracepoint id"
    }
},
{
    "Item": "nfqueue",
    "Checks": {
        "Regexps": [
			"CONFIG_NETFILTER_NETLINK_QUEUE=[my]",
			"CONFIG_NFT_QUEUE=[my]",
            "CONFIG_NETFILTER_XT_TARGET_NFQUEUE=[my]"
            ],
        "Reason": " * NFQUEUE netfilter extensions not supported by this kernel (CONFIG_NETFILTER_NETLINK_QUEUE, CONFIG_NFT_QUEUE, CONFIG_NETFILTER_XT_TARGET_NFQUEUE)."
    }
},
{
    "Item": "netlink",
    "Checks": {
        "Regexps": [
			"CONFIG_NETFILTER_NETLINK=[my]",
			"CONFIG_NETFILTER_NETLINK_QUEUE=[my]",
			"CONFIG_NETFILTER_NETLINK_ACCT=[my]",
			"CONFIG_PROC_EVENTS=[my]"
            ],
        "Reason": " * NETLINK extensions not supported by this kernel (CONFIG_NETFILTER_NETLINK, CONFIG_NETFILTER_NETLINK_QUEUE, CONFIG_NETFILTER_NETLINK_ACCT or CONFIG_PROC_EVENTS)."
    }
},
{
    "Item": "net diagnostics",
    "Checks": {
        "Regexps": [
			"CONFIG_INET_DIAG=[my]",
			"CONFIG_INET_TCP_DIAG=[my]",
			"CONFIG_INET_UDP_DIAG=[my]",
			"CONFIG_INET_DIAG_DESTROY=[my]"
            ],
        "Reason": " * One or more socket monitoring interfaces are not enabled (CONFIG_INET_DIAG, CONFIG_INET_TCP_DIAG, CONFIG_INET_UDP_DIAG, CONFIG_DIAG_DESTROY (Reject feature))."
    }
}
]
`

	reqsFullfiled := true
	dec := json.NewDecoder(strings.NewReader(reqsList))
	for {
		var reqs []ReqsList
		if err := dec.Decode(&reqs); err == io.EOF {
			break
		} else if err != nil {
			log.Error("%s", err)
			break
		}
		for _, req := range reqs {
			checkOk := true
			for _, trex := range req.Checks.RegExps {
				fmt.Printf("\tChecking => %s\n", trex)
				re, err := regexp.Compile(trex)
				if err != nil {
					fmt.Printf("\t%s %s\n", log.Bold(log.Red("Invalid regexp =>")), log.Red(trex))
					continue
				}
				if re.Find(fileContent) == nil {
					fmt.Printf("\t%s\n", log.Red(req.Checks.Reason))
					checkOk = false
				}
			}
			if checkOk {
				fmt.Printf("\n\t* %s\t %s\n", log.Bold(log.Green(req.Item)), log.Bold(log.Green("✔")))
			} else {
				reqsFullfiled = false
				fmt.Printf("\n\t* %s\t %s\n", log.Bold(log.Red(req.Item)), log.Bold(log.Red("✘")))
			}
			fmt.Println()
		}
	}
	if !reqsFullfiled {
		log.Raw("\n%sWARNING:%s Your kernel doesn't support some of the features OpenSnitch needs:\nRead more: https://github.com/evilsocket/opensnitch/issues/774\n", log.FG_WHITE+log.BG_YELLOW, log.RESET)
	}
}
