package ebpf

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"

	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
)

// print map contents. used only for debugging

//PrintEverything prints all the stats. used only for debugging
func PrintEverything() {
	bash, _ := exec.LookPath("bash")
	//get the number of the first map
	out, err := exec.Command(bash, "-c", "bpftool map show | head -n 1 | cut -d ':' -f1").Output()
	if err != nil {
		fmt.Println("bpftool map dump name tcpMap ", err)
	}
	i, _ := strconv.Atoi(string(out[:len(out)-1]))
	fmt.Println("i is", i)

	//dump all maps for analysis
	for j := i; j < i+14; j++ {
		_, _ = exec.Command(bash, "-c", "bpftool map dump id "+strconv.Itoa(j)+" > dump"+strconv.Itoa(j)).Output()
	}

	alreadyEstablished.RLock()
	for sock1, v := range alreadyEstablished.TCP {
		fmt.Println(*sock1, v)
	}

	fmt.Println("---------------------")
	for sock1, v := range alreadyEstablished.TCPv6 {
		fmt.Println(*sock1, v)
	}
	alreadyEstablished.RUnlock()

	fmt.Println("---------------------")
	sockets, _ := daemonNetlink.SocketsDump(syscall.AF_INET, syscall.IPPROTO_TCP)
	for idx := range sockets {
		fmt.Println("socket tcp: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET6, syscall.IPPROTO_TCP)
	for idx := range sockets {
		fmt.Println("socket tcp6: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET, syscall.IPPROTO_UDP)
	for idx := range sockets {
		fmt.Println("socket udp: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET6, syscall.IPPROTO_UDP)
	for idx := range sockets {
		fmt.Println("socket udp6: ", sockets[idx])
	}

}
