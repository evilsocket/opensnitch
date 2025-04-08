package dns

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
)

/*
#cgo LDFLAGS: -ldl

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <link.h>
#include <dlfcn.h>
#include <string.h>

char* find_libc() {
    void *handle;
    struct link_map * map;

    handle = dlopen(NULL, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "EBPF-DNS dlopen() failed: %s\n", dlerror());
        return NULL;
    }


    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == -1) {
        fprintf(stderr, "EBPF-DNS: dlinfo failed: %s\n", dlerror());
        return NULL;
    }

    while(1){
        if(map == NULL){
            break;
        }

        //printf("map->l_name: %s\n", map->l_name);
        if(strstr(map->l_name, "libc.so")){
            fprintf(stderr,"found %s\n", map->l_name);
            return map->l_name;
        }
        map = map->l_next;
    }
    return NULL;
}
*/
import "C"

type nameLookupEvent struct {
	AddrType uint32
	IP       [16]uint8
	Host     [252]byte
}

// ProbeDefs holds the hooks defined in the module
type ProbeDefs struct {
	URProbeGethostByname *ebpf.Program `ebpf:"uretprobe__gethostbyname"`
	UProbeGetAddrinfo    *ebpf.Program `ebpf:"uprobe__getaddrinfo"`
	URProbeGetAddrinfo   *ebpf.Program `ebpf:"uretprobe__getaddrinfo"`
}

// MapDefs holds the maps defined in the module
type MapDefs struct {
	// BPF_MAP_TYPE_RINGBUF
	PerfEvents *ebpf.Map `ebpf:"events"`
}

// container of hooks and maps
type dnsDefsT struct {
	ProbeDefs
	MapDefs
}

func findLibc() (string, error) {
	ret := C.find_libc()

	if ret == nil {
		return "", errors.New("Could not find path to libc.so")
	}
	str := C.GoString(ret)

	return str, nil
}

// Iterates over all symbols in an elf file and returns the offset matching the provided symbol name.
func lookupSymbol(elffile *elf.File, symbolName string) (uint64, error) {
	symbols, err := elffile.DynamicSymbols()
	if err != nil {
		return 0, err
	}
	for _, symb := range symbols {
		if symb.Name == symbolName {
			return symb.Value, nil
		}
	}
	return 0, fmt.Errorf("Symbol: '%s' not found", symbolName)
}

// ListenerEbpf starts listening for DNS events.
func ListenerEbpf(ebpfModPath string) error {
	probesAttached := 0
	m, err := core.LoadEbpfModule("opensnitch-dns.o", ebpfModPath)
	if err != nil {
		return err
	}
	defer m.Close()

	ebpfMod := dnsDefsT{}
	if err := m.Assign(&ebpfMod); err != nil {
		return err
	}

	// --------------

	// libbcc resolves the offsets for us. without bcc the offset for uprobes must parsed from the elf files
	// some how 0 must be replaced with the offset of getaddrinfo bcc does this using bcc_resolve_symname

	// Attaching to uprobe using perf open might be a better aproach requires https://github.com/iovisor/gobpf/pull/277

	libcFile, err := findLibc()
	if err != nil {
		log.Error("[eBPF DNS] Failed to find libc.so: %v", err)
		return err
	}
	ex, err := link.OpenExecutable(libcFile)
	if err != nil {
		return err
	}

	// --------------

	// User space needs to call perf_event_open() (...) before eBPF program can send data into it.
	rd, err := ringbuf.NewReader(ebpfMod.PerfEvents)
	if err != nil {
		return err
	}
	defer rd.Close()

	// --------------

	urg, err := ex.Uretprobe("gethostbyname", ebpfMod.URProbeGethostByname, nil)
	if err != nil {
		log.Error("[eBPF DNS] uretprobe__gethostbyname: %s", err)
	}
	defer urg.Close()
	probesAttached++

	up, err := ex.Uprobe("getaddrinfo", ebpfMod.UProbeGetAddrinfo, nil)
	if err != nil {
		log.Error("[eBPF DNS] uprobe__getaddrinfo: %s", err)
	}
	defer up.Close()
	probesAttached++

	urp, err := ex.Uretprobe("getaddrinfo", ebpfMod.URProbeGetAddrinfo, nil)
	if err != nil {
		log.Error("[eBPF-DNS] uretprobe__getaddrinfo: %s", err)
	}
	defer urp.Close()
	probesAttached++

	if probesAttached == 0 {
		log.Warning("[eBPF DNS]: Failed to find symbols for uprobes.")
		return errors.New("Failed to find symbols for uprobes")
	}

	// --------------

	exitChannel := make(chan struct{})
	perfChan := make(chan []byte, 0)

	for i := 0; i < runtime.NumCPU(); i++ {
		go spawnDNSWorker(i, perfChan, exitChannel)
	}

	go func(perfChan chan []byte, rd *ringbuf.Reader) {
		for {
			select {
			case <-exitChannel:
				goto Exit
			default:
				record, err := rd.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						goto Exit
					}
					log.Debug("[eBPF DNS] reader error: %s", err)
					continue
				}
				perfChan <- record.RawSample
			}
		}
	Exit:
		log.Debug("[eBPF DNS] reader closed")
	}(perfChan, rd)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
		syscall.SIGQUIT)

	<-sig
	log.Info("[eBPF DNS]: Received signal: terminating ebpf dns hook.")
	exitChannel <- struct{}{}
	for i := 0; i < runtime.NumCPU(); i++ {
		exitChannel <- struct{}{}
	}
	return nil
}

func spawnDNSWorker(id int, channel chan []byte, exitChannel chan struct{}) {

	log.Debug("[eBPF DNS] worker initialized #%d", id)
	var event nameLookupEvent
	var ip net.IP
	for {
		select {

		case <-time.After(1 * time.Millisecond):
			continue
		case <-exitChannel:
			goto Exit
		default:
			data := <-channel
			if len(data) > 0 {
				log.Trace("(%d) [eBPF DNS]: LookupEvent %d %x %x %x", id, len(data), data[:4], data[4:20], data[20:])
			}
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.Warning("(%d) [eBPF DNS]: Failed to decode ebpf nameLookupEvent: %s\n", id, err)
				continue
			}
			// Convert C string (null-terminated) to Go string
			host := string(event.Host[:bytes.IndexByte(event.Host[:], 0)])
			// 2 -> AF_INET (ipv4)
			if event.AddrType == 2 {
				ip = net.IP(event.IP[:4])
			} else {
				ip = net.IP(event.IP[:])
			}

			log.Debug("(%d) [eBPF DNS]: Tracking Resolved Message: %s -> %s\n", id, host, ip.String())
			Track(ip.String(), host)
		}
	}

Exit:
	log.Debug("[eBPF DNS] worker #%d closed", id)
}
