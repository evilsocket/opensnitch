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
	"strings"
	"syscall"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
	bpf "github.com/iovisor/gobpf/elf"
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
	m, err := core.LoadEbpfModule("opensnitch-dns.o", ebpfModPath)
	if err != nil {
		log.Error("[eBPF DNS]: %s", err)
		return err
	}
	defer m.Close()

	// libbcc resolves the offsets for us. without bcc the offset for uprobes must parsed from the elf files
	// some how 0 must be replaced with the offset of getaddrinfo bcc does this using bcc_resolve_symname

	// Attaching to uprobe using perf open might be a better aproach requires https://github.com/iovisor/gobpf/pull/277
	libcFile, err := findLibc()

	if err != nil {
		log.Error("EBPF-DNS: Failed to find libc.so: %v", err)
		return err
	}

	libcElf, err := elf.Open(libcFile)
	if err != nil {
		log.Error("EBPF-DNS: Failed to open %s: %v", libcFile, err)
		return err
	}
	probesAttached := 0
	for uprobe := range m.IterUprobes() {
		probeFunction := strings.Replace(uprobe.Name, "uretprobe/", "", 1)
		probeFunction = strings.Replace(probeFunction, "uprobe/", "", 1)
		offset, err := lookupSymbol(libcElf, probeFunction)
		if err != nil {
			log.Warning("EBPF-DNS: Failed to find symbol for uprobe %s (offset: %d): %s\n", uprobe.Name, offset, err)
			continue
		}
		err = bpf.AttachUprobe(uprobe, libcFile, offset)
		if err != nil {
			log.Warning("EBPF-DNS: Failed to attach uprobe %s : %s, (%s, %d)\n", uprobe.Name, err, libcFile, offset)
			continue
		}
		probesAttached++
	}

	if probesAttached == 0 {
		log.Warning("EBPF-DNS: Failed to find symbols for uprobes.")
		return errors.New("Failed to find symbols for uprobes")
	}

	// Reading Events
	channel := make(chan []byte)
	//log.Warning("EBPF-DNS: %+v\n", m)
	perfMap, err := bpf.InitPerfMap(m, "events", channel, nil)
	if err != nil {
		log.Error("EBPF-DNS: Failed to init perf map: %s\n", err)
		return err
	}
	sig := make(chan os.Signal, 1)
	exitChannel := make(chan bool)
	signal.Notify(sig,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
		syscall.SIGQUIT)

	for i := 0; i < 5; i++ {
		go spawnDNSWorker(i, channel, exitChannel)
	}

	perfMap.PollStart()
	<-sig
	log.Info("EBPF-DNS: Received signal: terminating ebpf dns hook.")
	perfMap.PollStop()
	for i := 0; i < 5; i++ {
		exitChannel <- true
	}
	return nil
}

func spawnDNSWorker(id int, channel chan []byte, exitChannel chan bool) {

	log.Debug("dns worker initialized #%d", id)
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
				log.Debug("(%d) EBPF-DNS: LookupEvent %d %x %x %x", id, len(data), data[:4], data[4:20], data[20:])
			}
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.Warning("(%d) EBPF-DNS: Failed to decode ebpf nameLookupEvent: %s\n", id, err)
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

			log.Debug("(%d) EBPF-DNS: Tracking Resolved Message: %s -> %s\n", id, host, ip.String())
			Track(ip.String(), host)
		}
	}

Exit:
	log.Debug("DNS worker #%d closed", id)
}
