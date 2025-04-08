package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"
)

func determineHostByteOrder() {
	lock.Lock()
	//determine host byte order
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		hostByteOrder = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		hostByteOrder = binary.BigEndian
	default:
		log.Error("Could not determine host byte order.")
	}
	lock.Unlock()
}

func mountDebugFS() error {
	debugfsPath := "/sys/kernel/debug/"
	kprobesPath := fmt.Sprint(debugfsPath, "tracing/kprobe_events")
	if core.Exists(kprobesPath) == false {
		if _, err := core.Exec("mount", []string{"-t", "debugfs", "none", debugfsPath}); err != nil {
			log.Warning("eBPF debugfs error: %s", err)
			return fmt.Errorf(`%s
Unable to access debugfs filesystem, needed for eBPF to work, likely caused by a hardened or customized kernel.
Change process monitor method to 'proc' to stop receiving this alert
			`, err)
		}
	}

	return nil
}

// Trim null characters, and return the left part of the byte array.
// NOTE: using BPF_MAP_TYPE_PERCPU_ARRAY does not initialize strings to 0,
// so we end up receiving events as follow:
// event.filename -> /usr/bin/iptables
// event.filename -> /bin/lsn/iptables (should be /bin/ls)
// It turns out, that there's a 0x00 character between "/bin/ls" and "n/iptables":
// [47 115 98 105 110 47 100 117 109 112 101 50 102 115 0 0 101 115
//                                                      ^^^
// TODO: investigate if there's any way of initializing the struct to 0
// like using __builtin_memset() (can't be used with PERCPU apparently)
func byteArrayToString(arr []byte) string {
	temp := bytes.SplitAfter(arr, []byte("\x00"))[0]
	return string(bytes.Trim(temp[:], "\x00"))
}

func deleteEbpfEntry(proto string, key []byte) bool {
	if err := ebpfMaps[proto].bpfMap.Delete(&key); err != nil {
		log.Trace("[eBPF] error deleting ebpf entry: %s", err)
		return false
	}
	return true
}

func getItems(proto string, isIPv6 bool) (items uint) {
	//isDup := make(map[string]uint8)
	var lookupKey []byte
	var nextKey []byte

	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
	}

	prot, ok := ebpfMaps[proto]
	if !ok || prot.bpfMap == nil {
		log.Trace("[eBPF] getItems: %s", proto)
		return
	}
	for err := prot.bpfMap.NextKey(nil, &lookupKey); ; err = prot.bpfMap.NextKey(&lookupKey, &nextKey) {
		if err != nil {
			break
		}
		log.Trace("[eBPF] %d cache item %s, key: %+v -> next: %+v", items, proto, lookupKey, nextKey)
		lookupKey = nextKey
		items++
	}

	return items
}

// deleteOldItems deletes maps' elements in order to keep them below maximum capacity.
// If ebpf maps are full they don't allow any more insertions, ending up lossing events.
func deleteOldItems(proto string, isIPv6 bool, maxToDelete uint) (deleted uint) {
	var lookupKey []byte
	var nextKey []byte
	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
	}

	prot, ok := ebpfMaps[proto]
	if !ok || prot.bpfMap == nil {
		log.Trace("[eBPF] DELETE ITEMS: %s", proto)
		return
	}
	for err := prot.bpfMap.NextKey(nil, &lookupKey); ; err = prot.bpfMap.NextKey(&lookupKey, &nextKey) {
		log.Trace("[eBPF] DELETE ITEMS %s: %s -> %+v -> %+v", proto, err, lookupKey, nextKey)
		if err != nil {
			break
		}
		log.Trace("[eBPF] DELETE ITEMS %s: %+v -> %+v", proto, lookupKey, nextKey)
		prot.bpfMap.Delete(&lookupKey)
		lookupKey = nextKey
	}

	return
}
