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

func deleteEbpfEntry(proto string, key unsafe.Pointer) bool {
	if err := m.DeleteElement(ebpfMaps[proto].bpfmap, key); err != nil {
		log.Debug("error deleting ebpf entry: %s", err)
		return false
	}
	return true
}

func getItems(proto string, isIPv6 bool) (items uint) {
	isDup := make(map[string]uint8)
	var lookupKey []byte
	var nextKey []byte

	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
	}
	var value networkEventT
	firstrun := true

	for {
		mp, ok := ebpfMaps[proto]
		if !ok {
			return
		}
		ok, err := m.LookupNextElement(mp.bpfmap, unsafe.Pointer(&lookupKey[0]),
			unsafe.Pointer(&nextKey[0]), unsafe.Pointer(&value))
		if !ok || err != nil { //reached end of map
			log.Debug("[ebpf] %s map: %d active items", proto, items)
			return
		}
		if firstrun {
			// on first run lookupKey is a dummy, nothing to delete
			firstrun = false
			copy(lookupKey, nextKey)
			continue
		}
		if counter, duped := isDup[string(lookupKey)]; duped && counter > 1 {
			deleteEbpfEntry(proto, unsafe.Pointer(&lookupKey[0]))
			continue
		}
		isDup[string(lookupKey)]++
		copy(lookupKey, nextKey)
		items++
	}

	return items
}

// deleteOldItems deletes maps' elements in order to keep them below maximum capacity.
// If ebpf maps are full they don't allow any more insertions, ending up lossing events.
func deleteOldItems(proto string, isIPv6 bool, maxToDelete uint) (deleted uint) {
	isDup := make(map[string]uint8)
	var lookupKey []byte
	var nextKey []byte
	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
	}
	var value networkEventT
	firstrun := true
	i := uint(0)

	for {
		i++
		if i > maxToDelete {
			return
		}
		ok, err := m.LookupNextElement(ebpfMaps[proto].bpfmap, unsafe.Pointer(&lookupKey[0]),
			unsafe.Pointer(&nextKey[0]), unsafe.Pointer(&value))
		if !ok || err != nil { //reached end of map
			return
		}
		if _, duped := isDup[string(lookupKey)]; duped {
			if deleteEbpfEntry(proto, unsafe.Pointer(&lookupKey[0])) {
				deleted++
				copy(lookupKey, nextKey)
				continue
			}
			return
		}

		if firstrun {
			// on first run lookupKey is a dummy, nothing to delete
			firstrun = false
			copy(lookupKey, nextKey)
			continue
		}

		if !deleteEbpfEntry(proto, unsafe.Pointer(&lookupKey[0])) {
			return
		}
		deleted++
		isDup[string(lookupKey)]++
		copy(lookupKey, nextKey)
	}

	return
}
