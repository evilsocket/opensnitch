// +build linux

// Copyright 2016 Cilium Project
// Copyright 2016 Sylvain Afchain
// Copyright 2016 Kinvolk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elf

import (
	"fmt"
	"os"
	"sort"
	"syscall"
	"unsafe"

	"github.com/iovisor/gobpf/pkg/cpuonline"
)

/*
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/perf_event.h>
#include <poll.h>

// from https://github.com/cilium/cilium/blob/master/pkg/bpf/perf.go

struct event_sample {
	struct perf_event_header header;
	uint32_t size;
	uint8_t data[];
};

struct read_state {
	void *buf;
	int buf_len;
	// These two fields are for backward reading: as opposed to normal ring buffers,
	// backward read buffers don't update the read pointer when reading.
	// So we keep the state externally here.
	uint64_t data_head_initialized;
	uint64_t data_head;
	uint64_t wrapped;
};

static int perf_event_read(int page_count, int page_size, void *_state,
		    void *_header, void *_sample_ptr, void *_lost_ptr)
{
	volatile struct perf_event_mmap_page *header = _header;
	uint64_t data_head = *((volatile uint64_t *) &header->data_head);
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	void *base  = ((uint8_t *)header) + page_size;
	struct read_state *state = _state;
	struct event_sample *e;
	void *begin, *end;
	void **sample_ptr = (void **) _sample_ptr;
	void **lost_ptr = (void **) _lost_ptr;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return 0;

	begin = base + data_tail % raw_size;
	e = begin;
	end = base + (data_tail + e->header.size) % raw_size;

	if (state->buf_len < e->header.size || !state->buf) {
		state->buf = realloc(state->buf, e->header.size);
		state->buf_len = e->header.size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;

		memcpy(state->buf, begin, len);
		memcpy((char *) state->buf + len, base, e->header.size - len);

		e = state->buf;
	} else {
		memcpy(state->buf, begin, e->header.size);
	}

	switch (e->header.type) {
	case PERF_RECORD_SAMPLE:
		*sample_ptr = state->buf;
		break;
	case PERF_RECORD_LOST:
		*lost_ptr = state->buf;
		break;
	}

	__sync_synchronize();
	header->data_tail += e->header.size;

	return e->header.type;
}

static int perf_event_dump_backward(int page_count, int page_size, void *_state,
		    void *_header, void *_sample_ptr)
{
	volatile struct perf_event_mmap_page *header = _header;
	uint64_t data_head = header->data_head;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	void *base  = ((uint8_t *)header) + page_size;
	struct read_state *state = _state;
	struct perf_event_header *p, *head;
	void **sample_ptr = (void **) _sample_ptr;
	void *begin, *end;
	uint64_t new_head;

	if (state->data_head_initialized == 0) {
		state->data_head_initialized = 1;
		state->data_head = data_head & (raw_size - 1);
	}

	if ((state->wrapped && state->data_head >= data_head) || state->wrapped > 1) {
		return 0;
	}

	begin = p = base + state->data_head;

	if (p->type != PERF_RECORD_SAMPLE)
		return 0;

	new_head = (state->data_head + p->size) & (raw_size - 1);
	end = base + new_head;

	if (state->buf_len < p->size || !state->buf) {
		state->buf = realloc(state->buf, p->size);
		state->buf_len = p->size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;

		memcpy(state->buf, begin, len);
		memcpy((char *) state->buf + len, base, p->size - len);
	} else {
		memcpy(state->buf, begin, p->size);
	}

	*sample_ptr = state->buf;

	if (new_head <= state->data_head) {
		state->wrapped++;
	}

	state->data_head = new_head;

	return p->type;
}
*/
import "C"

type PerfMap struct {
	name         string
	program      *Module
	pageCount    int
	receiverChan chan []byte
	lostChan     chan uint64
	pollStop     chan struct{}
	timestamp    func(*[]byte) uint64
}

// Matching 'struct perf_event_sample in kernel sources
type PerfEventSample struct {
	PerfEventHeader
	Size uint32
	data byte // Size bytes of data
}

func InitPerfMap(b *Module, mapName string, receiverChan chan []byte, lostChan chan uint64) (*PerfMap, error) {
	m, ok := b.maps[mapName]
	if !ok {
		return nil, fmt.Errorf("no map with name %s", mapName)
	}
	if receiverChan == nil {
		return nil, fmt.Errorf("receiverChan is nil")
	}
	// Maps are initialized in b.Load(), nothing to do here
	return &PerfMap{
		name:         mapName,
		program:      b,
		pageCount:    m.pageCount,
		receiverChan: receiverChan,
		lostChan:     lostChan,
		pollStop:     make(chan struct{}),
	}, nil
}

func (pm *PerfMap) SwapAndDumpBackward() (out [][]byte) {
	m, ok := pm.program.maps[pm.name]
	if !ok {
		// should not happen or only when pm.program is
		// suddenly changed
		panic(fmt.Sprintf("cannot find map %q", pm.name))
	}

	// step 1: create a new perf ring buffer
	pmuFds, headers, bases, err := createPerfRingBuffer(true, true, pm.pageCount)
	if err != nil {
		return
	}

	cpus, err := cpuonline.Get()
	if err != nil {
		return
	}

	// step 2: swap file descriptors
	// after it the ebpf programs will write to the new map
	for index, cpu := range cpus {
		// assign perf fd to map
		err := pm.program.UpdateElement(m, unsafe.Pointer(&cpu), unsafe.Pointer(&pmuFds[index]), 0)
		if err != nil {
			return
		}
	}

	// step 3: dump old buffer
	out = pm.DumpBackward()

	// step4: close old buffer
	// unmap
	for _, base := range m.bases {
		err := syscall.Munmap(base)
		if err != nil {
			return
		}
	}

	for _, fd := range m.pmuFDs {
		// disable
		_, _, err2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), C.PERF_EVENT_IOC_DISABLE, 0)
		if err2 != 0 {
			return
		}

		// close
		if err := syscall.Close(int(fd)); err != nil {
			return
		}
	}

	// update file descriptors to new perf ring buffer
	m.pmuFDs = pmuFds
	m.headers = headers
	m.bases = bases

	return
}

func (pm *PerfMap) DumpBackward() (out [][]byte) {
	incoming := OrderedBytesArray{timestamp: pm.timestamp}

	m, ok := pm.program.maps[pm.name]
	if !ok {
		// should not happen or only when pm.program is
		// suddenly changed
		panic(fmt.Sprintf("cannot find map %q", pm.name))
	}

	cpuCount := len(m.pmuFDs)
	pageSize := os.Getpagesize()
	for cpu := 0; cpu < cpuCount; cpu++ {
		state := C.struct_read_state{}
	ringBufferLoop:
		for {
			var sample *PerfEventSample
			ok := C.perf_event_dump_backward(C.int(pm.pageCount), C.int(pageSize),
				unsafe.Pointer(&state), unsafe.Pointer(m.headers[cpu]),
				unsafe.Pointer(&sample))
			switch ok {
			case 0:
				break ringBufferLoop // nothing to read
			case C.PERF_RECORD_SAMPLE:
				size := sample.Size - 4
				b := C.GoBytes(unsafe.Pointer(&sample.data), C.int(size))
				incoming.bytesArray = append(incoming.bytesArray, b)
			}
		}
	}

	if incoming.timestamp != nil {
		sort.Sort(incoming)
	}

	return incoming.bytesArray
}

// SetTimestampFunc registers a timestamp callback that will be used to
// reorder the perf events chronologically.
//
// If not set, the order of events sent through receiverChan is not guaranteed.
//
// Typically, the ebpf program will use bpf_ktime_get_ns() to get a timestamp
// and store it in the perf event. The perf event struct is opaque to this
// package, hence the need for a callback.
func (pm *PerfMap) SetTimestampFunc(timestamp func(*[]byte) uint64) {
	pm.timestamp = timestamp
}

func (pm *PerfMap) PollStart() {
	incoming := OrderedBytesArray{timestamp: pm.timestamp}

	m, ok := pm.program.maps[pm.name]
	if !ok {
		// should not happen or only when pm.program is
		// suddenly changed
		panic(fmt.Sprintf("cannot find map %q", pm.name))
	}

	go func() {
		cpuCount := len(m.pmuFDs)
		pageSize := os.Getpagesize()
		state := C.struct_read_state{}

		defer func() {
			close(pm.receiverChan)
			if pm.lostChan != nil {
				close(pm.lostChan)
			}
		}()

		for {
			select {
			case <-pm.pollStop:
				break
			default:
				perfEventPoll(m.pmuFDs)
			}

		harvestLoop:
			for {
				select {
				case <-pm.pollStop:
					return
				default:
				}

				var harvestCount C.int
				beforeHarvest := NowNanoseconds()
				for cpu := 0; cpu < cpuCount; cpu++ {
				ringBufferLoop:
					for {
						var sample *PerfEventSample
						var lost *PerfEventLost

						ok := C.perf_event_read(C.int(pm.pageCount), C.int(pageSize),
							unsafe.Pointer(&state), unsafe.Pointer(m.headers[cpu]),
							unsafe.Pointer(&sample), unsafe.Pointer(&lost))

						switch ok {
						case 0:
							break ringBufferLoop // nothing to read
						case C.PERF_RECORD_SAMPLE:
							size := sample.Size - 4
							b := C.GoBytes(unsafe.Pointer(&sample.data), C.int(size))
							incoming.bytesArray = append(incoming.bytesArray, b)
							harvestCount++
							if pm.timestamp == nil {
								continue ringBufferLoop
							}
							if incoming.timestamp(&b) > beforeHarvest {
								// see comment below
								break ringBufferLoop
							}
						case C.PERF_RECORD_LOST:
							if pm.lostChan != nil {
								select {
								case pm.lostChan <- lost.Lost:
								case <-pm.pollStop:
									return
								}
							}
						default:
							// ignore unknown events
						}
					}
				}

				if incoming.timestamp != nil {
					sort.Sort(incoming)
				}
				for incoming.Len() > 0 {
					if incoming.timestamp != nil && incoming.timestamp(&incoming.bytesArray[0]) > beforeHarvest {
						// This record has been sent after the beginning of the harvest. Stop
						// processing here to keep the order. "incoming" is sorted, so the next
						// elements also must not be processed now.
						break harvestLoop
					}
					select {
					case pm.receiverChan <- incoming.bytesArray[0]:
					case <-pm.pollStop:
						return
					}
					// remove first element
					incoming.bytesArray = incoming.bytesArray[1:]
				}
				if harvestCount == 0 && len(incoming.bytesArray) == 0 {
					break harvestLoop
				}
			}
		}
	}()
}

// PollStop stops the goroutine that polls the perf event map.
// Callers must not close receiverChan or lostChan: they will be automatically
// closed on the sender side.
func (pm *PerfMap) PollStop() {
	close(pm.pollStop)
}

func perfEventPoll(fds []C.int) error {
	var pfds []C.struct_pollfd

	for i, _ := range fds {
		var pfd C.struct_pollfd

		pfd.fd = fds[i]
		pfd.events = C.POLLIN

		pfds = append(pfds, pfd)
	}
	_, err := C.poll(&pfds[0], C.nfds_t(len(fds)), 500)
	if err != nil {
		return fmt.Errorf("error polling: %v", err.(syscall.Errno))
	}

	return nil
}

// Assume the timestamp is at the beginning of the user struct
type OrderedBytesArray struct {
	bytesArray [][]byte
	timestamp  func(*[]byte) uint64
}

func (a OrderedBytesArray) Len() int {
	return len(a.bytesArray)
}

func (a OrderedBytesArray) Swap(i, j int) {
	a.bytesArray[i], a.bytesArray[j] = a.bytesArray[j], a.bytesArray[i]
}

func (a OrderedBytesArray) Less(i, j int) bool {
	return a.timestamp(&a.bytesArray[i]) < a.timestamp(&a.bytesArray[j])
}

// Matching 'struct perf_event_header in <linux/perf_event.h>
type PerfEventHeader struct {
	Type      uint32
	Misc      uint16
	TotalSize uint16
}

// Matching 'struct perf_event_lost in kernel sources
type PerfEventLost struct {
	PerfEventHeader
	Id   uint64
	Lost uint64
}

// NowNanoseconds returns a time that can be compared to bpf_ktime_get_ns()
func NowNanoseconds() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	sec, nsec := ts.Unix()
	return 1000*1000*1000*uint64(sec) + uint64(nsec)
}
