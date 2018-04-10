package netfilter

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -I/usr/include
#cgo LDFLAGS: -L/usr/lib64/

#include "queue.h"
*/
import "C"

import (
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	AF_INET  = 2
	AF_INET6 = 10

	NF_DROP   Verdict = 0
	NF_ACCEPT Verdict = 1
	NF_STOLEN Verdict = 2
	NF_QUEUE  Verdict = 3
	NF_REPEAT Verdict = 4
	NF_STOP   Verdict = 5

	NF_DEFAULT_PACKET_SIZE uint32 = 0xffff

	ipv4version = 0x40
)

var (
	queueIndex     = make(map[uint32]*chan NFPacket, 0)
	queueIndexLock = sync.RWMutex{}

	gopacketDecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
)

type VerdictContainerC C.verdictContainer

type Queue struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan NFPacket
	idx     uint32
}

//Create and bind to queue specified by queueId
func NewQueue(queueId uint16, maxPacketsInQueue uint32, packetSize uint32) (*Queue, error) {
	var q = Queue{
		idx:     uint32(time.Now().UnixNano()),
		packets: make(chan NFPacket),
	}
	var err error
	var ret C.int

	if q.h, err = C.nfq_open(); err != nil {
		return nil, fmt.Errorf("Error opening Queue handle: %v\n", err)
	} else if ret, err = C.nfq_unbind_pf(q.h, AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error unbinding existing q handler from AF_INET protocol family: %v\n", err)
	} else if ret, err = C.nfq_unbind_pf(q.h, AF_INET6); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error unbinding existing q handler from AF_INET6 protocol family: %v\n", err)
	} else if ret, err := C.nfq_bind_pf(q.h, AF_INET); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error binding to AF_INET protocol family: %v\n", err)
	} else if ret, err := C.nfq_bind_pf(q.h, AF_INET6); err != nil || ret < 0 {
		return nil, fmt.Errorf("Error binding to AF_INET6 protocol family: %v\n", err)
	}

	queueIndexLock.Lock()
	queueIndex[q.idx] = &q.packets
	queueIndexLock.Unlock()

	if q.qh, err = C.CreateQueue(q.h, C.u_int16_t(queueId), C.u_int32_t(q.idx)); err != nil || q.qh == nil {
		C.nfq_close(q.h)
		return nil, fmt.Errorf("Error binding to queue: %v\n", err)
	} else if ret, err = C.nfq_set_queue_maxlen(q.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		C.nfq_destroy_queue(q.qh)
		C.nfq_close(q.h)
		return nil, fmt.Errorf("Unable to set max packets in queue: %v\n", err)
	} else if C.nfq_set_mode(q.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		C.nfq_destroy_queue(q.qh)
		C.nfq_close(q.h)
		return nil, fmt.Errorf("Unable to set packets copy mode: %v\n", err)
	} else if q.fd, err = C.nfq_fd(q.h); err != nil {
		C.nfq_destroy_queue(q.qh)
		C.nfq_close(q.h)
		return nil, fmt.Errorf("Unable to get queue file-descriptor. %v\n", err)
	}

	go q.run()

	return &q, nil
}

//Unbind and close the queue
func (q *Queue) Close() {
	C.nfq_destroy_queue(q.qh)
	C.nfq_close(q.h)
	queueIndexLock.Lock()
	delete(queueIndex, q.idx)
	queueIndexLock.Unlock()
}

//Get the channel for packets
func (q *Queue) Packets() <-chan NFPacket {
	return q.packets
}

func (q *Queue) run() {
	if errno := C.Run(q.h, q.fd); errno != 0 {
		fmt.Fprintf(os.Stderr, "Terminating, unable to receive packet due to errno=%d\n", errno)
	}
}

//export go_callback
func go_callback(queueId C.int, data *C.uchar, length C.int, mark C.uint, idx uint32, vc *VerdictContainerC) {
	(*vc).verdict = C.uint(NF_ACCEPT)
	(*vc).data = nil
	(*vc).mark_set = 0
	(*vc).length = 0

	queueIndexLock.RLock()
	queueChannel, found := queueIndex[idx]
	queueIndexLock.RUnlock()
	if !found {
		fmt.Fprintf(os.Stderr, "Unexpected queue idx %d\n", idx)
		return
	}

	xdata := C.GoBytes(unsafe.Pointer(data), length)

	var packet gopacket.Packet
	if xdata[0]&0xf0 == ipv4version {
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv4, gopacketDecodeOptions)
	} else {
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv6, gopacketDecodeOptions)
	}

	p := NFPacket{
		verdictChannel: make(chan VerdictContainer),
		Mark:           uint32(mark),
		Packet:         packet,
	}

	select {
	case *queueChannel <- p:
		select {
		case v := <-p.verdictChannel:
			if v.Packet == nil {
				(*vc).verdict = C.uint(v.Verdict)
			} else {
				(*vc).verdict = C.uint(v.Verdict)
				(*vc).data = (*C.uchar)(unsafe.Pointer(&v.Packet[0]))
				(*vc).length = C.uint(len(v.Packet))
			}

			if v.Mark != 0 {
				(*vc).mark_set = C.uint(1)
				(*vc).mark = C.uint(v.Mark)
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "Error sending packet to queue channel %d\n", idx)
	}
}
