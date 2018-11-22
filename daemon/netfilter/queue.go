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

	NF_DEFAULT_QUEUE_SIZE  uint32 = 4096
	NF_DEFAULT_PACKET_SIZE uint32 = 4096
)

var (
	queueIndex     = make(map[uint32]*chan Packet, 0)
	queueIndexLock = sync.RWMutex{}

	gopacketDecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
)

type VerdictContainerC C.verdictContainer

type Queue struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan Packet
	idx     uint32
}

func NewQueue(queueId uint16) (q *Queue, err error) {
	q = &Queue{
		idx:     uint32(time.Now().UnixNano()),
		packets: make(chan Packet),
	}

	if err = q.create(queueId); err != nil {
		return nil, err
	} else if err = q.setup(); err != nil {
		return nil, err
	}

	go q.run()

	return
}

func (q *Queue) destroy() {
	if q.qh != nil {
		C.nfq_destroy_queue(q.qh)
		q.qh = nil
	}

	if q.h != nil {
		C.nfq_close(q.h)
		q.h = nil
	}
}

func (q *Queue) create(queueId uint16) (err error) {
	var ret C.int

	if q.h, err = C.nfq_open(); err != nil {
		return fmt.Errorf("Error opening Queue handle: %v", err)
	} else if ret, err = C.nfq_unbind_pf(q.h, AF_INET); err != nil || ret < 0 {
		return fmt.Errorf("Error unbinding existing q handler from AF_INET protocol family: %v", err)
	} else if ret, err = C.nfq_unbind_pf(q.h, AF_INET6); err != nil || ret < 0 {
		return fmt.Errorf("Error unbinding existing q handler from AF_INET6 protocol family: %v", err)
	} else if ret, err := C.nfq_bind_pf(q.h, AF_INET); err != nil || ret < 0 {
		return fmt.Errorf("Error binding to AF_INET protocol family: %v", err)
	} else if ret, err := C.nfq_bind_pf(q.h, AF_INET6); err != nil || ret < 0 {
		return fmt.Errorf("Error binding to AF_INET6 protocol family: %v", err)
	} else if q.qh, err = C.CreateQueue(q.h, C.u_int16_t(queueId), C.u_int32_t(q.idx)); err != nil || q.qh == nil {
		q.destroy()
		return fmt.Errorf("Error binding to queue: %v", err)
	}

	queueIndexLock.Lock()
	queueIndex[q.idx] = &q.packets
	queueIndexLock.Unlock()

	return nil
}

func (q *Queue) setup() (err error) {
	var ret C.int

	queueSize := C.u_int32_t(NF_DEFAULT_QUEUE_SIZE)
	bufferSize := C.uint(NF_DEFAULT_PACKET_SIZE)
	totSize := C.uint(NF_DEFAULT_QUEUE_SIZE * NF_DEFAULT_PACKET_SIZE)

	if ret, err = C.nfq_set_queue_maxlen(q.qh, queueSize); err != nil || ret < 0 {
		q.destroy()
		return fmt.Errorf("Unable to set max packets in queue: %v", err)
	} else if C.nfq_set_mode(q.qh, C.u_int8_t(2), bufferSize) < 0 {
		q.destroy()
		return fmt.Errorf("Unable to set packets copy mode: %v", err)
	} else if q.fd, err = C.nfq_fd(q.h); err != nil {
		q.destroy()
		return fmt.Errorf("Unable to get queue file-descriptor. %v", err)
	} else if C.nfnl_rcvbufsiz(C.nfq_nfnlh(q.h), totSize) < 0 {
		q.destroy()
		return fmt.Errorf("Unable to increase netfilter buffer space size.")
	}

	return nil
}

func (q *Queue) Close() {
	q.destroy()
	queueIndexLock.Lock()
	delete(queueIndex, q.idx)
	queueIndexLock.Unlock()
}

func (q *Queue) Packets() <-chan Packet {
	return q.packets
}

func (q *Queue) run() {
	if errno := C.Run(q.h, q.fd); errno != 0 {
		fmt.Fprintf(os.Stderr, "Terminating, unable to receive packet due to errno=%d", errno)
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
	if (xdata[0] >> 4) == 4 { // first 4 bits is the version
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv4, gopacketDecodeOptions)
	} else {
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv6, gopacketDecodeOptions)
	}

	p := Packet{
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
