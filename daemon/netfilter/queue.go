package netfilter

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -I/usr/include
#cgo LDFLAGS: -L/usr/lib64/ -ldl

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
	"github.com/evilsocket/opensnitch/daemon/log"
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
	exitChan       = make(chan bool, 1)

	gopacketDecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
)

// VerdictContainerC is the struct that contains the mark, action, length and
// payload of a packet.
// It's defined in queue.h, and filled on go_callback()
type VerdictContainerC C.verdictContainer

// Queue holds the information of a netfilter queue.
// The handles of the connection to the kernel and the created queue.
// A channel where the intercepted packets will be received.
// The ID of the queue.
type Queue struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan Packet
	idx     uint32
}

// NewQueue opens a new netfilter queue to receive packets marked with a mark.
func NewQueue(queueID uint16) (q *Queue, err error) {
	q = &Queue{
		idx:     uint32(time.Now().UnixNano()),
		packets: make(chan Packet),
	}

	if err = q.create(queueID); err != nil {
		return nil, err
	} else if err = q.setup(); err != nil {
		return nil, err
	}

	go q.run(exitChan)

	return q, nil
}

func (q *Queue) create(queueID uint16) (err error) {
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
	} else if q.qh, err = C.CreateQueue(q.h, C.u_int16_t(queueID), C.u_int32_t(q.idx)); err != nil || q.qh == nil {
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
		return fmt.Errorf("Unable to increase netfilter buffer space size")
	}

	return nil
}

func (q *Queue) run(exitCh chan<- bool) {
	if errno := C.Run(q.h, q.fd); errno != 0 {
		fmt.Fprintf(os.Stderr, "Terminating, unable to receive packet due to errno=%d", errno)
	}
	exitChan <- true
}

// Close ensures that nfqueue resources are freed and closed.
// C.stop_reading_packets() stops the reading packets loop, which causes
// go-subroutine run() to exit.
// After exit, listening queue is destroyed and closed.
// If for some reason any of the steps stucks while closing it, we'll exit by timeout.
func (q *Queue) Close() {
	close(q.packets)
	C.stop_reading_packets()
	q.destroy()
	queueIndexLock.Lock()
	delete(queueIndex, q.idx)
	queueIndexLock.Unlock()
}

func (q *Queue) destroy() {
	// we'll try to exit cleanly, but sometimes nfqueue gets stuck
	time.AfterFunc(5*time.Second, func() {
		log.Warning("queue stuck, closing by timeout")
		if q != nil {
			C.close(q.fd)
			q.closeNfq()
		}
		os.Exit(0)
	})
	C.nfq_unbind_pf(q.h, AF_INET)
	C.nfq_unbind_pf(q.h, AF_INET6)
	if q.qh != nil {
		if ret := C.nfq_destroy_queue(q.qh); ret != 0 {
			log.Warning("Queue.destroy(), nfq_destroy_queue() not closed: %d", ret)
		}
	}

	q.closeNfq()
}

func (q *Queue) closeNfq() {
	if q.h != nil {
		if ret := C.nfq_close(q.h); ret != 0 {
			log.Warning("Queue.destroy(), nfq_close() not closed: %d", ret)
		}
	}
}

// Packets return the list of enqueued packets.
func (q *Queue) Packets() <-chan Packet {
	return q.packets
}

// FYI: the export keyword is mandatory to specify that go_callback is defined elsewhere

//export go_callback
func go_callback(queueID C.int, data *C.uchar, length C.int, mark C.uint, idx uint32, vc *VerdictContainerC, uid uint32) {
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

	p := Packet{
		verdictChannel:  make(chan VerdictContainer),
		Mark:            uint32(mark),
		UID:             uid,
		NetworkProtocol: xdata[0] >> 4, // first 4 bits is the version
	}

	var packet gopacket.Packet
	if p.IsIPv4() {
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv4, gopacketDecodeOptions)
	} else {
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv6, gopacketDecodeOptions)
	}

	p.Packet = packet

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
