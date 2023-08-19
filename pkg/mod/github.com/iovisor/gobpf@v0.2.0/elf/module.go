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
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

/*
#cgo CFLAGS: -I${SRCDIR}/include/uapi -I${SRCDIR}/include

#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

static int perf_event_open_tracepoint(int tracepoint_id, int pid, int cpu,
                           int group_fd, unsigned long flags)
{
	struct perf_event_attr attr = {0,};
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = tracepoint_id;

	return syscall(__NR_perf_event_open, &attr, pid, cpu,
                      group_fd, flags);
}

int bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.target_fd	   = target_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type   = type;

	return syscall(__NR_bpf, BPF_PROG_ATTACH, &attr, sizeof(attr));
}

int bpf_prog_detach(int prog_fd, int target_fd, enum bpf_attach_type type)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.target_fd	   = target_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type   = type;

	return syscall(__NR_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));
}

int bpf_attach_socket(int sock, int fd)
{
	return setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd));
}

int bpf_detach_socket(int sock, int fd)
{
	return setsockopt(sock, SOL_SOCKET, SO_DETACH_BPF, &fd, sizeof(fd));
}

int bpf_attach_xdp(const char *dev_name, int progfd, uint32_t flags)
{
  	int ifindex = if_nametoindex(dev_name);
  	char err_buf[256];
  	int ret = -1;

  	if (ifindex == 0) {
    		fprintf(stderr, "bpf: Resolving device name to index: %s\n", strerror(errno));
    		return -1;
  	}

  	ret = bpf_set_link_xdp_fd(ifindex, progfd, flags);
  	if (ret) {
    		fprintf(stderr, "bpf: Attaching prog to %s: %s", dev_name, err_buf);
    		return -1;
  	}

  	return 0;
}
*/
import "C"

type Module struct {
	fileName   string
	fileReader io.ReaderAt
	file       *elf.File

	log                []byte
	maps               map[string]*Map
	probes             map[string]*Kprobe
	uprobes            map[string]*Uprobe
	cgroupPrograms     map[string]*CgroupProgram
	socketFilters      map[string]*SocketFilter
	tracepointPrograms map[string]*TracepointProgram
	schedPrograms      map[string]*SchedProgram
	xdpPrograms        map[string]*XDPProgram

	compatProbe bool // try to be automatically convert function names depending on kernel versions (SyS_ and __x64_sys_)
}

// Kprobe represents a kprobe or kretprobe and has to be declared
// in the C file,
type Kprobe struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
	efd   int
}

type Uprobe struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
	efds  map[string]int
}

type AttachType int

const (
	IngressType AttachType = iota
	EgressType
	SockCreateType
)

const defaultLogSize uint32 = 524288

// CgroupProgram represents a cgroup skb/sock program
type CgroupProgram struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
}

// SocketFilter represents a socket filter
type SocketFilter struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
}

// TracepointProgram represents a tracepoint program
type TracepointProgram struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
	efd   int
}

// SchedProgram represents a traffic classifier program
type SchedProgram struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
}

// XDPProgram represents a XDP hook program
type XDPProgram struct {
	Name  string
	insns *C.struct_bpf_insn
	fd    int
}

func newModule(logSize uint32) *Module {
	return &Module{
		probes:             make(map[string]*Kprobe),
		uprobes:            make(map[string]*Uprobe),
		cgroupPrograms:     make(map[string]*CgroupProgram),
		socketFilters:      make(map[string]*SocketFilter),
		tracepointPrograms: make(map[string]*TracepointProgram),
		schedPrograms:      make(map[string]*SchedProgram),
		xdpPrograms:        make(map[string]*XDPProgram),
		log:                make([]byte, logSize),
	}
}

func NewModuleWithLog(fileName string, logSize uint32) *Module {

	module := newModule(logSize)
	module.fileName = fileName
	return module
}

func NewModuleFromReaderWithLog(fileReader io.ReaderAt, logSize uint32) *Module {
	module := newModule(logSize)
	module.fileReader = fileReader
	return module
}

func NewModule(fileName string) *Module {

	module := newModule(defaultLogSize)
	module.fileName = fileName
	return module
}

func NewModuleFromReader(fileReader io.ReaderAt) *Module {
	module := newModule(defaultLogSize)
	module.fileReader = fileReader
	return module
}

var kprobeIDNotExist error = errors.New("kprobe id file doesn't exist")

func writeKprobeEvent(probeType, eventName, funcName, maxactiveStr string) (int, error) {
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, fmt.Errorf("cannot open kprobe_events: %v", err)
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxactiveStr, eventName, funcName)
	if _, err = f.WriteString(cmd); err != nil {
		return -1, fmt.Errorf("cannot write %q to kprobe_events: %v", cmd, err)
	}

	kprobeIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	kprobeIdBytes, err := ioutil.ReadFile(kprobeIdFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, kprobeIDNotExist
		}
		return -1, fmt.Errorf("cannot read kprobe id: %v", err)
	}

	kprobeId, err := strconv.Atoi(strings.TrimSpace(string(kprobeIdBytes)))
	if err != nil {
		return -1, fmt.Errorf("invalid kprobe id: %v", err)
	}

	return kprobeId, nil
}

func writeUprobeEvent(probeType, eventName, path string, offset uint64) (int, error) {
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, fmt.Errorf("cannot open uprobe_events: %v", err)
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s:%s %s:%#x\n", probeType, eventName, path, offset)

	if _, err = f.WriteString(cmd); err != nil {
		return -1, fmt.Errorf("cannot write %q to uprobe_events: %v", cmd, err)
	}

	uprobeIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/uprobes/%s/id", eventName)
	uprobeIdBytes, err := ioutil.ReadFile(uprobeIdFile)
	if err != nil {
		return -1, fmt.Errorf("cannot read uprobe id: %v", err)
	}

	uprobeId, err := strconv.Atoi(strings.TrimSpace(string(uprobeIdBytes)))
	if err != nil {
		return -1, fmt.Errorf("invalid uprobe id: %v", err)
	}

	return uprobeId, nil
}

func perfEventOpenTracepoint(id int, progFd int) (int, error) {
	efd, err := C.perf_event_open_tracepoint(C.int(id), -1 /* pid */, 0 /* cpu */, -1 /* group_fd */, C.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 {
		return -1, fmt.Errorf("perf_event_open error: %v", err)
	}

	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(efd), C.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		return -1, fmt.Errorf("error enabling perf event: %v", err)
	}

	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(efd), C.PERF_EVENT_IOC_SET_BPF, uintptr(progFd)); err != 0 {
		return -1, fmt.Errorf("error attaching bpf program to perf event: %v", err)
	}
	return int(efd), nil
}

// Log gives users access to the log buffer with verifier messages
func (b *Module) Log() []byte {
	return b.log
}

// EnableOptionCompatProbe will attempt to automatically convert function
// names in kprobe and kretprobe to maintain compatibility between kernel
// versions.
// See: https://github.com/iovisor/gobpf/issues/146
func (b *Module) EnableOptionCompatProbe() {
	b.compatProbe = true
}

// EnableKprobe enables a kprobe/kretprobe identified by secName.
// For kretprobes, you can configure the maximum number of instances
// of the function that can be probed simultaneously with maxactive.
// If maxactive is 0 it will be set to the default value: if CONFIG_PREEMPT is
// enabled, this is max(10, 2*NR_CPUS); otherwise, it is NR_CPUS.
// For kprobes, maxactive is ignored.
func (b *Module) EnableKprobe(secName string, maxactive int) error {
	var probeType, funcName string
	isKretprobe := strings.HasPrefix(secName, "kretprobe/")
	probe, ok := b.probes[secName]
	if !ok {
		return fmt.Errorf("no such kprobe %q", secName)
	}
	progFd := probe.fd
	var maxactiveStr string
	if isKretprobe {
		probeType = "r"
		funcName = strings.TrimPrefix(secName, "kretprobe/")
		if maxactive > 0 {
			maxactiveStr = fmt.Sprintf("%d", maxactive)
		}
	} else {
		probeType = "p"
		funcName = strings.TrimPrefix(secName, "kprobe/")
	}
	eventName := probeType + funcName

	kprobeId, err := writeKprobeEvent(probeType, eventName, funcName, maxactiveStr)
	// fallback without maxactive
	if err == kprobeIDNotExist {
		kprobeId, err = writeKprobeEvent(probeType, eventName, funcName, "")
	}
	if err != nil {
		return err
	}

	probe.efd, err = perfEventOpenTracepoint(kprobeId, progFd)
	return err
}

func writeTracepointEvent(category, name string) (int, error) {
	tracepointIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", category, name)
	tracepointIdBytes, err := ioutil.ReadFile(tracepointIdFile)
	if err != nil {
		return -1, fmt.Errorf("cannot read tracepoint id %q: %v", tracepointIdFile, err)
	}

	tracepointId, err := strconv.Atoi(strings.TrimSpace(string(tracepointIdBytes)))
	if err != nil {
		return -1, fmt.Errorf("invalid tracepoint id: %v\n", err)
	}

	return tracepointId, nil
}

func (b *Module) EnableTracepoint(secName string) error {
	prog, ok := b.tracepointPrograms[secName]
	if !ok {
		return fmt.Errorf("no such tracepoint program %q", secName)
	}
	progFd := prog.fd

	tracepointGroup := strings.SplitN(secName, "/", 3)
	if len(tracepointGroup) != 3 {
		return fmt.Errorf("invalid section name %q, expected tracepoint/category/name", secName)
	}
	category := tracepointGroup[1]
	name := tracepointGroup[2]

	tracepointId, err := writeTracepointEvent(category, name)
	if err != nil {
		return err
	}

	prog.efd, err = perfEventOpenTracepoint(tracepointId, progFd)
	return err
}

// IterKprobes returns a channel that emits the kprobes that included in the
// module.
func (b *Module) IterKprobes() <-chan *Kprobe {
	ch := make(chan *Kprobe)
	go func() {
		for name := range b.probes {
			ch <- b.probes[name]
		}
		close(ch)
	}()
	return ch
}

// EnableKprobes enables all kprobes/kretprobes included in the module. The
// value in maxactive will be applied to all the kretprobes.
func (b *Module) EnableKprobes(maxactive int) error {
	var err error
	for _, kprobe := range b.probes {
		err = b.EnableKprobe(kprobe.Name, maxactive)
		if err != nil {
			return err
		}
	}
	return nil
}

// IterUprobes returns a channel that emits the uprobes included in the module.
func (b *Module) IterUprobes() <-chan *Uprobe {
	ch := make(chan *Uprobe)
	go func() {
		for name := range b.uprobes {
			ch <- b.uprobes[name]
		}
		close(ch)
	}()
	return ch
}

func (b *Module) IterCgroupProgram() <-chan *CgroupProgram {
	ch := make(chan *CgroupProgram)
	go func() {
		for name := range b.cgroupPrograms {
			ch <- b.cgroupPrograms[name]
		}
		close(ch)
	}()
	return ch
}

func (b *Module) IterTracepointProgram() <-chan *TracepointProgram {
	ch := make(chan *TracepointProgram)
	go func() {
		for name := range b.tracepointPrograms {
			ch <- b.tracepointPrograms[name]
		}
		close(ch)
	}()
	return ch
}

func (b *Module) IterXDPProgram() <-chan *XDPProgram {
	ch := make(chan *XDPProgram)
	go func() {
		for name := range b.xdpPrograms {
			ch <- b.xdpPrograms[name]
		}
		close(ch)
	}()
	return ch
}

func (b *Module) CgroupProgram(name string) *CgroupProgram {
	return b.cgroupPrograms[name]
}

func (p *CgroupProgram) Fd() int {
	return p.fd
}

func (tp *TracepointProgram) Fd() int {
	return tp.fd
}

var safeEventRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

func safeEventName(event string) string {
	return safeEventRegexp.ReplaceAllString(event, "_")
}

// AttachUprobe attaches the uprobe's BPF script to the program or library
// at the given path and offset.
func AttachUprobe(uprobe *Uprobe, path string, offset uint64) error {
	var probeType string
	if strings.HasPrefix(uprobe.Name, "uretprobe/") {
		probeType = "r"
	} else {
		probeType = "p"
	}
	eventName := fmt.Sprintf("%s__%s_%x_gobpf_%d",
		probeType, safeEventName(path), offset, os.Getpid())

	if _, ok := uprobe.efds[eventName]; ok {
		return errors.New("uprobe already attached")
	}

	uprobeID, err := writeUprobeEvent(probeType, eventName, path, offset)
	if err != nil {
		return err
	}

	efd, err := perfEventOpenTracepoint(uprobeID, uprobe.fd)
	if err != nil {
		return err
	}

	uprobe.efds[eventName] = efd

	return nil
}

func (b *Module) AttachXDP(devName string, secName string) error {
	xdp, ok := b.xdpPrograms[secName]
	if !ok {
		return fmt.Errorf("no such XDP hook %q", secName)
	}
	if err := attachXDP(devName, xdp.fd, 0, true); err != nil {
		return err
	}
	return nil
}

// AttachXDPWithFlags attaches an xdp section to a device with flags.
func (b *Module) AttachXDPWithFlags(devName string, secName string, flags uint32) error {
	xdp, ok := b.xdpPrograms[secName]
	if !ok {
		return fmt.Errorf("no such XDP hook %q", secName)
	}
	return attachXDP(devName, xdp.fd, flags, true)
}

func (b *Module) RemoveXDP(devName string) error {
	if err := attachXDP(devName, -1, 0, false); err != nil {
		return err
	}
	return nil
}

func attachXDP(devName string, fd int, flags uint32, attach bool) error {
	devNameCS := C.CString(devName)
	res, err := C.bpf_attach_xdp(devNameCS, C.int(fd), C.uint32_t(flags))
	defer C.free(unsafe.Pointer(devNameCS))

	if res != 0 || err != nil {
		return fmt.Errorf(xdpFormat(attach), devName, err)
	}
	return nil
}

func xdpFormat(attach bool) string {
	if attach {
		return "failed to attach BPF xdp to device %s: %v"
	}
	return "failed to remove BPF xdp from device %s: %v"
}

func AttachCgroupProgram(cgroupProg *CgroupProgram, cgroupPath string, attachType AttachType) error {
	return AttachCgroupProgramFromFd(cgroupProg.fd, cgroupPath, attachType)
}

func AttachCgroupProgramFromFd(progFd int, cgroupPath string, attachType AttachType) error {
	f, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("error opening cgroup %q: %v", cgroupPath, err)
	}
	defer f.Close()

	ret, err := C.bpf_prog_attach(C.int(progFd), C.int(f.Fd()), uint32(attachType))
	if ret < 0 {
		return fmt.Errorf("failed to attach prog to cgroup %q: %v", cgroupPath, err)
	}
	return nil
}

func DetachCgroupProgram(cgroupProg *CgroupProgram, cgroupPath string, attachType AttachType) error {
	f, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("error opening cgroup %q: %v", cgroupPath, err)
	}
	defer f.Close()

	progFd := C.int(cgroupProg.fd)
	cgroupFd := C.int(f.Fd())
	ret, err := C.bpf_prog_detach(progFd, cgroupFd, uint32(attachType))
	if ret < 0 {
		return fmt.Errorf("failed to detach prog from cgroup %q: %v", cgroupPath, err)
	}

	return nil
}

func (b *Module) IterSocketFilter() <-chan *SocketFilter {
	ch := make(chan *SocketFilter)
	go func() {
		for name := range b.socketFilters {
			ch <- b.socketFilters[name]
		}
		close(ch)
	}()
	return ch
}

func (b *Module) SocketFilter(name string) *SocketFilter {
	return b.socketFilters[name]
}

func AttachSocketFilter(socketFilter *SocketFilter, sockFd int) error {
	ret, err := C.bpf_attach_socket(C.int(sockFd), C.int(socketFilter.fd))
	if ret != 0 {
		return fmt.Errorf("error attaching BPF socket filter: %v", err)
	}

	return nil
}

func (sf *SocketFilter) Fd() int {
	return sf.fd
}

func DetachSocketFilter(socketFilter *SocketFilter, sockFd int) error {
	ret, err := C.bpf_detach_socket(C.int(sockFd), C.int(socketFilter.fd))
	if ret != 0 {
		return fmt.Errorf("error detaching BPF socket filter: %v", err)
	}

	return nil
}

func (b *Module) Kprobe(name string) *Kprobe {
	return b.probes[name]
}

func (kp *Kprobe) Fd() int {
	return kp.fd
}

func disableKprobe(eventName string) error {
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open kprobe_events: %v", err)
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		pathErr, ok := err.(*os.PathError)
		if ok && pathErr.Err == syscall.ENOENT {
			// This can happen when for example two modules
			// use the same elf object and both call `Close()`.
			// The second will encounter the error as the
			// probe already has been cleared by the first.
			return nil
		} else {
			return fmt.Errorf("cannot write %q to kprobe_events: %v", cmd, err)
		}
	}
	return nil
}

func disableUprobe(eventName string) error {
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot open uprobe_events: %v", err)
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		return fmt.Errorf("cannot write %q to uprobe_events: %v", cmd, err)
	}
	return nil
}

func (b *Module) Uprobe(name string) *Uprobe {
	return b.uprobes[name]
}

func (up *Uprobe) Fd() int {
	return up.fd
}

// IterSchedProgram returns a channel that emits the sched programs included in the
// module.
func (b *Module) IterSchedProgram() <-chan *SchedProgram {
	ch := make(chan *SchedProgram)
	go func() {
		for name := range b.schedPrograms {
			ch <- b.schedPrograms[name]
		}
		close(ch)
	}()
	return ch
}

func (b *Module) SchedProgram(name string) *SchedProgram {
	return b.schedPrograms[name]
}

func (sp *SchedProgram) Fd() int {
	return sp.fd
}

func (b *Module) XDPProgram(name string) *XDPProgram {
	return b.xdpPrograms[name]
}

func (xdpp *XDPProgram) Fd() int {
	return xdpp.fd
}

func (b *Module) closeProbes() error {
	var funcName string
	for _, probe := range b.probes {
		if probe.efd != -1 {
			if err := syscall.Close(probe.efd); err != nil {
				return fmt.Errorf("error closing perf event fd: %v", err)
			}
			probe.efd = -1
		}
		if err := syscall.Close(probe.fd); err != nil {
			return fmt.Errorf("error closing probe fd: %v", err)
		}
		name := probe.Name
		isKretprobe := strings.HasPrefix(name, "kretprobe/")
		var err error
		if isKretprobe {
			funcName = strings.TrimPrefix(name, "kretprobe/")
			err = disableKprobe("r" + funcName)
		} else {
			funcName = strings.TrimPrefix(name, "kprobe/")
			err = disableKprobe("p" + funcName)
		}
		if err != nil {
			return fmt.Errorf("error clearing probe: %v", err)
		}
	}
	return nil
}

func (b *Module) closeUprobes() error {
	for _, probe := range b.uprobes {
		for eventName, efd := range probe.efds {
			if err := syscall.Close(efd); err != nil {
				return fmt.Errorf("error closing uprobe's event fd: %v", err)
			}
			if err := disableUprobe(eventName); err != nil {
				return fmt.Errorf("error clearing probe: %v", err)
			}
		}

		if err := syscall.Close(probe.fd); err != nil {
			return fmt.Errorf("error closing uprobe fd: %v", err)
		}
	}
	return nil
}

func (b *Module) closeTracepointPrograms() error {
	for _, program := range b.tracepointPrograms {
		if program.efd != -1 {
			if err := syscall.Close(program.efd); err != nil {
				return fmt.Errorf("error closing perf event fd: %v", err)
			}
			program.efd = -1
		}
		if err := syscall.Close(program.fd); err != nil {
			return fmt.Errorf("error closing tracepoint program fd: %v", err)
		}
	}
	return nil
}

func (b *Module) closeCgroupPrograms() error {
	for _, program := range b.cgroupPrograms {
		if err := syscall.Close(program.fd); err != nil {
			return fmt.Errorf("error closing cgroup program fd: %v", err)
		}
	}
	return nil
}

func (b *Module) closeSocketFilters() error {
	for _, filter := range b.socketFilters {
		if err := syscall.Close(filter.fd); err != nil {
			return fmt.Errorf("error closing socket filter fd: %v", err)
		}
	}
	return nil
}

func (b *Module) closeXDPPrograms() error {
	for _, xdp := range b.xdpPrograms {
		if err := syscall.Close(xdp.fd); err != nil {
			return fmt.Errorf("error closing XDP program fd: %v", err)
		}
	}
	return nil
}

func unpinMap(m *Map, pinPath string) error {
	mapPath, err := getMapPath(&m.m.def, m.Name, pinPath)
	if err != nil {
		return err
	}
	return syscall.Unlink(mapPath)
}

func (b *Module) closeMaps(options map[string]CloseOptions) error {
	for _, m := range b.maps {
		doUnpin := options[fmt.Sprintf("maps/%s", m.Name)].Unpin
		if doUnpin {
			mapDef := m.m.def
			var pinPath string
			if mapDef.pinning == PIN_CUSTOM_NS {
				closeOption, ok := options[fmt.Sprintf("maps/%s", m.Name)]
				if !ok {
					return fmt.Errorf("close option for maps/%s must have PinPath set", m.Name)
				}
				pinPath = closeOption.PinPath
			} else if mapDef.pinning == PIN_GLOBAL_NS {
				// mapDef.namespace is used for PIN_GLOBAL_NS maps
				pinPath = ""
			} else if mapDef.pinning == PIN_OBJECT_NS {
				return fmt.Errorf("unpinning with PIN_OBJECT_NS is to be implemented")
			}
			if err := unpinMap(m, pinPath); err != nil {
				return fmt.Errorf("error unpinning map %q: %v", m.Name, err)
			}
		}

		// unmap
		for _, base := range m.bases {
			err := syscall.Munmap(base)
			if err != nil {
				return fmt.Errorf("unmap error: %v", err)
			}
		}

		for _, fd := range m.pmuFDs {
			// disable
			_, _, err2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), C.PERF_EVENT_IOC_DISABLE, 0)
			if err2 != 0 {
				return fmt.Errorf("error disabling perf event: %v", err2)
			}

			// close
			if err := syscall.Close(int(fd)); err != nil {
				return fmt.Errorf("error closing perf event fd: %v", err)
			}
		}
		if err := syscall.Close(int(m.m.fd)); err != nil {
			return fmt.Errorf("error closing map fd: %v", err)
		}
		C.free(unsafe.Pointer(m.m))
	}
	return nil
}

// CloseOptions can be used for custom `Close` parameters
type CloseOptions struct {
	// Set Unpin to true to close pinned maps as well
	Unpin   bool
	PinPath string
}

// Close takes care of terminating all underlying BPF programs and structures.
// That is:
//
// * Closing map file descriptors and unpinning them where applicable
// * Detaching BPF programs from kprobes and closing their file descriptors
// * Closing cgroup-bpf file descriptors
// * Closing socket filter file descriptors
// * Closing XDP file descriptors
//
// It doesn't detach BPF programs from cgroups or sockets because they're
// considered resources the user controls.
// It also doesn't unpin pinned maps. Use CloseExt and set Unpin to do this.
func (b *Module) Close() error {
	return b.CloseExt(nil)
}

// CloseExt takes a map "elf section -> CloseOptions"
func (b *Module) CloseExt(options map[string]CloseOptions) error {
	if err := b.closeMaps(options); err != nil {
		return err
	}
	if err := b.closeProbes(); err != nil {
		return err
	}
	if err := b.closeUprobes(); err != nil {
		return err
	}
	if err := b.closeCgroupPrograms(); err != nil {
		return err
	}
	if err := b.closeTracepointPrograms(); err != nil {
		return err
	}
	if err := b.closeSocketFilters(); err != nil {
		return err
	}
	if err := b.closeXDPPrograms(); err != nil {
		return err
	}
	return nil
}
