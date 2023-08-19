// +build !linux

package elf

import (
	"io"
	"unsafe"
)

type Module struct{}
type Kprobe struct{}
type CgroupProgram struct{}
type AttachType struct{}
type CloseOptions struct{}
type SocketFilter struct{}
type TracepointProgram struct{}
type SchedProgram struct{}

func NewModule(fileName string) *Module {
	return nil
}

func NewModuleFromReader(fileReader io.ReaderAt) *Module {
	return nil
}

func (b *Module) EnableKprobe(secName string, maxactive int) error {
	return errNotSupported
}

func (b *Module) IterKprobes() <-chan *Kprobe {
	return nil
}

func (b *Module) EnableKprobes(maxactive int) error {
	return errNotSupported
}

func (b *Module) IterCgroupProgram() <-chan *CgroupProgram {
	return nil
}

func (b *Module) CgroupProgram(name string) *CgroupProgram {
	return nil
}

func (b *Module) Kprobe(name string) *Kprobe {
	return nil
}

func (b *Module) AttachProgram(cgroupProg *CgroupProgram, cgroupPath string, attachType AttachType) error {
	return errNotSupported
}

func (b *Module) Close() error {
	return errNotSupported
}

func (b *Module) CloseExt(options map[string]CloseOptions) error {
	return errNotSupported
}

func (b *Module) DeleteElement(mp *Map, key unsafe.Pointer) error {
	return errNotSupported
}

func (b *Module) EnableTracepoint(secName string) error {
	return errNotSupported
}

func (b *Module) IterMaps() <-chan *Map {
	return nil
}

func (b *Module) IterSocketFilter() <-chan *SocketFilter {
	return nil
}

func (b *Module) IterTracepointProgram() <-chan *TracepointProgram {
	return nil
}

func (b *Module) Log() []byte {
	return nil
}

func (b *Module) LookupElement(mp *Map, key, value unsafe.Pointer) error {
	return errNotSupported
}

func (b *Module) LookupNextElement(mp *Map, key, nextKey, value unsafe.Pointer) (bool, error) {
	return false, errNotSupported
}

func (b *Module) Map(name string) *Map {
	return nil
}

func (b *Module) SchedProgram(name string) *SchedProgram {
	return nil
}

func (b *Module) SocketFilter(name string) *SocketFilter {
	return nil
}

func (b *Module) UpdateElement(mp *Map, key, value unsafe.Pointer, flags uint64) error {
	return errNotSupported
}
