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
	"syscall"
	"unsafe"
)

/*
#include <linux/bpf.h>
#include <linux/unistd.h>

extern __u64 ptr_to_u64(void *);

// from https://github.com/cilium/cilium/blob/master/pkg/bpf/bpf.go
// Apache License, Version 2.0

static void create_bpf_update_elem(int fd, void *key, void *value,
			    unsigned long long flags, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
	ptr_bpf_attr->map_fd = fd;
	ptr_bpf_attr->key = ptr_to_u64(key);
	ptr_bpf_attr->value = ptr_to_u64(value);
	ptr_bpf_attr->flags = flags;
}

static void create_bpf_lookup_elem(int fd, void *key, void *value, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
	ptr_bpf_attr->map_fd = fd;
	ptr_bpf_attr->key = ptr_to_u64(key);
	ptr_bpf_attr->value = ptr_to_u64(value);
}

static int next_bpf_elem(int fd, void *key, void *next_key, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
	ptr_bpf_attr->map_fd = fd;
	ptr_bpf_attr->key = ptr_to_u64(key);
	ptr_bpf_attr->next_key = ptr_to_u64(next_key);
}
*/
import "C"

// UpdateElement stores value in key in the map stored in mp.
// The flags can have the following values (if you include "uapi/linux/bpf.h"):
// C.BPF_ANY to create new element or update existing;
// C.BPF_NOEXIST to create new element if it didn't exist;
// C.BPF_EXIST to update existing element.
func (b *Module) UpdateElement(mp *Map, key, value unsafe.Pointer, flags uint64) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_update_elem(
		C.int(mp.m.fd),
		key,
		value,
		C.ulonglong(flags),
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("unable to update element: %s", err)
	}

	return nil
}

// LookupElement looks up the given key in the the map stored in mp.
// The value is stored in the value unsafe.Pointer.
func (b *Module) LookupElement(mp *Map, key, value unsafe.Pointer) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_lookup_elem(
		C.int(mp.m.fd),
		key,
		value,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("unable to lookup element: %s", err)
	}

	return nil
}

// LookupAndDeleteElement picks up and delete the element in the the map stored in mp.
// The value is stored in the value unsafe.Pointer.
func (b *Module) LookupAndDeleteElement(mp *Map, value unsafe.Pointer) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_lookup_elem(
		C.int(mp.m.fd),
		unsafe.Pointer(nil),
		value,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_LOOKUP_AND_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("unable to lookup and delete element: %s", err)
	}

	return nil
}

// DeleteElement deletes the given key in the the map stored in mp.
// The key is stored in the key unsafe.Pointer.
func (b *Module) DeleteElement(mp *Map, key unsafe.Pointer) error {
	uba := C.union_bpf_attr{}
	value := unsafe.Pointer(nil)
	C.create_bpf_lookup_elem(
		C.int(mp.m.fd),
		key,
		value,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("unable to delete element: %s", err)
	}

	return nil
}

// LookupNextElement looks up the next element in mp using the given key.
// The next key and the value are stored in the nextKey and value parameter.
// Returns false at the end of the mp.
func (b *Module) LookupNextElement(mp *Map, key, nextKey, value unsafe.Pointer) (bool, error) {
	uba := C.union_bpf_attr{}
	C.next_bpf_elem(
		C.int(mp.m.fd),
		key,
		nextKey,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)
	if err == syscall.ENOENT {
		return false, nil
	}
	if err != 0 {
		return false, fmt.Errorf("unable to find next element: %s", err)
	}
	if ret != 0 {
		return false, nil
	}

	if err := b.LookupElement(mp, nextKey, value); err != nil {
		return false, err
	}
	return true, nil
}
