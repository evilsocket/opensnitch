// +build 386 arm armbe mips mipsle ppc s390 sparc

package pkg

import "sync/atomic"

type T struct {
	A int64
	B int32
	C int64
}

func fn() {
	var v T
	atomic.AddInt64(&v.A, 0)
	atomic.AddInt64(&v.C, 0) // want `address of non 64-bit aligned field C passed to sync/atomic.AddInt64`
	atomic.LoadInt64(&v.C)   // want `address of non 64-bit aligned field C passed to sync/atomic.LoadInt64`
}

func fn2(t *T) {
	addr := &t.C
	if true {
		atomic.LoadUint64(addr) // want `address of non 64-bit`
	} else {
		_ = addr
	}
}
