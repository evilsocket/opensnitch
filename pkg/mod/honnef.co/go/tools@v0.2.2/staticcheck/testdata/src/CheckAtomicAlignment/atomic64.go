// +build amd64 amd64p32 arm64 ppc64 ppc64le mips64 mips64le mips64p32 mips64p32le sparc64

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
	atomic.AddInt64(&v.C, 0)
	atomic.LoadInt64(&v.C)
}
