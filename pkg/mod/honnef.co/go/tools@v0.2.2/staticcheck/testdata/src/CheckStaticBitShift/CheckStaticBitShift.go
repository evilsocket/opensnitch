package pkg

// Partially copied from go vet's test suite.

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-THIRD-PARTY file.

type Number int8

func fn() {
	var n8 Number
	n8 <<= 8 // want `will always clear it`

	var i8 int8
	_ = i8 << 7
	_ = (i8 + 1) << 8 // want `will always clear it`
	_ = i8 << (7 + 1) // want `will always clear it`
	_ = i8 >> 8       // want `will always clear it`
	i8 <<= 8          // want `will always clear it`
	i8 >>= 8          // want `will always clear it`
	i8 <<= 12         // want `will always clear it`

	var i16 int16
	_ = i16 << 15
	_ = i16 << 16 // want `will always clear it`
	_ = i16 >> 16 // want `will always clear it`
	i16 <<= 16    // want `will always clear it`
	i16 >>= 16    // want `will always clear it`
	i16 <<= 18    // want `will always clear it`

	var i32 int32
	_ = i32 << 31
	_ = i32 << 32 // want `will always clear it`
	_ = i32 >> 32 // want `will always clear it`
	i32 <<= 32    // want `will always clear it`
	i32 >>= 32    // want `will always clear it`
	i32 <<= 40    // want `will always clear it`

	var i64 int64
	_ = i64 << 63
	_ = i64 << 64 // want `will always clear it`
	_ = i64 >> 64 // want `will always clear it`
	i64 <<= 64    // want `will always clear it`
	i64 >>= 64    // want `will always clear it`
	i64 <<= 70    // want `will always clear it`

	var u8 uint8
	_ = u8 << 7
	_ = u8 << 8 // want `will always clear it`
	_ = u8 >> 8 // want `will always clear it`
	u8 <<= 8    // want `will always clear it`
	u8 >>= 8    // want `will always clear it`
	u8 <<= 12   // want `will always clear it`

	var u16 uint16
	_ = u16 << 15
	_ = u16 << 16 // want `will always clear it`
	_ = u16 >> 16 // want `will always clear it`
	u16 <<= 16    // want `will always clear it`
	u16 >>= 16    // want `will always clear it`
	u16 <<= 18    // want `will always clear it`

	var u32 uint32
	_ = u32 << 31
	_ = u32 << 32 // want `will always clear it`
	_ = u32 >> 32 // want `will always clear it`
	u32 <<= 32    // want `will always clear it`
	u32 >>= 32    // want `will always clear it`
	u32 <<= 40    // want `will always clear it`

	var u64 uint64
	_ = u64 << 63
	_ = u64 << 64 // want `will always clear it`
	_ = u64 >> 64 // want `will always clear it`
	u64 <<= 64    // want `will always clear it`
	u64 >>= 64    // want `will always clear it`
	u64 <<= 70    // want `will always clear it`
	_ = u64 << u64
}

func fn1() {
	var ui uint
	_ = ui << 64
	_ = ui >> 64
	ui <<= 64
	ui >>= 64

	var uptr uintptr
	_ = uptr << 64
	_ = uptr >> 64
	uptr <<= 64
	uptr >>= 64

	var i int
	_ = i << 64
	_ = i >> 64
	i <<= 64
	i >>= 64
}
