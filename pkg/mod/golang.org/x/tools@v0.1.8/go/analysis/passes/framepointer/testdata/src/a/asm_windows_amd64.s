// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

TEXT ·z1(SB), 0, $0
	MOVQ	$0, BP // not an error on windows
	RET
