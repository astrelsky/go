// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build prospero

package unix

import "syscall"

func PosixFallocate(fd int, off int64, size int64) error {
	// unsupported
	return syscall.EINVAL
}
