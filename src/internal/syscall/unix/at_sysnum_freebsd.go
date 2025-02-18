// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !prospero && freebsd

package unix

import "syscall"

const (
	AT_REMOVEDIR        = 0x800
	AT_SYMLINK_NOFOLLOW = 0x200

	UTIME_OMIT = -0x2

	unlinkatTrap       uintptr = syscall.SYS_UNLINKAT
	openatTrap         uintptr = syscall.SYS_OPENAT
	posixFallocateTrap uintptr = syscall.SYS_POSIX_FALLOCATE
)
