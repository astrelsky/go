// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import (
	"bytes"
	"runtime"
	"strconv"
	"strings"
	"unsafe"
)

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: sec, Nsec: nsec}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: sec, Usec: usec}
}

func SetKevent(k *Kevent_t, fd, mode, flags int) {
	k.Ident = uint64(fd)
	k.Filter = int16(mode)
	k.Flags = uint16(flags)
}

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint32(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint32(length)
}

func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	var writtenOut uint64 = 0
	_, _, e1 := Syscall9(SYS_SENDFILE, uintptr(infd), uintptr(outfd), uintptr(*offset), uintptr(count), 0, uintptr(unsafe.Pointer(&writtenOut)), 0, 0, 0)

	written = int(writtenOut)

	if e1 != 0 {
		err = e1
	}
	return
}

/*
#define MODULE_INFO_NAME_LENGTH 128
#define MODULE_INFO_SANDBOXED_PATH_LENGTH 1024
#define MODULE_INFO_MAX_SECTIONS 4
#define FINGERPRINT_LENGTH 20

// A -1L terminated list of module handles
typedef int64_t *module_handle_list_t;

typedef struct {
	uintptr_t vaddr;
	uint32_t size;
	uint32_t prot;
} module_section_t;

typedef struct {
	char filename[MODULE_INFO_NAME_LENGTH];
	uint64_t handle;
	uint8_t unknown0[32]; // NOLINT(readability-magic-numbers)
	uintptr_t unknown1; // init
	uintptr_t unknown2; // fini
	uintptr_t unknown3; // eh_frame_hdr
	uintptr_t unknown4; // eh_frame_hdr_sz
	uintptr_t unknown5; // eh_frame
	uintptr_t unknown6; // eh_frame_sz
	module_section_t sections[MODULE_INFO_MAX_SECTIONS];
	uint8_t unknown7[1176]; // NOLINT(readability-magic-numbers)
	uint8_t fingerprint[FINGERPRINT_LENGTH];
	uint32_t unknown8;
	char libname[MODULE_INFO_NAME_LENGTH];
	uint32_t unknown9;
	char sandboxed_path[MODULE_INFO_SANDBOXED_PATH_LENGTH];
	uint64_t sdk_version;
} module_info_t;

static_assert(sizeof(module_info_t) == 0xa58, "sizeof(module_info_t) != 0xa58"); // NOLINT(readability-magic-numbers)
*/

type ModuleSection struct {
	vaddr uintptr
	size  uint32
	prot  uint32
}

type ModuleInfo struct {
	filename       [128]byte
	handle         uintptr
	unknown0       [32]byte
	unknown1       uintptr // init
	unknown2       uintptr // fini
	unknown3       uintptr // eh_frame_hdr
	unknown4       uintptr // eh_frame_hdr_sz
	unknown5       uintptr // eh_frame
	unknown6       uintptr // eh_frame_sz
	sections       [4]ModuleSection
	unknown7       [1176]byte
	fingerprint    [20]byte
	unknown8       uint32
	libname        [128]byte
	unknown9       uint32
	sandboxed_path [1024]byte
	sdk_version    uint64
}

func (info *ModuleInfo) FileName() string {
	length := bytes.IndexByte(info.filename[:], 0)
	if length == -1 {
		length = 128
	}
	return string(info.filename[:length])
}

func (info *ModuleInfo) Handle() uintptr {
	return info.handle
}

// int dl_get_list(int pid, int64_t *handles, uint32_t max_handles, uint32_t *num_handles)
func DlGetList(pid int32) (handles []uintptr, err Errno) {
	const MAX_HANDLES = 0x300
	buf := [MAX_HANDLES]uintptr{}
	var length uint32 = 0
	_, _, err = RawSyscall6(SYS_DL_GET_LIST, uintptr(pid), uintptr(unsafe.Pointer(&buf[0])), uintptr(MAX_HANDLES), uintptr(unsafe.Pointer(&length)), 0, 0)
	if err != 0 {
		return
	}
	handles = buf[:length]
	return
}

// static int dl_get_info_2(int pid, uint32_t sandboxed_path, int64_t handle, module_info_t *info)
func DlGetInfo2(pid int32, handle uintptr) (*ModuleInfo, Errno) {
	info := &ModuleInfo{}
	_, _, err := RawSyscall6(SYS_DL_GET_INFO_2, uintptr(pid), 1, handle, uintptr(unsafe.Pointer(info)), 0, 0)
	if err != 0 {
		return nil, err
	}
	return info, 0
}

func _setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := RawSyscall6(SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func Syscall9(num, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err Errno)
func SyscallN(trap uintptr, args ...uintptr) (r1, r2 uintptr, err Errno)

var _master_sock int
var _victim_sock int
var _rw_pipe [2]int
var _pipe_addr uintptr

// Internal kwrite function - not friendly, only for setting up better primitives.
func _kwrite(addr uintptr, data unsafe.Pointer) {
	victim_buf := [3]uintptr{addr, 0, 0}

	_setsockopt(_master_sock, IPPROTO_IPV6, IPV6_PKTINFO, unsafe.Pointer(&victim_buf[0]), 0x14)
	_setsockopt(_victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, data, 0x14)
}

type InvalidKernelAddressError struct {
	addr uintptr
}

func (e *InvalidKernelAddressError) Error() string {
	hex := strconv.FormatUint(uint64(e.addr), 16)
	return "invalid kernel address 0x" + strings.Repeat("0", 8-len(hex)) + hex
}

func _write(fd int, p []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := RawSyscall(SYS_WRITE, uintptr(fd), uintptr(_p0), uintptr(len(p)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func _read(fd int, p []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := RawSyscall(SYS_READ, uintptr(fd), uintptr(_p0), uintptr(len(p)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// Public API function to write kernel data.
func KernelCopyin(kdest uintptr, p []byte) (n int, err error) {
	if int64(kdest) >= 0 {
		panic(InvalidKernelAddressError{kdest})
	}

	// Set pipe flags
	write_buf := [3]uintptr{0, 0x4000000000000000, 0}

	_kwrite(_pipe_addr, unsafe.Pointer(&write_buf[0]))

	// Set pipe data addr
	write_buf = [3]uintptr{kdest, 0, 0}
	_kwrite(_pipe_addr+0x10, unsafe.Pointer(&write_buf[0]))

	// Perform write across pipe
	n, err = _write(_rw_pipe[1], p)
	return
}

// Public API function to read kernel data.
func KernelCopyout(ksrc uintptr, p []byte) (n int, err error) {
	if int64(ksrc) >= 0 {
		panic(InvalidKernelAddressError{ksrc})
	}

	// Set pipe flags
	write_buf := [3]uintptr{0x4000000040000000, 0x4000000000000000, 0}

	println("_kwrite 1")
	_kwrite(_pipe_addr, unsafe.Pointer(&write_buf[0]))

	// Set pipe data addr
	write_buf = [3]uintptr{ksrc, 0, 0}
	println("_kwrite 2")
	_kwrite(_pipe_addr+0x10, unsafe.Pointer(&write_buf[0]))

	// Perform read across pipe
	println("_read ", _rw_pipe[0])
	n, err = _read(_rw_pipe[0], p)
	return
}

// Arguments passed by way of entrypoint arguments.
func init() {
	// master_sock int32, victim_sock int32, rw_pipe [2]int32, pipe_addr uintptr
	rwpair := runtime.GetRWPair()
	rwpipe := runtime.GetRWPipe()
	_master_sock = int(rwpair[0])
	_victim_sock = int(rwpair[1])
	_rw_pipe[0] = int(rwpipe[0])
	_rw_pipe[1] = int(rwpipe[1])
	_pipe_addr = runtime.GetKernelPipeAddress()
}

func GetKernelBase() uintptr {
	return runtime.GetKernelBase()
}
