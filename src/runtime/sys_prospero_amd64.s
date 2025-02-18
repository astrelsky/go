// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// System calls and other sys.stuff for AMD64, FreeBSD
// /usr/src/sys/kern/syscalls.master for syscall numbers.
//

//go:build prospero

#include "go_asm.h"
#include "go_tls.h"
#include "textflag.h"
#include "cgo/abi_amd64.h"

#define CLOCK_REALTIME		0
#define CLOCK_MONOTONIC		4
#define AMD64_SET_FSBASE	129

#define SYS_exit		1
#define SYS_read		3
#define SYS_write		4
#define SYS_open		5
#define SYS_close		6
#define SYS_getpid		20
#define SYS_kill		37
#define SYS_sigaltstack		53
#define SYS_munmap		73
#define SYS_madvise		75
#define SYS_setitimer		83
#define SYS_fcntl		92
#define SYS_sysarch		165
#define SYS___sysctl		202
#define SYS_clock_gettime	232
#define SYS_nanosleep		240
#define SYS_issetugid		253
#define SYS_sched_yield		331
#define SYS_sigprocmask		340
#define SYS_kqueue		362
#define SYS_kevent		363
#define SYS_sigaction		416
#define SYS_thr_exit		431
#define SYS_thr_self		432
#define SYS_thr_kill		433
#define SYS__umtx_op		454
#define SYS_thr_new		455
#define SYS_mmap		477
#define SYS_cpuset_getaffinity	487
#define SYS_pipe2 		687

TEXT runtime·sys_umtx_op(SB),NOSPLIT,$0
	MOVQ addr+0(FP), DI
	MOVL mode+8(FP), SI
	MOVL val+12(FP), DX
	MOVQ uaddr1+16(FP), R10
	MOVQ ut+24(FP), R8
	MOVL $SYS__umtx_op, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	3(PC)
	MOVQ	CX, AX
	NEGQ	AX
	MOVL	AX, ret+32(FP)
	RET


// dummy value used for thread and retval
GLOBL dummy_retval(SB), (NOPTR), $8

TEXT runtime·thr_new<ABIInternal>(SB),NOSPLIT|NOFRAME,$0
	LEAQ	dummy_retval(SB), DI
	MOVQ	CX, SI
	MOVQ	AX, DX
	MOVQ	BX, CX
	MOVQ	runtime·ppthread_create(SB), R12
	CALL	R12
	RET

TEXT runtime·thr_start(SB),NOSPLIT,$0
	MOVQ	DI, R13 // m

	// set up FS to point at m->tls
	LEAQ	m_tls(R13), DI

	CALL	runtime·settls(SB)	// smashes DI

	// set up m, g
	get_tls(CX)
	MOVQ	m_g0(R13), DI
	MOVQ	R13, g_m(DI)
	MOVQ	DI, g(CX)

	CALL	runtime·stackcheck(SB)
	CALL	runtime·mstart(SB)

	MOVQ 0, AX			// crash (not reached)

// Exit the entire program (like C exit)
TEXT runtime·exit(SB),NOSPLIT,$-8
	MOVL	code+0(FP), DI		// arg 1 exit status
	MOVQ	$SYS_getpid, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	MOVQ	AX, DI
	MOVQ	$9, SI
	MOVQ	$SYS_kill, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	UD2
	RET

// func exitThread(wait *atomic.uint32)
TEXT runtime·exitThread(SB),NOSPLIT,$0-8
	MOVQ	wait+0(FP), AX
	// We're done using m.
	MOVL	$0, (AX)
	LEAQ	dummy_retval(SB), DI
	MOVQ	runtime·ppthread_exit(SB), R12
	CALL	R12
	MOVL	$0xf1, 0xf1  // crash
	JMP	0(PC)

TEXT runtime·open(SB),NOSPLIT,$-8
	MOVQ	name+0(FP), DI		// arg 1 pathname
	MOVL	mode+8(FP), SI		// arg 2 flags
	MOVL	perm+12(FP), DX		// arg 3 mode
	MOVQ	$SYS_open, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$-1, AX
	MOVL	AX, ret+16(FP)
	RET

TEXT runtime·closefd(SB),NOSPLIT,$-8
	MOVL	fd+0(FP), DI		// arg 1 fd
	MOVQ	$SYS_close, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$-1, AX
	MOVL	AX, ret+8(FP)
	RET

TEXT runtime·read(SB),NOSPLIT,$-8
	MOVL	fd+0(FP), DI		// arg 1 fd
	MOVQ	p+8(FP), SI		// arg 2 buf
	MOVL	n+16(FP), DX		// arg 3 count
	MOVQ	$SYS_read, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	3(PC)
	MOVQ	CX, AX
	NEGQ	AX			// caller expects negative errno
	MOVL	AX, ret+24(FP)
	RET

// func pipe2(flags int32) (r, w int32, errno int32)
TEXT runtime·pipe2(SB),NOSPLIT,$0-20
	LEAQ	r+8(FP), DI
	MOVL	flags+0(FP), SI
	MOVQ	$SYS_pipe2, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	3(PC)
	MOVQ	CX, AX
	NEGQ	AX
	MOVL	AX, errno+16(FP)
	RET

TEXT runtime·write1(SB),NOSPLIT,$-8
	MOVQ	fd+0(FP), DI		// arg 1 fd
	MOVQ	p+8(FP), SI		// arg 2 buf
	MOVL	n+16(FP), DX		// arg 3 count
	MOVQ	$SYS_write, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	3(PC)
	MOVQ	CX, AX
	NEGQ	AX			// caller expects negative errno
	MOVL	AX, ret+24(FP)
	RET

TEXT runtime·thr_self<ABIInternal>(SB),NOSPLIT,$0
	// thr_self(&0(FP))
	MOVQ	0x10(FS), AX
	RET

TEXT runtime·thr_kill(SB),NOSPLIT,$0-16
	// pthread_kill(tid, sig)
	MOVQ	tid+0(FP), DI	// arg 1 id
	MOVQ	sig+8(FP), SI	// arg 2 sig
	MOVQ	runtime·ppthread_kill(SB), R12
	CALL	R12
	RET

TEXT runtime·raiseproc(SB),NOSPLIT,$0
	// getpid
	MOVQ	$SYS_getpid, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	// kill(self, sig)
	MOVQ	AX, DI		// arg 1 pid
	MOVL	sig+0(FP), SI	// arg 2 sig
	MOVQ	$SYS_kill, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	RET

TEXT runtime·setitimer(SB), NOSPLIT, $-8
	MOVL	mode+0(FP), DI
	MOVQ	new+8(FP), SI
	MOVQ	old+16(FP), DX
	MOVQ	$SYS_setitimer, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	RET

// func fallback_walltime() (sec int64, nsec int32)
TEXT runtime·fallback_walltime(SB), NOSPLIT, $32-12
	MOVQ	$SYS_clock_gettime, AX
	MOVQ	$CLOCK_REALTIME, DI
	LEAQ	8(SP), SI
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	MOVQ	8(SP), AX	// sec
	MOVQ	16(SP), DX	// nsec

	// sec is in AX, nsec in DX
	MOVQ	AX, sec+0(FP)
	MOVL	DX, nsec+8(FP)
	RET

TEXT runtime·fallback_nanotime(SB), NOSPLIT, $32-8
	MOVQ	$SYS_clock_gettime, AX
	MOVQ	$CLOCK_MONOTONIC, DI
	LEAQ	8(SP), SI
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	MOVQ	8(SP), AX	// sec
	MOVQ	16(SP), DX	// nsec

	// sec is in AX, nsec in DX
	// return nsec in AX
	IMULQ	$1000000000, AX
	ADDQ	DX, AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT runtime·asmSigaction(SB),NOSPLIT,$0
	MOVQ	sig+0(FP), DI		// arg 1 sig
	MOVQ	new+8(FP), SI		// arg 2 act
	MOVQ	old+16(FP), DX		// arg 3 oact
	MOVQ	$SYS_sigaction, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$-1, AX
	MOVL	AX, ret+24(FP)
	RET

TEXT runtime·callCgoSigaction(SB),NOSPLIT,$16
	MOVQ	sig+0(FP), DI		// arg 1 sig
	MOVQ	new+8(FP), SI		// arg 2 act
	MOVQ	old+16(FP), DX		// arg 3 oact
	MOVQ	_cgo_sigaction(SB), AX
	MOVQ	SP, BX			// callee-saved
	ANDQ	$~15, SP		// alignment as per amd64 psABI
	CALL	AX
	MOVQ	BX, SP
	MOVL	AX, ret+24(FP)
	RET

TEXT runtime·sigfwd(SB),NOSPLIT,$0-32
	MOVQ	fn+0(FP),    AX
	MOVL	sig+8(FP),   DI
	MOVQ	info+16(FP), SI
	MOVQ	ctx+24(FP),  DX
	MOVQ	SP, BX		// callee-saved
	ANDQ	$~15, SP	// alignment for x86_64 ABI
	CALL	AX
	MOVQ	BX, SP
	RET

// Called using C ABI.
TEXT runtime·sigtramp(SB),NOSPLIT|TOPFRAME|NOFRAME,$0
	// Transition from C ABI to Go ABI.
	PUSH_REGS_HOST_TO_ABI0()

	// Set up ABIInternal environment: g in R14, cleared X15.
	get_tls(R12)
	MOVQ	g(R12), R14
	PXOR	X15, X15

	// Reserve space for spill slots.
	NOP	SP		// disable vet stack checking
	ADJSP   $24

	// Call into the Go signal handler
	MOVQ	DI, AX	// sig
	MOVQ	SI, BX	// info
	MOVQ	DX, CX	// ctx
	CALL	·sigtrampgo<ABIInternal>(SB)

	ADJSP	$-24

	POP_REGS_HOST_TO_ABI0()
	RET

// Called using C ABI.
TEXT runtime·sigprofNonGoWrapper<>(SB),NOSPLIT|NOFRAME,$0
	// Transition from C ABI to Go ABI.
	PUSH_REGS_HOST_TO_ABI0()

	// Set up ABIInternal environment: g in R14, cleared X15.
	get_tls(R12)
	MOVQ	g(R12), R14
	PXOR	X15, X15

	// Reserve space for spill slots.
	NOP	SP		// disable vet stack checking
	ADJSP   $24

	// Call into the Go signal handler
	MOVQ	DI, AX	// sig
	MOVQ	SI, BX	// info
	MOVQ	DX, CX	// ctx
	CALL	·sigprofNonGo<ABIInternal>(SB)

	ADJSP	$-24

	POP_REGS_HOST_TO_ABI0()
	RET

// Used instead of sigtramp in programs that use cgo.
// Arguments from kernel are in DI, SI, DX.
TEXT runtime·cgoSigtramp(SB),NOSPLIT,$0
	// If no traceback function, do usual sigtramp.
	MOVQ	runtime·cgoTraceback(SB), AX
	TESTQ	AX, AX
	JZ	sigtramp

	// If no traceback support function, which means that
	// runtime/cgo was not linked in, do usual sigtramp.
	MOVQ	_cgo_callers(SB), AX
	TESTQ	AX, AX
	JZ	sigtramp

	// Figure out if we are currently in a cgo call.
	// If not, just do usual sigtramp.
	get_tls(CX)
	MOVQ	g(CX),AX
	TESTQ	AX, AX
	JZ	sigtrampnog     // g == nil
	MOVQ	g_m(AX), AX
	TESTQ	AX, AX
	JZ	sigtramp        // g.m == nil
	MOVL	m_ncgo(AX), CX
	TESTL	CX, CX
	JZ	sigtramp        // g.m.ncgo == 0
	MOVQ	m_curg(AX), CX
	TESTQ	CX, CX
	JZ	sigtramp        // g.m.curg == nil
	MOVQ	g_syscallsp(CX), CX
	TESTQ	CX, CX
	JZ	sigtramp        // g.m.curg.syscallsp == 0
	MOVQ	m_cgoCallers(AX), R8
	TESTQ	R8, R8
	JZ	sigtramp        // g.m.cgoCallers == nil
	MOVL	m_cgoCallersUse(AX), CX
	TESTL	CX, CX
	JNZ	sigtramp	// g.m.cgoCallersUse != 0

	// Jump to a function in runtime/cgo.
	// That function, written in C, will call the user's traceback
	// function with proper unwind info, and will then call back here.
	// The first three arguments, and the fifth, are already in registers.
	// Set the two remaining arguments now.
	MOVQ	runtime·cgoTraceback(SB), CX
	MOVQ	$runtime·sigtramp(SB), R9
	MOVQ	_cgo_callers(SB), AX
	JMP	AX

sigtramp:
	JMP	runtime·sigtramp(SB)

sigtrampnog:
	// Signal arrived on a non-Go thread. If this is SIGPROF, get a
	// stack trace.
	CMPL	DI, $27 // 27 == SIGPROF
	JNZ	sigtramp

	// Lock sigprofCallersUse.
	MOVL	$0, AX
	MOVL	$1, CX
	MOVQ	$runtime·sigprofCallersUse(SB), R11
	LOCK
	CMPXCHGL	CX, 0(R11)
	JNZ	sigtramp  // Skip stack trace if already locked.

	// Jump to the traceback function in runtime/cgo.
	// It will call back to sigprofNonGo, via sigprofNonGoWrapper, to convert
	// the arguments to the Go calling convention.
	// First three arguments to traceback function are in registers already.
	MOVQ	runtime·cgoTraceback(SB), CX
	MOVQ	$runtime·sigprofCallers(SB), R8
	MOVQ	$runtime·sigprofNonGoWrapper<>(SB), R9
	MOVQ	_cgo_callers(SB), AX
	JMP	AX

TEXT runtime·sysMmap(SB),NOSPLIT,$0
	MOVQ	addr+0(FP), DI		// arg 1 addr
	MOVQ	n+8(FP), SI		// arg 2 len
	MOVL	prot+16(FP), DX		// arg 3 prot
	MOVL	flags+20(FP), R10		// arg 4 flags
	MOVL	fd+24(FP), R8		// arg 5 fid
	MOVL	off+28(FP), R9		// arg 6 offset
	MOVQ	$SYS_mmap, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	ok
	MOVQ	$0, p+32(FP)
	MOVQ	CX, err+40(FP)
	RET
ok:
	MOVQ	AX, p+32(FP)
	MOVQ	$0, err+40(FP)
	RET

// Call the function stored in _cgo_mmap using the GCC calling convention.
// This must be called on the system stack.
TEXT runtime·callCgoMmap(SB),NOSPLIT,$16
	MOVQ	addr+0(FP), DI
	MOVQ	n+8(FP), SI
	MOVL	prot+16(FP), DX
	MOVL	flags+20(FP), CX
	MOVL	fd+24(FP), R8
	MOVL	off+28(FP), R9
	MOVQ	_cgo_mmap(SB), AX
	MOVQ	SP, BX
	ANDQ	$~15, SP	// alignment as per amd64 psABI
	MOVQ	BX, 0(SP)
	CALL	AX
	MOVQ	0(SP), SP
	MOVQ	AX, ret+32(FP)
	RET

TEXT runtime·sysMunmap(SB),NOSPLIT,$0
	MOVQ	addr+0(FP), DI		// arg 1 addr
	MOVQ	n+8(FP), SI		// arg 2 len
	MOVQ	$SYS_munmap, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$0xf1, 0xf1  // crash
	RET

// Call the function stored in _cgo_munmap using the GCC calling convention.
// This must be called on the system stack.
TEXT runtime·callCgoMunmap(SB),NOSPLIT,$16-16
	MOVQ	addr+0(FP), DI
	MOVQ	n+8(FP), SI
	MOVQ	_cgo_munmap(SB), AX
	MOVQ	SP, BX
	ANDQ	$~15, SP	// alignment as per amd64 psABI
	MOVQ	BX, 0(SP)
	CALL	AX
	MOVQ	0(SP), SP
	RET

TEXT runtime·madvise(SB),NOSPLIT,$0
	MOVQ	addr+0(FP), DI
	MOVQ	n+8(FP), SI
	MOVL	flags+16(FP), DX
	MOVQ	$SYS_madvise, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$-1, AX
	MOVL	AX, ret+24(FP)
	RET

TEXT runtime·sigaltstack(SB),NOSPLIT,$-8
	MOVQ	new+0(FP), DI
	MOVQ	old+8(FP), SI
	MOVQ	$SYS_sigaltstack, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$0xf1, 0xf1  // crash
	RET

TEXT runtime·usleep(SB),NOSPLIT,$16
	MOVL	$0, DX
	MOVL	usec+0(FP), AX
	MOVL	$1000000, CX
	DIVL	CX
	MOVQ	AX, 0(SP)		// tv_sec
	MOVL	$1000, AX
	MULL	DX
	MOVQ	AX, 8(SP)		// tv_nsec

	MOVQ	SP, DI			// arg 1 - rqtp
	MOVQ	$0, SI			// arg 2 - rmtp
	MOVQ	$SYS_nanosleep, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	RET


// set tls base to DI
TEXT runtime·settls(SB),NOSPLIT,$0
	ADDQ	$8, DI	// adjust for ELF: wants to use -8(FS) for g and m

	// preserve the pthread tls
	MOVQ	0(FS), AX
	MOVQ	AX, (DI)
	MOVQ	0x8(FS), AX
	MOVQ	AX, 0x8(DI)
	MOVQ	0x10(FS), AX
	MOVQ	AX, 0x10(DI)
	MOVQ	0x18(FS), AX
	MOVQ	AX, 0x18(DI)
	MOVQ	0x20(FS), AX
	MOVQ	AX, 0x20(DI)

	PUSHQ	DI
	MOVQ	SP, SI
	MOVQ	$AMD64_SET_FSBASE, DI
	MOVQ	$SYS_sysarch, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$0xf1, 0xf1  // crash
	POPQ	DI
	RET

TEXT runtime·sysctl(SB),NOSPLIT,$0
	MOVQ	mib+0(FP), DI		// arg 1 - name
	MOVL	miblen+8(FP), SI		// arg 2 - namelen
	MOVQ	out+16(FP), DX		// arg 3 - oldp
	MOVQ	size+24(FP), R10		// arg 4 - oldlenp
	MOVQ	dst+32(FP), R8		// arg 5 - newp
	MOVQ	ndst+40(FP), R9		// arg 6 - newlen
	MOVQ	$SYS___sysctl, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS 5(PC)
	MOVQ	CX, AX
	NEGQ	AX
	MOVL	AX, ret+48(FP)
	RET
	MOVL	$0, AX
	MOVL	AX, ret+48(FP)
	RET

TEXT runtime·osyield(SB),NOSPLIT,$-4
	MOVQ	$SYS_sched_yield, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	RET

TEXT runtime·sigprocmask(SB),NOSPLIT,$0
	MOVL	how+0(FP), DI		// arg 1 - how
	MOVQ	new+8(FP), SI		// arg 2 - set
	MOVQ	old+16(FP), DX		// arg 3 - oset
	MOVQ	$SYS_sigprocmask, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	2(PC)
	MOVL	$0xf1, 0xf1  // crash
	RET

// int32 runtime·kqueue(void);
TEXT runtime·kqueue(SB),NOSPLIT,$0
	MOVQ	$0, DI
	MOVQ	$0, SI
	MOVQ	$0, DX
	MOVQ	$SYS_kqueue, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	3(PC)
	MOVQ	CX, AX
	NEGQ	AX
	MOVL	AX, ret+0(FP)
	RET

// int32 runtime·kevent(int kq, Kevent *changelist, int nchanges, Kevent *eventlist, int nevents, Timespec *timeout);
TEXT runtime·kevent(SB),NOSPLIT,$0
	MOVL	kq+0(FP), DI
	MOVQ	ch+8(FP), SI
	MOVL	nch+16(FP), DX
	MOVQ	ev+24(FP), R10
	MOVL	nev+32(FP), R8
	MOVQ	ts+40(FP), R9
	MOVQ	$SYS_kevent, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	3(PC)
	MOVQ	CX, AX
	NEGQ	AX
	MOVL	AX, ret+48(FP)
	RET

// func fcntl(fd, cmd, arg int32) (int32, int32)
TEXT runtime·fcntl(SB),NOSPLIT,$0
	MOVL	fd+0(FP), DI	// fd
	MOVL	cmd+4(FP), SI	// cmd
	MOVL	arg+8(FP), DX	// arg
	MOVQ	$SYS_fcntl, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	noerr
	MOVL	$-1, ret+16(FP)
	MOVL	CX, errno+20(FP)
	RET
noerr:
	MOVL	AX, ret+16(FP)
	MOVL	$0, errno+20(FP)
	RET

// func cpuset_getaffinity(level int, which int, id int64, size int, mask *byte) int32
TEXT runtime·cpuset_getaffinity(SB), NOSPLIT, $0-44
	MOVQ	level+0(FP), DI
	MOVQ	which+8(FP), SI
	MOVQ	id+16(FP), DX
	MOVQ	size+24(FP), R10
	MOVQ	mask+32(FP), R8
	MOVQ	$SYS_cpuset_getaffinity, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	TESTQ	AX, AX
	JNS	3(PC)
	MOVQ	CX, AX
	NEGQ	AX
	MOVL	AX, ret+40(FP)
	RET

// func issetugid() int32
TEXT runtime·issetugid(SB),NOSPLIT,$0
	MOVQ	$0, DI
	MOVQ	$0, SI
	MOVQ	$0, DX
	MOVQ	$SYS_issetugid, AX
	MOVQ	runtime·psyscall_addr(SB), R12
	CALL	R12
	MOVL	AX, ret+0(FP)
	RET

// void runtime·asmcdeclcall(void *c);
TEXT runtime·asmcdeclcall(SB),NOSPLIT,$0
	// asmcgocall will put first argument into DI.
	PUSHQ	DI			// save for later
	MOVQ	libcall_fn(DI), AX
	MOVQ	libcall_args(DI), R11
	MOVQ	libcall_n(DI), R10

skiperrno1:
	CMPQ	R11, $0
	JEQ	skipargs
	// Load 6 args into correspondent registers.
	MOVQ	0(R11), DI
	MOVQ	8(R11), SI
	MOVQ	16(R11), DX
	MOVQ	24(R11), CX
	MOVQ	32(R11), R8
	MOVQ	40(R11), R9
skipargs:

	// Call SysV function
	CALL	AX

	// Return result
	POPQ	DI
	MOVQ	AX, libcall_r1(DI)

skiperrno2:
	RET
