// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build prospero

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

func cgoSigtramp()

type PayloadArgs struct {
	dlsym           uintptr
	rwpipe          [2]int32
	rwpair          [2]int32
	kpipe_addr      uintptr
	kdata_base_addr uintptr
}

type pthread_attr struct {
	sched_policy   int32
	sched_inherit  int32
	prio           int32
	suspend        int32
	flags          int32
	stackaddr_attr uintptr
	stacksize_attr uintptr
	guardsize_attr uint64
	cpuset         uintptr
	cpuset_size    uintptr
}

const PTHREAD_DETACHED = 1

//go:linkname psyscall_addr runtime.psyscall_addr
var psyscall_addr uintptr // name to take addr of syscall

//go:linkname ppthread_create runtime.ppthread_create
var ppthread_create uintptr // name to take addr of pthread_create

//go:linkname ppthread_exit runtime.ppthread_exit
var ppthread_exit uintptr // name to take addr of pthread_exit

//go:linkname ppthread_kill runtime.ppthread_kill
var ppthread_kill uintptr // name to take addr of pthread_kill

//go:linkname homebrew_args runtime.homebrew_args
var homebrew_args PayloadArgs

func GetDlsym() uintptr {
	return homebrew_args.dlsym
}

func GetRWPipe() [2]int32 {
	return [2]int32{homebrew_args.rwpipe[0], homebrew_args.rwpipe[1]}
}

func GetRWPair() [2]int32 {
	return [2]int32{homebrew_args.rwpair[0], homebrew_args.rwpair[1]}
}

func GetKernelPipeAddress() uintptr {
	return homebrew_args.kpipe_addr
}

func GetKernelBase() uintptr {
	return homebrew_args.kdata_base_addr
}

func GetSyscallAddress() uintptr {
	return psyscall_addr
}

type mOS struct{}

//go:noescape
func thr_new(fn uintptr, tls unsafe.Pointer, attr **pthread_attr) int32

//go:noescape
func sigaltstack(new, old *stackt)

//go:noescape
func sigprocmask(how int32, new, old *sigset)

//go:noescape
func setitimer(mode int32, new, old *itimerval)

//go:noescape
func sysctl(mib *uint32, miblen uint32, out *byte, size *uintptr, dst *byte, ndst uintptr) int32

func raiseproc(sig uint32)

func thr_self() thread
func thr_kill(tid thread, sig int)

func thr_attr_init(unsafe.Pointer) int32
func thr_attr_destroy(unsafe.Pointer) int32

//go:noescape
func sys_umtx_op(addr *uint32, mode int32, val uint32, uaddr1 uintptr, ut *umtx_time) int32

func osyield()

//go:nosplit
func osyield_no_g() {
	osyield()
}

func kqueue() int32

//go:noescape
func kevent(kq int32, ch *keventt, nch int32, ev *keventt, nev int32, ts *timespec) int32

func pipe2(flags int32) (r, w int32, errno int32)
func fcntl(fd, cmd, arg int32) (ret int32, errno int32)

func issetugid() int32

// From FreeBSD's <sys/sysctl.h>
const (
	_CTL_HW      = 6
	_HW_PAGESIZE = 7
)

var sigset_all = sigset{[4]uint32{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}}

// Undocumented numbers from FreeBSD's lib/libc/gen/sysctlnametomib.c.
const (
	_CTL_QUERY     = 0
	_CTL_QUERY_MIB = 3
)

// sysctlnametomib fill mib with dynamically assigned sysctl entries of name,
// return count of effected mib slots, return 0 on error.
func sysctlnametomib(name []byte, mib *[_CTL_MAXNAME]uint32) uint32 {
	oid := [2]uint32{_CTL_QUERY, _CTL_QUERY_MIB}
	miblen := uintptr(_CTL_MAXNAME)
	if sysctl(&oid[0], 2, (*byte)(unsafe.Pointer(mib)), &miblen, (*byte)(unsafe.Pointer(&name[0])), (uintptr)(len(name))) < 0 {
		return 0
	}
	miblen /= unsafe.Sizeof(uint32(0))
	if miblen <= 0 {
		return 0
	}
	return uint32(miblen)
}

const (
	_CPU_CURRENT_PID = -1 // Current process ID.
)

//go:noescape
func cpuset_getaffinity(level int, which int, id int64, size int, mask *byte) int32

//go:systemstack
func getncpu() int32 {
	// Use a large buffer for the CPU mask. We're on the system
	// stack, so this is fine, and we can't allocate memory for a
	// dynamically-sized buffer at this point.
	const maxCPUs = 64 * 1024
	var mask [maxCPUs / 8]byte
	/*var mib [_CTL_MAXNAME]uint32

	// According to FreeBSD's /usr/src/sys/kern/kern_cpuset.c,
	// cpuset_getaffinity return ERANGE when provided buffer size exceed the limits in kernel.
	// Querying kern.smp.maxcpus to calculate maximum buffer size.
	// See https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=200802

	// Variable kern.smp.maxcpus introduced at Dec 23 2003, revision 123766,
	// with dynamically assigned sysctl entries.
	miblen := sysctlnametomib([]byte("kern.smp.maxcpus"), &mib)
	if miblen == 0 {
		return 1
	}

	// Query kern.smp.maxcpus.
	dstsize := uintptr(4)
	maxcpus := uint32(0)
	if sysctl(&mib[0], miblen, (*byte)(unsafe.Pointer(&maxcpus)), &dstsize, nil, 0) != 0 {
		return 1
	}*/

	const maxcpus = 64

	maskSize := int(maxcpus+7) / 8
	if maskSize < goarch.PtrSize {
		maskSize = goarch.PtrSize
	}
	if maskSize > len(mask) {
		maskSize = len(mask)
	}

	if cpuset_getaffinity(_CPU_LEVEL_WHICH, _CPU_WHICH_PID, _CPU_CURRENT_PID,
		maskSize, (*byte)(unsafe.Pointer(&mask[0]))) != 0 {
		return 1
	}
	n := int32(0)
	for _, v := range mask[:maskSize] {
		for v != 0 {
			n += int32(v & 1)
			v >>= 1
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

func getPageSize() uintptr {
	return 0x4000
}

// FreeBSD's umtx_op syscall is effectively the same as Linux's futex, and
// thus the code is largely similar. See Linux implementation
// and lock_futex.go for comments.

//go:nosplit
func futexsleep(addr *uint32, val uint32, ns int64) {
	systemstack(func() {
		futexsleep1(addr, val, ns)
	})
}

func futexsleep1(addr *uint32, val uint32, ns int64) {
	var utp *umtx_time
	if ns >= 0 {
		var ut umtx_time
		ut._clockid = _CLOCK_MONOTONIC
		ut._timeout.setNsec(ns)
		utp = &ut
	}
	ret := sys_umtx_op(addr, _UMTX_OP_WAIT_UINT_PRIVATE, val, unsafe.Sizeof(*utp), utp)
	if ret >= 0 || ret == -_EINTR || ret == -_ETIMEDOUT {
		return
	}
	print("umtx_wait addr=", addr, " val=", val, " ret=", ret, "\n")
	*(*int32)(unsafe.Pointer(uintptr(0x1005))) = 0x1005
}

//go:nosplit
func futexwakeup(addr *uint32, cnt uint32) {
	ret := sys_umtx_op(addr, _UMTX_OP_WAKE_PRIVATE, cnt, 0, nil)
	if ret >= 0 {
		return
	}

	systemstack(func() {
		print("umtx_wake_addr=", addr, " ret=", ret, "\n")
	})
}

func thr_start()

// May run with m.p==nil, so write barriers are not allowed.
//
//go:nowritebarrier
func newosproc(mp *m) {
	stk := unsafe.Pointer(mp.g0.stack.hi)
	var oset sigset
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)

	attr := &pthread_attr{
		flags:          PTHREAD_DETACHED,
		stackaddr_attr: mp.g0.stack.lo,
		stacksize_attr: uintptr(stk) - mp.g0.stack.lo,
	}

	ret := retryOnEAGAIN(func() int32 {
		var e int32
		systemstack(func() {
			e = thr_new(abi.FuncPCABI0(thr_start), unsafe.Pointer(mp), &attr)
		})
		return e
	})

	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret != 0 {
		print("runtime: failed to create new OS thread (have ", mcount(), " already; errno=", ret, ")\n")
		throw("newosproc")
	}
}

// Version of newosproc that doesn't require a valid G.
//
//go:nosplit
func newosproc0(stacksize uintptr, fn unsafe.Pointer) {
	stack := sysAlloc(stacksize, &memstats.stacks_sys)
	if stack == nil {
		writeErrStr(failallocatestack)
		exit(1)
	}
	// This code "knows" it's being called once from the library
	// initialization code, and so it's using the static m0 for the
	// tls and procid (thread) pointers. thr_new() requires the tls
	// pointers, though the tid pointers can be nil.
	// However, newosproc0 is currently unreachable because builds
	// utilizing c-shared/c-archive force external linking.

	var oset sigset
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)

	attr := &pthread_attr{
		flags:          PTHREAD_DETACHED,
		stackaddr_attr: uintptr(stack),
		stacksize_attr: stacksize,
	}

	ret := thr_new(uintptr(fn), unsafe.Pointer(&m0), &attr)
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret < 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}
}

// Called to do synchronous initialization of Go code built with
// -buildmode=c-archive or -buildmode=c-shared.
// None of the Go runtime is initialized.
//
//go:nosplit
//go:nowritebarrierrec
func libpreinit() {
	initsig(true)
}

// Call a c function with cdecl conventions,
// and switch to os stack during the call.
func asmcdeclcall(fn unsafe.Pointer)

var asmcdeclcallAddr unsafe.Pointer

func osinit() {
	asmcdeclcallAddr = unsafe.Pointer(abi.FuncPCABI0(asmcdeclcall))
	ncpu = getncpu()
	if physPageSize == 0 {
		physPageSize = getPageSize()
	}
}

var urandom_dev = []byte("/dev/urandom\x00")

//go:nosplit
func getRandomData(r []byte) {
	fd := open(&urandom_dev[0], 0 /* O_RDONLY */, 0)
	n := read(fd, unsafe.Pointer(&r[0]), int32(len(r)))
	closefd(fd)
	extendRandom(r, int(n))
}

func goenvs() {
	goenvs_unix()
}

// Called to initialize a new m (including the bootstrap m).
// Called on the parent thread (main thread in case of bootstrap), can allocate memory.
func mpreinit(mp *m) {
	mp.gsignal = malg(32 * 1024)
	mp.gsignal.m = mp
}

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, cannot allocate memory.
func minit() {
	getg().m.procid = uint64(thr_self())

	// On FreeBSD before about April 2017 there was a bug such
	// that calling execve from a thread other than the main
	// thread did not reset the signal stack. That would confuse
	// minitSignals, which calls minitSignalStack, which checks
	// whether there is currently a signal stack and uses it if
	// present. To avoid this confusion, explicitly disable the
	// signal stack on the main thread when not running in a
	// library. This can be removed when we are confident that all
	// FreeBSD users are running a patched kernel. See issue #15658.
	if gp := getg(); !isarchive && !islibrary && gp.m == &m0 && gp == gp.m.g0 {
		st := stackt{ss_flags: _SS_DISABLE}
		sigaltstack(&st, nil)
	}

	minitSignals()
}

// Called from dropm to undo the effect of an minit.
//
//go:nosplit
func unminit() {
	unminitSignals()
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
func mdestroy(mp *m) {
}

func sigtramp()

type sigactiont struct {
	sa_handler uintptr
	sa_flags   int32
	sa_mask    sigset
}

// See os_freebsd2.go, os_freebsd_amd64.go for setsig function

//go:nosplit
//go:nowritebarrierrec
func setsigstack(i uint32) {
	var sa sigactiont
	sigaction(i, nil, &sa)
	if sa.sa_flags&_SA_ONSTACK != 0 {
		return
	}
	sa.sa_flags |= _SA_ONSTACK
	sigaction(i, &sa, nil)
}

//go:nosplit
//go:nowritebarrierrec
func getsig(i uint32) uintptr {
	var sa sigactiont
	sigaction(i, nil, &sa)
	return sa.sa_handler
}

// setSignalstackSP sets the ss_sp field of a stackt.
//
//go:nosplit
func setSignalstackSP(s *stackt, sp uintptr) {
	s.ss_sp = sp
}

//go:nosplit
//go:nowritebarrierrec
func sigaddset(mask *sigset, i int) {
	mask.__bits[(i-1)/32] |= 1 << ((uint32(i) - 1) & 31)
}

func sigdelset(mask *sigset, i int) {
	mask.__bits[(i-1)/32] &^= 1 << ((uint32(i) - 1) & 31)
}

//go:nosplit
func (c *sigctxt) fixsigcode(sig uint32) {
}

func setProcessCPUProfiler(hz int32) {
	setProcessCPUProfilerTimer(hz)
}

func setThreadCPUProfiler(hz int32) {
	setThreadCPUProfilerHz(hz)
}

//go:nosplit
func validSIGPROF(mp *m, c *sigctxt) bool {
	return true
}

func sysargs(argc int32, argv **byte) {
}

const (
	_AT_NULL     = 0  // Terminates the vector
	_AT_PAGESZ   = 6  // Page size in bytes
	_AT_TIMEKEEP = 22 // Pointer to timehands.
	_AT_HWCAP    = 25 // CPU feature flags
	_AT_HWCAP2   = 26 // CPU feature flags 2
)

func sysauxv(auxv []uintptr) (pairs int) {
	return 0
}

// sysSigaction calls the sigaction system call.
//
//go:nosplit
func sysSigaction(sig uint32, new, old *sigactiont) {
	// Use system stack to avoid split stack overflow on amd64
	if asmSigaction(uintptr(sig), new, old) != 0 {
		systemstack(func() {
			throw("sigaction failed")
		})
	}
}

// asmSigaction is implemented in assembly.
//
//go:noescape
func asmSigaction(sig uintptr, new, old *sigactiont) int32

// raise sends a signal to the calling thread.
//
// It must be nosplit because it is used by the signal handler before
// it definitely has a Go stack.
//
//go:nosplit
func raise(sig uint32) {
	thr_kill(thr_self(), int(sig))
}

func signalM(mp *m, sig int) {
	thr_kill(thread(mp.procid), sig)
}

// sigPerThreadSyscall is only used on linux, so we assign a bogus signal
// number.
const sigPerThreadSyscall = 1 << 31

//go:nosplit
func runPerThreadSyscall() {
	throw("runPerThreadSyscall only valid on linux")
}

//go:nosplit
//go:nowritebarrierrec
func setsig(i uint32, fn uintptr) {
	var sa sigactiont
	sa.sa_flags = _SA_SIGINFO | _SA_ONSTACK | _SA_RESTART
	sa.sa_mask = sigset_all
	if fn == abi.FuncPCABIInternal(sighandler) { // abi.FuncPCABIInternal(sighandler) matches the callers in signal_unix.go
		if iscgo {
			fn = abi.FuncPCABI0(cgoSigtramp)
		} else {
			fn = abi.FuncPCABI0(sigtramp)
		}
	}
	sa.sa_handler = fn
	sigaction(i, &sa, nil)
}
