package runtime

import "unsafe"

// I'm lazy, register args only
const maxArgs = 6

//go:linkname syscall_SyscallN syscall.SyscallN
//go:nosplit
func syscall_SyscallN(trap uintptr, args ...uintptr) (r1 uintptr) {
	nargs := len(args)

	// asmstdcall expects it can access the first 4 arguments
	// to load them into registers.
	var tmp [4]uintptr
	switch {
	case nargs < 4:
		copy(tmp[:], args)
		args = tmp[:]
	case nargs > maxArgs:
		panic("runtime: SyscallN has too many arguments")
	}

	lockOSThread()
	defer unlockOSThread()
	c := &getg().m.syscall
	c.fn = trap
	c.n = uintptr(nargs)
	c.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	cgocall(asmcdeclcallAddr, unsafe.Pointer(c))
	return c.r1
}
