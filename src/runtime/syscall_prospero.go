package runtime

import "unsafe"

// I'm lazy, register args only
const maxArgs = 6

//go:linkname syscall_SyscallN syscall.SyscallN
//go:nosplit
//go:cgo_unsafe_args
func syscall_SyscallN(trap uintptr, args ...uintptr) (r1 uintptr) {
	if trap == 0 {
		panic("null trap")
	}
	nargs := len(args)

	// asmstdcall expects it can access the first 6 arguments
	// to load them into registers.
	var tmp [maxArgs]uintptr
	switch {
	case nargs < maxArgs:
		copy(tmp[:], args)
		args = tmp[:]
	case nargs > maxArgs:
		panic("runtime: SyscallN has too many arguments")
	}

	call := libcall{
		fn:   trap,
		n:    uintptr(nargs),
		args: uintptr(unsafe.Pointer(&args[0])),
	}

	entersyscallblock()
	asmcgocall(asmcdeclcallAddr, unsafe.Pointer(&call))
	exitsyscall()

	r1 = call.r1
	return
}
