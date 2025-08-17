// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"
#include "go_asm.h"

DATA argv_hack<>+0x00(SB)/8, $0
DATA argv_hack<>+0x08(SB)/8, $0
GLOBL argv_hack<>(SB), (NOPTR + RODATA), $16

// I don't actually know what this one is for
TEXT _rt0_amd64_prospero_lib(SB),NOSPLIT,$0
	JMP	_rt0_amd64_lib(SB)


TEXT exit(SB),NOSPLIT,$0
	// crash with error code
	// we have no choice because we failed to get syscall address
	MOVQ	$0xBADCA110, AX
	JMP		AX


/*
struct functions {
	int (*_rt0_go)(int argc, const char **argv);
	void (*exit)(int status);
	uintptr_t *psyscall_addr;
} _rt0_functions;
*/


// RDI: args
// RSI homebrew_args
// RDX functions
TEXT _rt0_amd64_prospero(SB),NOSPLIT,$-8
	MOVQ	SI, CX
	TESTQ	CX, CX
	JNZ	has_args
	MOVQ	$argv_hack<>(SB), CX
has_args:
	LEAQ	runtime·homebrew_args(SB), SI
	LEAQ	runtime·_rt0_functions(SB), DX
	LEAQ	runtime·rt0_go(SB), AX
	MOVQ	AX, 0x00(DX)
	LEAQ	exit(SB), AX
	MOVQ	AX, 0x08(DX)
	LEAQ	runtime·psyscall_addr(SB), AX
	MOVQ	AX, 0x10(DX)
	// fallthrough to pre-compiled c code
	
/*
typedef int (*dlsym_t)(int, const char*, void*);

struct payload_args {
	union {
		dlsym_t dlsym;         // 0x00
		int (*getpid)(void);
		uintptr_t addr;
	};
	int *rwpipe;                // 0x08
	int *rwpair;                // 0x10
	uint64_t kpipe_addr;        // 0x18
	uint64_t kdata_base_addr;   // 0x20
};

struct functions {
	int (*_rt0_go)(int argc, const char **argv);
	void (*exit)(int status) __attribute__((noreturn));
	uintptr_t *psyscall_addr;
};

int _rt0_amd64_prospero(const struct payload_args *restrict args, struct payload_args *restrict homebrew_args, const struct functions *restrict functions, const char **argv) {
	*homebrew_args = *args;

	int libkernel = 0x2001;
	const char *fname = NULL;

	// this will fail safely without a fault in copyin
	if (args->dlsym(0, (char *)(-1LL), NULL) < 0) {
		// real dlsym
		uint64_t fn = 0x646970746567; // "getpid"
		fname = (char *)&fn;
		if (args->dlsym(libkernel, fname, functions->psyscall_addr)) {
			libkernel = 1;
			if (args->dlsym(libkernel, fname, functions->psyscall_addr)) {
				functions->exit(-1);
			}
		}
	} else {
		// it is already getpid
		*functions->psyscall_addr = args->addr;
	}
	*functions->psyscall_addr += 10;

	// remaining setup, get argc and argv and then jump to runtime.rt0_go.abi0

	int argc = 0;
	while (argv && argv[argc]) {
		argc++;
	}
	
	return functions->_rt0_go(argc, argv);
}
*/


	BYTE $0x41
	BYTE $0x57
	BYTE $0x41
	BYTE $0x56
	BYTE $0x41
	BYTE $0x54
	BYTE $0x53
	BYTE $0x50
	BYTE $0xc5
	BYTE $0xfc
	BYTE $0x10
	BYTE $0x07
	BYTE $0x48
	BYTE $0x8b
	BYTE $0x47
	BYTE $0x20
	BYTE $0x4c
	BYTE $0x8b
	BYTE $0x27
	BYTE $0x48
	BYTE $0x89
	BYTE $0xd3
	BYTE $0x31
	BYTE $0xff
	BYTE $0x31
	BYTE $0xd2
	BYTE $0x49
	BYTE $0x89
	BYTE $0xce
	BYTE $0x48
	BYTE $0x89
	BYTE $0x46
	BYTE $0x20
	BYTE $0xc5
	BYTE $0xfc
	BYTE $0x11
	BYTE $0x06
	BYTE $0x48
	BYTE $0xc7
	BYTE $0xc6
	BYTE $0xff
	BYTE $0xff
	BYTE $0xff
	BYTE $0xff
	BYTE $0xc5
	BYTE $0xf8
	BYTE $0x77
	BYTE $0x41
	BYTE $0xff
	BYTE $0xd4
	BYTE $0x85
	BYTE $0xc0
	BYTE $0x78
	BYTE $0x38
	BYTE $0x4c
	BYTE $0x8b
	BYTE $0x7b
	BYTE $0x10
	BYTE $0x4d
	BYTE $0x89
	BYTE $0x27
	BYTE $0x49
	BYTE $0x83
	BYTE $0xc4
	BYTE $0x0a
	BYTE $0x4d
	BYTE $0x89
	BYTE $0x27
	BYTE $0x4d
	BYTE $0x85
	BYTE $0xf6
	BYTE $0x74
	BYTE $0x6a
	BYTE $0xbf
	BYTE $0xff
	BYTE $0xff
	BYTE $0xff
	BYTE $0xff
	BYTE $0x4c
	BYTE $0x89
	BYTE $0xf0
	BYTE $0x66
	BYTE $0x66
	BYTE $0x66
	BYTE $0x66
	BYTE $0x66
	BYTE $0x66
	BYTE $0x2e
	BYTE $0x0f
	BYTE $0x1f
	BYTE $0x84
	BYTE $0x00
	BYTE $0x00
	BYTE $0x00
	BYTE $0x00
	BYTE $0x00
	BYTE $0xff
	BYTE $0xc7
	BYTE $0x48
	BYTE $0x83
	BYTE $0x38
	BYTE $0x00
	BYTE $0x48
	BYTE $0x8d
	BYTE $0x40
	BYTE $0x08
	BYTE $0x75
	BYTE $0xf4
	BYTE $0xeb
	BYTE $0x47
	BYTE $0x4c
	BYTE $0x8b
	BYTE $0x7b
	BYTE $0x10
	BYTE $0x48
	BYTE $0xb8
	BYTE $0x67
	BYTE $0x65
	BYTE $0x74
	BYTE $0x70
	BYTE $0x69
	BYTE $0x64
	BYTE $0x00
	BYTE $0x00
	BYTE $0x48
	BYTE $0x89
	BYTE $0xe6
	BYTE $0xbf
	BYTE $0x01
	BYTE $0x20
	BYTE $0x00
	BYTE $0x00
	BYTE $0x48
	BYTE $0x89
	BYTE $0x04
	BYTE $0x24
	BYTE $0x4c
	BYTE $0x89
	BYTE $0xfa
	BYTE $0x41
	BYTE $0xff
	BYTE $0xd4
	BYTE $0x85
	BYTE $0xc0
	BYTE $0x74
	BYTE $0x12
	BYTE $0x48
	BYTE $0x89
	BYTE $0xe6
	BYTE $0xbf
	BYTE $0x01
	BYTE $0x00
	BYTE $0x00
	BYTE $0x00
	BYTE $0x4c
	BYTE $0x89
	BYTE $0xfa
	BYTE $0x41
	BYTE $0xff
	BYTE $0xd4
	BYTE $0x85
	BYTE $0xc0
	BYTE $0x75
	BYTE $0x22
	BYTE $0x4d
	BYTE $0x8b
	BYTE $0x27
	BYTE $0x49
	BYTE $0x83
	BYTE $0xc4
	BYTE $0x0a
	BYTE $0x4d
	BYTE $0x89
	BYTE $0x27
	BYTE $0x4d
	BYTE $0x85
	BYTE $0xf6
	BYTE $0x75
	BYTE $0x96
	BYTE $0x31
	BYTE $0xff
	BYTE $0x4c
	BYTE $0x89
	BYTE $0xf6
	BYTE $0xff
	BYTE $0x13
	BYTE $0x48
	BYTE $0x83
	BYTE $0xc4
	BYTE $0x08
	BYTE $0x5b
	BYTE $0x41
	BYTE $0x5c
	BYTE $0x41
	BYTE $0x5e
	BYTE $0x41
	BYTE $0x5f
	BYTE $0xc3
	BYTE $0xbf
	BYTE $0xff
	BYTE $0xff
	BYTE $0xff
	BYTE $0xff
	BYTE $0xff
	BYTE $0x53
	BYTE $0x08
