// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"
#include "go_asm.h"

DATA fname_getpid<>+0x00(SB)/8, $0x646970746567 // "getpid"
GLOBL fname_getpid<>(SB), (NOPTR + RODATA), $8

DATA fname_pthread_create<>+0x00(SB)/8, $0x5F64616572687470 // "pthread_"
DATA fname_pthread_create<>+0x08(SB)/8, $0x657461657263 // "create"
GLOBL fname_pthread_create<>(SB), (NOPTR + RODATA), $16

DATA fname_pthread_exit<>+0x00(SB)/8, $0x5F64616572687470 // "pthread_"
DATA fname_pthread_exit<>+0x08(SB)/8, $0x74697865 // "exit"
GLOBL fname_pthread_exit<>(SB), (NOPTR + RODATA), $16

DATA fname_pthread_kill<>+0x00(SB)/8, $0x5F64616572687470 // "pthread_"
DATA fname_pthread_kill<>+0x08(SB)/8, $0x6C6C696B // "kill"
GLOBL fname_pthread_kill<>(SB), (NOPTR + RODATA), $16

DATA console<>+0x00(SB)/8, $0x6E6F632F7665642F // "/dev/con"
DATA console<>+0x08(SB)/8, $0x656C6F73         // "sole"
GLOBL console<>(SB), (NOPTR + RODATA), $16

DATA argv_hack<>+0x00(SB)/8, $0
DATA argv_hack<>+0x08(SB)/8, $0
GLOBL argv_hack<>(SB), (NOPTR + RODATA), $16

GLOBL ppthread_join(SB), (NOPTR), $8
GLOBL main_thread(SB), (NOPTR), $8

DATA libkernel_handle(SB)/4, $0x2001
GLOBL libkernel_handle(SB), (NOPTR), $4

// MOVQ src, dst // stupid x86

// Handle needed argument passed by homebrew elf loader
TEXT _rt0_amd64_prospero(SB),NOSPLIT,$-8
	LEAQ	runtime·homebrew_args(SB), AX
	MOVQ	0x0(DI), SI
	MOVQ	SI, PayloadArgs_dlsym(AX)
	MOVQ	0x8(DI), SI
	MOVL	(SI), BX
	MOVL	BX, PayloadArgs_rwpipe(AX)
	MOVL	4(SI), BX
	MOVL	BX, (PayloadArgs_rwpipe + 4)(AX)
	MOVQ	0x10(DI), SI
	MOVL	(SI), BX
	MOVL	BX, PayloadArgs_rwpair(AX)
	MOVL	4(SI), BX
	MOVL	BX, (PayloadArgs_rwpair + 4)(AX)
	MOVQ	0x18(DI), SI
	MOVQ	SI, PayloadArgs_kpipe_addr(AX)
	MOVQ	0x20(DI), SI
	MOVQ	SI, PayloadArgs_kdata_base_addr(AX)
	MOVQ	DI, AX // payload_args->dlsym
	MOVL	libkernel_handle(SB), DI
	MOVQ	$fname_getpid<>(SB), SI
	LEAQ	runtime·psyscall_addr(SB), DX
	PUSHQ	AX
	CALL	(AX)
	TESTQ	AX,AX
	JZ		found_handle
	MOVL	$0x1, libkernel_handle(SB)
	MOVL	libkernel_handle(SB), DI
	MOVQ	(SP), AX
	MOVQ	$fname_getpid<>(SB), SI
	LEAQ	runtime·psyscall_addr(SB), DX
	CALL	(AX)
found_handle:
	ADDQ	$10, runtime·psyscall_addr(SB)
	MOVQ	(SP), AX
	MOVL	libkernel_handle(SB), DI
	MOVQ	$fname_pthread_create<>(SB), SI
	LEAQ	runtime·ppthread_create(SB), DX
	CALL	(AX)
	MOVQ	(SP), AX
	MOVL	libkernel_handle(SB), DI
	MOVQ	$fname_pthread_exit<>(SB), SI
	LEAQ	runtime·ppthread_exit(SB), DX
	CALL	(AX)
	MOVQ	(SP), AX
	MOVL	libkernel_handle(SB), DI
	MOVQ	$fname_pthread_kill<>(SB), SI
	LEAQ	runtime·ppthread_kill(SB), DX
	CALL	(AX)
	POPQ	AX
	MOVQ	$console<>(SB), DI
	MOVQ	$1, SI
	XORQ	DX, DX
	MOVQ	$5, AX
	MOVQ	runtime·psyscall_addr(SB), BX
	CALL	BX
	MOVQ	AX, DI
	MOVQ	$1, SI
	MOVQ	$90, AX
	MOVQ	runtime·psyscall_addr(SB), BX
	CALL	BX
	MOVQ	$1, DI
	MOVQ	$2, SI
	MOVQ	$90, AX
	MOVQ	runtime·psyscall_addr(SB), BX
	CALL	BX

	// we need to fake argc, argv and env
	MOVQ	$0, DI
	MOVQ	$argv_hack<>(SB), SI
	JMP	runtime·rt0_go(SB)

// I don't actually know what this one is for
TEXT _rt0_amd64_prospero_lib(SB),NOSPLIT,$0
	JMP	_rt0_amd64_lib(SB)
