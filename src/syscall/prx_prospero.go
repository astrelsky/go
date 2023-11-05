// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

// PrxError describes reasons for Prx load failures.
type PrxError struct {
	Err     error
	ObjName string
	Msg     string
}

func (e *PrxError) Error() string { return e.Msg }

func (e *PrxError) Unwrap() error { return e.Err }

// A Prx implements access to a single Prx.
type Prx struct {
	Name   string
	Handle uintptr
}

// int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv, uint32_t flags, void *unknown, int *result)
func internalKernelLoadStartModule(name *byte) uintptr {
	var result int32 = 0
	res, _, _ := sceKernelLoadStartModule.Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&result)))
	return res
}

func KernelLoadStartModule(name string) uintptr {
	cname, err := BytePtrFromString(name)
	if err != nil {
		return 0
	}
	return internalKernelLoadStartModule(cname)
}

func findLoadedPrx(name string) uintptr {
	cname, e := ByteSliceFromString(name)
	if e != nil {
		return 0
	}
	handles, err := DynlibGetList()
	if err != 0 {
		return 0
	}
	for i := range handles {
		handle := handles[i]
		if handle == LIBKERNEL_HANDLE || handle == LIBC_HANDLE {
			continue
		}
		info, err := DynlibGetInfo(handle)
		if err != 0 {
			panic(err)
		}
		// check name and stuff "libSceSysmodule.sprx"
		if bytes.HasPrefix(info.name[:], cname) {
			return uintptr(handle)
		}
	}
	return 0
}

// uintptr sceSysmoduleLoadModuleInternal(uint32_t);
func loadModuleInternal(id uintptr, name string) uintptr {
	res, _, _ := sceSysmoduleLoadModuleByNameInternal.Call(id)
	if int(res) == -1 {
		return 0
	}
	return findLoadedPrx(name)
}

// int sceSysmoduleLoadModuleByNameInternal(const char *fname, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
func loadModuleByNameInternal(name string) uintptr {
	cname, err := BytePtrFromString(name)
	if err != nil {
		return 0
	}
	res, _, _ := sceSysmoduleLoadModuleByNameInternal.Call(uintptr(unsafe.Pointer(cname)), 0, 0, 0, 0, 0)
	if int(res) == -1 {
		return 0
	}
	return findLoadedPrx(name)
}

func GetInternalPrxId(name string) uintptr {
	if !strings.HasSuffix(name, ".sprx") {
		name += ".sprx"
	}
	id, ok := internalPrx[name]
	if ok {
		return id
	}
	return 0
}

// LoadPrx loads the named prx file into memory.
func LoadPrx(name string) *Prx {
	handle := findLoadedPrx(name)
	if handle == 0 {
		id, ok := internalPrx[name]
		if ok {
			handle = loadModuleInternal(id, name)
		} else {
			handle = loadModuleByNameInternal(name)
		}
		if handle == 0 {
			return nil
		}
	}
	return &Prx{Name: name, Handle: handle}
}

// MustLoadPrx is like LoadPrx but panics if load operation fails.
func MustLoadPrx(name string) *Prx {
	d := LoadPrx(name)
	if d == nil {
		panic("Failed to load prx " + name)
	}
	return d
}

// FindProc searches Prx d for procedure named name and returns *Proc
// if found. It returns an error if search fails.
func (d *Prx) FindProc(name string) (proc *Proc, err error) {
	a := dlsym(d.Handle, name)
	if a == 0 {
		return nil, &PrxError{
			Err:     nil,
			ObjName: name,
			Msg:     "Failed to find " + name + " procedure in " + d.Name,
		}
	}
	p := &Proc{
		Prx:  d,
		Name: name,
		addr: a,
	}
	return p, nil
}

// MustFindProc is like FindProc but panics if search fails.
func (d *Prx) MustFindProc(name string) *Proc {
	p, e := d.FindProc(name)
	if e != nil {
		panic(e)
	}
	return p
}

// Release unloads Prx d from memory.
func (d *Prx) Release() (err error) {
	//return FreeLibrary(d.Handle)
	return nil
}

// A Proc implements access to a procedure inside a Prx.
type Proc struct {
	Prx  *Prx
	Name string
	addr uintptr
}

// Addr returns the address of the procedure represented by p.
// The return value can be passed to Syscall to run the procedure.
func (p *Proc) Addr() uintptr {
	return p.addr
}

// Call executes procedure p with arguments a.
//
// The returned error is always non-nil, constructed from the result of GetLastError.
// Callers must inspect the primary return value to decide whether an error occurred
// (according to the semantics of the specific function being called) before consulting
// the error. The error always has type syscall.Errno.
//
// On amd64, Call can pass and return floating-point values. To pass
// an argument x with C type "float", use
// uintptr(math.Float32bits(x)). To pass an argument with C type
// "double", use uintptr(math.Float64bits(x)). Floating-point return
// values are returned in r2. The return value for C type "float" is
// math.Float32frombits(uint32(r2)). For C type "double", it is
// math.Float64frombits(uint64(r2)).
//
//go:uintptrescapes
func (p *Proc) Call(a ...uintptr) (uintptr, uintptr, error) {
	return SyscallN(p.Addr(), a...)
}

//go:uintptrescapes
func doDlsym(handle uintptr, name uintptr, addr uintptr) {
	SyscallN(runtime.GetDlsym(), handle, name, addr)
}

func dlsym(handle uintptr, name string) uintptr {
	cname, err := BytePtrFromString(name)
	if err != nil {
		return 0
	}

	var addr uintptr = 0
	doDlsym(handle, uintptr(unsafe.Pointer(cname)), uintptr(unsafe.Pointer(&addr)))
	return addr
}

// A LazyPrx implements access to a single Prx.
// It will delay the load of the Prx until the first
// call to its Handle method or to one of its
// LazyProc's Addr method.
//
// LazyPrx is subject to the same Prx preloading attacks as documented
// on LoadPrx.
//
// Use LazyPrx in golang.org/x/sys/windows for a secure way to
// load system Prxs.
type LazyPrx struct {
	mu   sync.Mutex
	dll  *Prx // non nil once Prx is loaded
	Name string
}

type PrxLoadError struct {
	Name string
}

func (err *PrxLoadError) Error() string {
	return "failed to load prx " + err.Name
}

// Load loads Prx file d.Name into memory. It returns an error if fails.
// Load will not try to load Prx, if it is already loaded into memory.
func (d *LazyPrx) Load() error {
	// Non-racy version of:
	// if d.dll == nil {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.dll))) == nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.dll == nil {
			dll := LoadPrx(d.Name)
			if dll == nil {
				return &PrxLoadError{d.Name}
			}
			// Non-racy version of:
			// d.dll = dll
			atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.dll)), unsafe.Pointer(dll))
		}
	}
	return nil
}

// mustLoad is like Load but panics if search fails.
func (d *LazyPrx) mustLoad() {
	e := d.Load()
	if e != nil {
		panic(e)
	}
}

// Handle returns d's module handle.
func (d *LazyPrx) Handle() uintptr {
	d.mustLoad()
	return uintptr(d.dll.Handle)
}

// NewProc returns a LazyProc for accessing the named procedure in the Prx d.
func (d *LazyPrx) NewProc(name string) *LazyProc {
	return &LazyProc{l: d, Name: name}
}

// NewLazyPrx creates new LazyPrx associated with Prx file.
func NewLazyPrx(name string) *LazyPrx {
	return &LazyPrx{Name: name}
}

// A LazyProc implements access to a procedure inside a LazyPrx.
// It delays the lookup until the Addr, Call, or Find method is called.
type LazyProc struct {
	mu   sync.Mutex
	Name string
	l    *LazyPrx
	proc *Proc
}

// Find searches Prx for procedure named p.Name. It returns
// an error if search fails. Find will not search procedure,
// if it is already found and loaded into memory.
func (p *LazyProc) Find() error {
	// Non-racy version of:
	// if p.proc == nil {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.proc))) == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.proc == nil {
			e := p.l.Load()
			if e != nil {
				return e
			}
			proc, e := p.l.dll.FindProc(p.Name)
			if e != nil {
				return e
			}
			// Non-racy version of:
			// p.proc = proc
			atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.proc)), unsafe.Pointer(proc))
		}
	}
	return nil
}

// mustFind is like Find but panics if search fails.
func (p *LazyProc) mustFind() {
	e := p.Find()
	if e != nil {
		panic(e)
	}
}

// Addr returns the address of the procedure represented by p.
// The return value can be passed to Syscall to run the procedure.
func (p *LazyProc) Addr() uintptr {
	p.mustFind()
	return p.proc.Addr()
}

// Call executes procedure p with arguments a. See the documentation of
// Proc.Call for more information.
//
//go:uintptrescapes
func (p *LazyProc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	p.mustFind()
	return p.proc.Call(a...)
}

// SetAddr sets the procedure address for functions which cannot be
// resolved using dlsym.
func (p *LazyProc) SetAddr(addr uintptr) {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.proc))) != nil {
		panic("Address for procedure " + p.Name + " has already been set")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.proc)), unsafe.Pointer(addr))
}
