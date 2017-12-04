// Copyright © 2015-2017 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package yara provides bindings to the YARA library.
package yara

/*
#include <yara.h>

int stdScanCallback(int, void*, void*);
int customScanCallback(int, void*, void*);
*/
import "C"
import (
	"errors"
	"reflect"
	"runtime"
	"time"
	"unsafe"
)

// Rules contains a compiled YARA ruleset.
type Rules struct {
	*rules
}

type rules struct {
	cptr *C.YR_RULES
}

var dummy *[]MatchRule

// A MatchRule represents a rule successfully matched against a block
// of data.
type MatchRule struct {
	Rule      string
	Namespace string
	Tags      []string
	Meta      map[string]interface{}
	Strings   []MatchString
}

// A MatchString represents a string declared and matched in a rule.
type MatchString struct {
	Name   string
	Offset uint64
	Data   []byte
}

func init() {
	_ = C.yr_initialize()
}

//export newMatch
func newMatch(userData unsafe.Pointer, namespace, identifier *C.char) {
	matches := callbackData.Get(*(*uintptr)(userData)).(*[]MatchRule)
	*matches = append(*matches, MatchRule{
		Rule:      C.GoString(identifier),
		Namespace: C.GoString(namespace),
		Tags:      []string{},
		Meta:      map[string]interface{}{},
		Strings:   []MatchString{},
	})
}

//export addMetaInt
func addMetaInt(userData unsafe.Pointer, identifier *C.char, value C.int) {
	matches := callbackData.Get(*(*uintptr)(userData)).(*[]MatchRule)
	i := len(*matches) - 1
	(*matches)[i].Meta[C.GoString(identifier)] = int32(value)
}

//export addMetaString
func addMetaString(userData unsafe.Pointer, identifier *C.char, value *C.char) {
	matches := callbackData.Get(*(*uintptr)(userData)).(*[]MatchRule)
	i := len(*matches) - 1
	(*matches)[i].Meta[C.GoString(identifier)] = C.GoString(value)
}

//export addMetaBool
func addMetaBool(userData unsafe.Pointer, identifier *C.char, value C.int) {
	matches := callbackData.Get(*(*uintptr)(userData)).(*[]MatchRule)
	i := len(*matches) - 1
	(*matches)[i].Meta[C.GoString(identifier)] = bool(value != 0)
}

//export addTag
func addTag(userData unsafe.Pointer, tag *C.char) {
	matches := callbackData.Get(*(*uintptr)(userData)).(*[]MatchRule)
	i := len(*matches) - 1
	(*matches)[i].Tags = append((*matches)[i].Tags, C.GoString(tag))
}

//export addString
func addString(userData unsafe.Pointer, identifier *C.char, offset C.uint64_t, data unsafe.Pointer, length C.int) {
	ms := MatchString{
		Name:   C.GoString(identifier),
		Offset: uint64(offset),
		Data:   make([]byte, int(length)),
	}

	var tmpSlice []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&tmpSlice))
	hdr.Data = uintptr(data)
	hdr.Len = int(length)
	copy(ms.Data, tmpSlice)

	matches := callbackData.Get(*(*uintptr)(userData)).(*[]MatchRule)
	i := len(*matches) - 1
	(*matches)[i].Strings = append((*matches)[i].Strings, ms)
}

// ScanFlags are used to tweak the behavior of Scan* functions.
type ScanFlags int

const (
	// ScanFlagsFastMode avoids multiple matches of the same string
	// when not necessary.
	ScanFlagsFastMode = C.SCAN_FLAGS_FAST_MODE
	// ScanFlagsProcessMemory causes the scanned data to be
	// interpreted like live, in-prcess memory rather than an on-disk
	// file.
	ScanFlagsProcessMemory = C.SCAN_FLAGS_PROCESS_MEMORY
)

type ScanCallbackMessageType int

const (
	ScanRuleMatching    ScanCallbackMessageType = C.CALLBACK_MSG_RULE_MATCHING
	ScanRuleNotMatching                         = C.CALLBACK_MSG_RULE_NOT_MATCHING
	ScanImportModule                            = C.CALLBACK_MSG_IMPORT_MODULE
	ScanModuleImported                          = C.CALLBACK_MSG_MODULE_IMPORTED
	ScanFinished                                = C.CALLBACK_MSG_SCAN_FINISHED
)

var (
	ErrScanAbort = errors.New("Callback function requested abort")
	ErrScanError = errors.New("Callback function signalled error")
)

// ScanCallbackFunc is the type of the function that is used with the
// ScanFileCallback, ScanMemCallback, ScanProcCallback,
// ScanFileDescriptorCallback functions.
//
// The type of messageData depends on messageType: For
// ScanRuleMatching, ScanRuleNotMatching types, messageDaa is a Rule
// object. For ScanImportModule, messageData is a *ModuleImport. For
// ScanFinished, messageData is nil.
//
// For ScanModuleImported, messageData is a pointer to the
// YR_OBJECT_STRUCTURE provided by YARA. This is subject to change.
//
// The return value is used by YARA to determine how to continue the
// scan.
type ScanCallbackFunc func(messageType ScanCallbackMessageType, messageData interface{}) error

type ModuleImport struct {
	Name string
	buf  []byte
}

func callbackErrorCode(err error) C.int {
	if err == ErrScanAbort {
		return C.CALLBACK_ABORT
	} else if err != nil {
		return C.CALLBACK_ERROR
	}
	return C.CALLBACK_CONTINUE
}

//export customScanCallback
func customScanCallback(message C.int, messageData, userData unsafe.Pointer) C.int {
	callbackFn := callbackData.Get(*(*uintptr)(userData)).(ScanCallbackFunc)
	var data interface{}
	switch message {
	case C.CALLBACK_MSG_RULE_MATCHING, C.CALLBACK_MSG_RULE_NOT_MATCHING:
		data = Rule{(*C.YR_RULE)(messageData)}
	case C.CALLBACK_MSG_IMPORT_MODULE:
		mi := ModuleImport{
			Name: C.GoString((*C.YR_MODULE_IMPORT)(messageData).module_name)}
		if err := callbackFn(ScanCallbackMessageType(message), &mi); err != nil {
			return callbackErrorCode(err)
		}
		sz := C.size_t(len(mi.buf))
		(*C.YR_MODULE_IMPORT)(messageData).module_data_size = sz
		if sz > 0 {
			(*C.YR_MODULE_IMPORT)(messageData).module_data =
				C.malloc(C.size_t(len(mi.buf)))
			C.memcpy((*C.YR_MODULE_IMPORT)(messageData).module_data,
				unsafe.Pointer(&mi.buf[0]),
				sz)
		}
		return C.CALLBACK_CONTINUE
		// TODO: C.CALLBACK_MSG_MODULE_IMPORTED, handle *C.YR_OBJECT_STRUCTURE
	case C.CALLBACK_MSG_SCAN_FINISHED:
		fallthrough
	default:
		data = messageData
	}
	return callbackErrorCode(callbackFn(ScanCallbackMessageType(message), data))
}

// ScanMem scans an in-memory buffer with the ruleset. It returns a list of rules that matched.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	id := callbackData.Put(&matches)
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_mem(
		r.cptr,
		ptr,
		C.size_t(len(buf)),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.stdScanCallback),
		unsafe.Pointer(&id),
		C.int(timeout/time.Second)))
	keepAlive(r)
	return
}

// ScanMemCallback scans an in-memory buffer with the ruleset. Events
// such as matched rules are passed to callbackFn.
func (r *Rules) ScanMemCallback(buf []byte, flags ScanFlags, timeout time.Duration, callbackFn ScanCallbackFunc) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	id := callbackData.Put(callbackFn)
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_mem(
		r.cptr,
		ptr,
		C.size_t(len(buf)),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.customScanCallback),
		unsafe.Pointer(&id),
		C.int(timeout/time.Second)))
	keepAlive(r)
	return
}

// ScanFile scans a file with the ruleset. It returns a list of rules
// that matched.
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration) (matches []MatchRule, err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	id := callbackData.Put(&matches)
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_file(
		r.cptr,
		cfilename,
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.stdScanCallback),
		unsafe.Pointer(&id),
		C.int(timeout/time.Second)))
	keepAlive(r)
	return
}

// ScanFileCallback scans a file with the ruleset. Events such as
// matched rules are passed to callbackFn.
func (r *Rules) ScanFileCallback(filename string, flags ScanFlags, timeout time.Duration, callbackFn ScanCallbackFunc) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	id := callbackData.Put(callbackFn)
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_file(
		r.cptr,
		cfilename,
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.customScanCallback),
		unsafe.Pointer(&id),
		C.int(timeout/time.Second)))
	keepAlive(r)
	return
}

// ScanProc scans a live process with the ruleset. It returns a list
// of rules that matched.
func (r *Rules) ScanProc(pid int, flags int, timeout time.Duration) (matches []MatchRule, err error) {
	id := callbackData.Put(&matches)
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_proc(
		r.cptr,
		C.int(pid),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.stdScanCallback),
		unsafe.Pointer(&id),
		C.int(timeout/time.Second)))
	keepAlive(r)
	return
}

// ScanProcCallback scans a live process with the ruleset. Events such
// as matched rules are passed to callbackFn.
func (r *Rules) ScanProcCallback(pid int, flags int, timeout time.Duration, callbackFn ScanCallbackFunc) (err error) {
	id := callbackData.Put(callbackFn)
	defer callbackData.Delete(id)
	err = newError(C.yr_rules_scan_proc(
		r.cptr,
		C.int(pid),
		C.int(flags),
		C.YR_CALLBACK_FUNC(C.customScanCallback),
		unsafe.Pointer(&id),
		C.int(timeout/time.Second)))
	keepAlive(r)
	return
}

// Save writes a compiled ruleset to filename.
func (r *Rules) Save(filename string) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	err = newError(C.yr_rules_save(r.cptr, cfilename))
	keepAlive(r)
	return
}

// LoadRules retrieves a compiled ruleset from filename.
func LoadRules(filename string) (*Rules, error) {
	r := &Rules{rules: &rules{}}
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	if err := newError(C.yr_rules_load(cfilename,
		&(r.rules.cptr))); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(r.rules, (*rules).finalize)
	return r, nil
}

func (r *rules) finalize() {
	C.yr_rules_destroy(r.cptr)
	runtime.SetFinalizer(r, nil)
}

// Destroy destroys the YARA data structure representing a ruleset.
// Since a Finalizer for the underlying YR_RULES structure is
// automatically set up on creation, it should not be necessary to
// explicitly call this method.
func (r *Rules) Destroy() {
	if r.rules != nil {
		r.rules.finalize()
		r.rules = nil
	}
}

// DefineVariable defines a named variable for use by the compiler.
// Boolean, int64, float64, and string types are supported.
func (r *Rules) DefineVariable(name string, value interface{}) (err error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_rules_define_boolean_variable(
			r.cptr, cname, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_rules_define_integer_variable(
			r.cptr, cname, C.int64_t(value)))
	case float64:
		err = newError(C.yr_rules_define_float_variable(
			r.cptr, cname, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_rules_define_string_variable(
			r.cptr, cname, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	keepAlive(r)
	return
}

// GetRules returns a slice of rule objects that are part of the
// ruleset
func (r *Rules) GetRules() (rv []Rule) {
	for p := unsafe.Pointer(r.cptr.rules_list_head); (*C.YR_RULE)(p).g_flags&C.RULE_GFLAGS_NULL == 0; p = unsafe.Pointer(uintptr(p) + unsafe.Sizeof(*r.cptr.rules_list_head)) {
		rv = append(rv, Rule{(*C.YR_RULE)(p)})
	}
	return
}
