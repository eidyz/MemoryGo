package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/JamesHovious/w32"
	"reflect"
	"strings"
	"unsafe"
)

func reverseSlice(s interface{}) {
	size := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, size-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

func float32ToByte(f float32) []byte {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, f)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	bytes := buf.Bytes()
	reverseSlice(bytes)
	return bytes
}

// GetProcessName returns name of process given the processID
func GetProcessName(processID uint32) string {
	snapshot := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, processID)
	if snapshot == w32.ERROR_INVALID_HANDLE {
		return "<UNKNOWN>"
	}
	defer w32.CloseHandle(snapshot)

	var me w32.MODULEENTRY32
	me.Size = uint32(unsafe.Sizeof(me))
	if w32.Module32First(snapshot, &me) {
		return w32.UTF16PtrToString(&me.SzModule[0])
	}

	return "<UNKNOWN>"
}

func listProcesses() []uint32 {
	sz := uint32(1000)
	procs := make([]uint32, sz)
	var bytesReturned uint32
	if w32.EnumProcesses(procs, sz, &bytesReturned) {
		return procs[:int(bytesReturned)/4]
	}
	return []uint32{}
}

// FindProcessByName returns processID
func FindProcessByName(procName string) (uint32, error) {
	for _, processID := range listProcesses() {
		if getProcessName(processID) == procName {
			return processID, nil
		}
	}
	return 0, fmt.Errorf("couldn't find process with name %s", procName)
}

// GetModule returns specified module base address
func GetModule(moduleName string, processID uint32) (baseAdd uint32, err error) {
	hModuleSnap := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPMODULE, processID)

	if hModuleSnap < 0 {
		w32.CloseHandle(hModuleSnap)
		return 0, fmt.Errorf("failed to take a snapshot of modules")
	}

	var modEntry32 w32.MODULEENTRY32
	modEntry32.Size = (uint32)(unsafe.Sizeof(modEntry32))

	if w32.Module32First(hModuleSnap, &modEntry32) == true {
		if strings.EqualFold(w32.UTF16PtrToString(&modEntry32.SzModule[0]), moduleName) {
			w32.CloseHandle(hModuleSnap)
			return *(*uint32)(unsafe.Pointer(&modEntry32.ModBaseAddr)), nil
		}
	}

	for w32.Module32Next(hModuleSnap, &modEntry32) {
		if strings.EqualFold(w32.UTF16PtrToString(&modEntry32.SzModule[0]), moduleName) {
			w32.CloseHandle(hModuleSnap)
			return *(*uint32)(unsafe.Pointer(&modEntry32.ModBaseAddr)), nil
		}
	}

	w32.CloseHandle(hModuleSnap)

	return 0, fmt.Errorf("couldn't find specified module in snapshot of the process")
}

// GetProcessHandle returns the process handle
func GetProcessHandle(processID uint32) w32.HANDLE {
	handle, _ := w32.OpenProcess(w32.PROCESS_ALL_ACCESS, false, processID)
	return handle
}

// RW read write struct with some helper functions to convert values to other types
type RW struct {
	Value byte
}

// ToFloat32 converts value from Read() to float32 type
func (rw *RW) ToFloat32() float32 {
	return *(*float32)(unsafe.Pointer(&rw.Value))
}

// ToUint32 converts value from Read() to uint32 type
func (rw *RW) ToUint32() uint32 {
	return *(*uint32)(unsafe.Pointer(&rw.Value))
}

// ReadMemory reads value from memory to a RW struct so you can easily convert to other types
func ReadMemory(handle w32.HANDLE, offset uint32) RW {
	var size uintptr = 1
	pointer, _ := w32.ReadProcessMemory(handle, offset, uint(unsafe.Sizeof(&size)))
	return RW{pointer[0]}
}

// WriteMemory function which accepts uint32 or float32 as the value you want to write
func WriteMemory(handle w32.HANDLE, offset uint32, value interface{}) {
	switch value.(type) {
	case uint32:
		realValue := value.(uint32)
		w32.WriteProcessMemoryAsUint32(handle, offset, realValue)
	case float32:
		var size float32
		realValue := value.(float32)
		bytes := float32ToByte(realValue)
		w32.WriteProcessMemory(handle, offset, bytes, uint(unsafe.Sizeof(&size)))
	default:
		fmt.Errorf("Wrong type given, this function only accepts uint32 or float32 types")
	}
}
