from ctypes import *
import os

### Setting the necessary vars and structs
LPVOID = c_void_p
HANDLE = LPVOID
DWORD = c_uint32
WORD = c_uint16
UINT = c_uint
INVALID_HANDLE_VALUE = c_void_p(-1).value
LONG = c_long

PROCESS_VM_READ = 0x0010
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

MEM_PRIVATE = 0x20000
MEM_COMMIT = 0x1000

PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES),
    ]

class SYSTEM_INFO(Structure):
    _fields_ = [("wProcessorArchitecture", WORD),
                ("wReserved", WORD),
                ("dwPageSize", DWORD),
                ("lpMinimumApplicationAddress", DWORD),
                ("lpMaximumApplicationAddress", DWORD),
                ("dwActiveProcessorMask", DWORD),
                ("dwNumberOfProcessors", DWORD),
                ("dwProcessorType", DWORD),
                ("dwAllocationGranularity", DWORD),
                ("wProcessorLevel", WORD),
                ("wProcessorRevision", WORD)]

class MEMORY_BASIC_INFORMATION (Structure):

    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", DWORD),
        ("RegionSize", UINT),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)
        ]

def EnablePrivilege(privilegeStr, hToken = None):
    """Enable Privilege on token, if no token is given the function gets the token of the current process."""
    if hToken == None:
        TOKEN_ADJUST_PRIVILEGES = 0x00000020
        TOKEN_QUERY = 0x0008
        hToken = HANDLE(INVALID_HANDLE_VALUE)
        windll.advapi32.OpenProcessToken(windll.kernel32.GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken) )
    
    privilege_id = LUID()
    windll.advapi32.LookupPrivilegeValueA(None, privilegeStr, byref(privilege_id))

    SE_PRIVILEGE_ENABLED = 0x00000002
    laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
    tp  = TOKEN_PRIVILEGES(1, laa)
    
    windll.advapi32.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None)


def scan_pids(proc_name):
    """Get a list of every pid, and check the basename of the process, return if it is proc_name"""
    count = 32
    while True:
        ProcessIds = ( DWORD * count)()
        cb = sizeof( ProcessIds )
        BytesReturned = DWORD()
        if windll.psapi.EnumProcesses( byref(ProcessIds), cb, byref(BytesReturned)):
            if BytesReturned.value < cb:
                break
            else:
                count *= 2
        
    for index in range(BytesReturned.value / sizeof( DWORD ) ):
        ProcessId = ProcessIds[index]
        hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, ProcessId)
        if hProcess:
            ImageFileName = ( c_char * 260 )()
            if windll.psapi.GetProcessImageFileNameA(hProcess, ImageFileName, 260) > 0:
                filename = os.path.basename(ImageFileName.value)
                if filename == proc_name:
                    windll.kernel32.CloseHandle(hProcess)
                    return ProcessId
            windll.kernel32.CloseHandle(hProcess) 


### THE INTERESTING PART ###
## The pid of the process we are going to scan.
proc_name = "notepad++.exe"
print "[+]Scanning processes"
print "\t[+]Process to scan for: " + proc_name

pid = scan_pids( proc_name )
print "\t[+]Found pid: " + str( pid )

## Get the min and max scan address.
print "[+]Retrieving scan range"
si = SYSTEM_INFO()
windll.kernel32.GetSystemInfo( byref( si ) )

addr = si.lpMinimumApplicationAddress
maxaddr = si.lpMaximumApplicationAddress

print "\t[+]Scan range: " + str( hex( addr ) ) + " - " + str( hex( maxaddr ) )


## Give this process SeDebugPrivilege
print "[+]Enabling 'SeDebugPrivilege'"
EnablePrivilege("SeDebugPrivilege")

## Open the process
print "[+]Opening the process"
hProcess = windll.kernel32.OpenProcess( PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, 0, pid )

print "[+]Start scanning"
while addr < maxaddr:
    MBI = MEMORY_BASIC_INFORMATION ()
    windll.kernel32.VirtualQueryEx (hProcess, addr, byref( MBI ), sizeof( MBI ))

## The new addr that will be scanned 
    addr += MBI.RegionSize
    
    if MBI.Type == MEM_PRIVATE and MBI.State == MEM_COMMIT and MBI.Protect in ( PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE ):
        print "\t[+]Found useful memory address: " + str( hex( MBI.BaseAddress ) ) + " | Region Size: " + str ( MBI.RegionSize / 1024) + "KB"

        cbuffer = c_buffer(MBI.RegionSize)
        windll.kernel32.ReadProcessMemory( hProcess, MBI.BaseAddress, cbuffer, MBI.RegionSize, 0 )

        data = cbuffer.raw

        if "Testing please" in data:
            print "Found: " + str( MBI.BaseAddress )

windll.kernel32.CloseHandle( hProcess )
