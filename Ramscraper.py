from ctypes import *
import re

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

### THE INTERESTING PART ###

## The pid of the process we are going to scan. 
pid = 9248

## Get the min and max scan address.  
si = SYSTEM_INFO()
windll.kernel32.GetSystemInfo( byref( si ) )

addr = si.lpMinimumApplicationAddress
maxaddr = si.lpMaximumApplicationAddress

## Give this process SeDebugPrivilege
EnablePrivilege("SeDebugPrivilege")

## Open the process
hProcess = windll.kernel32.OpenProcess( PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, 0, pid )

while addr < maxaddr:

    MBI = MEMORY_BASIC_INFORMATION ()
    windll.kernel32.VirtualQueryEx (hProcess, addr, byref( MBI ), sizeof( MBI ))

## The new addr that will be scanned 
    addr += MBI.RegionSize

    if MBI.Type == MEM_PRIVATE and MBI.State == MEM_COMMIT and MBI.Protect in ( PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE ):
        
        cbuffer = c_buffer(MBI.RegionSize)
        windll.kernel32.ReadProcessMemory( hProcess, MBI.BaseAddress, cbuffer, MBI.RegionSize, 0 )

        data = cbuffer.raw

## Test the data for something, this is a very simple regex example. It cheks for 16 digits.
        match = re.search(r"\d{16", data)
        if match:
            print match.group(0)

windll.kernel32.CloseHandle( hProcess )

