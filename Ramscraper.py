from time import sleep
from ctypes import *

### Setting the necessary vars and structs
LPVOID = c_void_p
HANDLE = LPVOID
DWORD = c_uint32
WORD = c_uint16
UINT = c_uint
INVALID_HANDLE_VALUE = c_void_p(-1).value
LONG = c_long

TOKEN_ADJUST_PRIVILEGES = 0x00000020
TOKEN_QUERY = 0x0008

SE_PRIVILEGE_ENABLED = 0x00000002

PROCESS_VM_READ = 0x0010
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400

MEM_PRIVATE = 0x20000
MEM_COMMIT = 0x1000

PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

TH32CS_SNAPPROCESS = 0x00000002

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

class PROCESSENTRY32(Structure):
     _fields_ = [("dwSize", c_ulong),
                 ("cntUsage", c_ulong),
                 ("th32ProcessID", c_ulong),
                 ("th32DefaultHeapID", c_ulong),
                 ("th32ModuleID", c_ulong),
                 ("cntThreads", c_ulong),
                 ("th32ParentProcessID", c_ulong),
                 ("pcPriClassBase", c_ulong),
                 ("dwFlags", c_ulong),
                 ("szExeFile", c_char * 260)]

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

def check_buffer( buffer ):
    """Test function to test the buffer, this function could contain anything. 
       You could easily do something with regular expressions."""
    
    if "teststring" in buffer:
        print "Found!"
        return True
    return False

def Processis64( hProcess ):
    """From MSDN: 
        a value that is set to TRUE if the process is running under WOW64. 
        If the process is running under 32-bit Windows, the value is set to FALSE. 
        If the process is a 64-bit application running under 64-bit Windows, the value is also set to FALSE"""

    pis64 = c_bool()
    windll.kernel32.IsWow64Process(hProcess, byref( pis64 ) ) 
    
    return pis64.value

def scan_memory( ):
    """Scan the memory of every process except some predefined processes."""
    print "START SCANNING"
    readlimit = 100*4096
    
    skip = ("svchost.exe", "iexplore.exe", "explorer.exe", "System",
            "smss.exe", "csrss.exe", "winlogon.exe", "lsass.exe",
            "spoolsv.exe", "alg.exe", "wuauclt.exe", "wininit.exe",
            "services.exe", "lsm.exe", "audiodg.exe", "dllhost.exe",
            "conhost.exe", "igfxsrvc.exe", "SearchFilterHost.exe",
            "SearchFilterHost.exe", "wmpnetwk.exe", "SearchIndexer.exe",
            "SearchProtocolHost.exe", "WUDFHost.exe", "dwm.exe", "LogonUI.exe")
    
    hSnap = windll.kernel32.CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 )
    
    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof( PROCESSENTRY32 )

    ## The first pid i == 0 (System)
    windll.kernel32.Process32First( hSnap, byref( pe32 ) )

    ownpid= windll.kernel32.GetCurrentProcessId()
    print "PID current process: " + str( ownpid )

    print "Enumerating processes"
    while True:
        if windll.kernel32.Process32Next( hSnap, byref( pe32 ) ) == 0:
            break
        
        name = pe32.szExeFile
        pid = pe32.th32ProcessID
        
        
        print "\tName: " + str( name ) + " | PID: " + str( pid )
        if not name in skip and pid != ownpid:
            print "\t\tScanning: "
            ## Open the process
            hProcess = windll.kernel32.OpenProcess( PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, 0, pid )
            
            addr =  c_long(0)

            while True:
                MBI = MEMORY_BASIC_INFORMATION()
                windll.kernel32.VirtualQueryEx( hProcess, addr.value, byref( MBI ), sizeof( MBI ) )
               
                if ( addr.value != 0 and MBI.BaseAddress == None ) or (MBI.AllocationBase == None and not Processis64( hProcess ) ):
                    break
                
                ## The new addr that will be scanned 
                addr.value += MBI.RegionSize
                
                if MBI.Type == MEM_PRIVATE and MBI.State == MEM_COMMIT and MBI.Protect in ( PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE ):
                    #print "\t\tFound good region: " + str( MBI.BaseAddress )
                    ReadAddr = 0
                    while MBI.RegionSize > 0:
                        
                        if ReadAddr != 0:
                            ReadAddr += readlimit

                        else:
                            ReadAddr = MBI.BaseAddress

                        if MBI.RegionSize > readlimit:
                            BuffSize = readlimit
                            MBI.RegionSize -= readlimit

                        else:
                            BuffSize = MBI.RegionSize
                            MBI.RegionSize = 0

                        Buff = create_string_buffer( BuffSize )
                        windll.kernel32.ReadProcessMemory( hProcess, ReadAddr, Buff, BuffSize, 0 )

                        check_buffer( Buff.raw )

            windll.kernel32.CloseHandle( hProcess )

    windll.kernel32.CloseHandle( hSnap )
    
if __name__ == "__main__":
    EnablePrivilege( 'SeDebugPrivilege' )
    scan_memory()

