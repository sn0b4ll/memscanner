import binascii
import cmd
import ctypes as c
import datetime
import sys
import re

from ctypes import wintypes as w
from ctypes.wintypes import WORD, DWORD, LPVOID
from struct import *
from time import *

# Prepare
PVOID = LPVOID
SIZE_T = c.c_size_t
DWORD_PTR = c.c_ulonglong

# Prepare return objects
class SYSTEM_INFO(c.Structure):
        """https://msdn.microsoft.com/en-us/library/ms724958"""
        class _U(c.Union):
            class _S(c.Structure):
                _fields_ = (('wProcessorArchitecture', WORD),
                            ('wReserved', WORD))
            _fields_ = (('dwOemId', DWORD), # obsolete
                        ('_s', _S))
            _anonymous_ = ('_s',)
        _fields_ = (('_u', _U),
                    ('dwPageSize', DWORD),
                    ('lpMinimumApplicationAddress', LPVOID),
                    ('lpMaximumApplicationAddress', LPVOID),
                    ('dwActiveProcessorMask',   DWORD_PTR),
                    ('dwNumberOfProcessors',    DWORD),
                    ('dwProcessorType',         DWORD),
                    ('dwAllocationGranularity', DWORD),
                    ('wProcessorLevel',    WORD),
                    ('wProcessorRevision', WORD))
        _anonymous_ = ('_u',)
    
class MEMORY_BASIC_INFORMATION(c.Structure):
    """https://msdn.microsoft.com/en-us/library/aa366775"""
    _fields_ = (('BaseAddress', PVOID),
                ('AllocationBase',    PVOID),
                ('AllocationProtect', DWORD),
                ('RegionSize', SIZE_T),
                ('State',   DWORD),
                ('Protect', DWORD),
                ('Type',    DWORD))

# Define process id
pid = 4768

# Load the windows kernel
k32 = c.windll.kernel32

# Prepare OpenProcess
# https://msdn.microsoft.com/de-de/library/windows/desktop/ms684320(v=vs.85).aspx
OpenProcess = k32.OpenProcess
OpenProcess.argtypes = [w.DWORD,w.BOOL,w.DWORD]
OpenProcess.restype = w.HANDLE

# Prepate ReadProcessMemory
# https://msdn.microsoft.com/de-de/library/windows/desktop/ms680553(v=vs.85).aspx
ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes = [w.HANDLE,w.LPCVOID,w.LPVOID,c.c_size_t,c.POINTER(c.c_size_t)]
ReadProcessMemory.restype = w.BOOL

# Prepare WriteProcessMemory
# https://msdn.microsoft.com/de-de/library/windows/desktop/ms681674(v=vs.85).aspx
WriteProcessMemory = k32.WriteProcessMemory
WriteProcessMemory.argtypes = [w.HANDLE,w.LPVOID,w.LPCVOID,c.c_size_t,c.POINTER(c.c_size_t)]
WriteProcessMemory.restype = w.BOOL


# Execute OpenProcess
PAA = 0x1F0FFF # dwDesiredAccess = ALL_ACCESS
ph = OpenProcess(PAA,False,int(pid)) #program handle

# Prepare result_list
address_buffer = []

def search_value(value):
    """
    Search all private and mapped pages for values
    """
    
    # Get the pages
    pages = get_pages(state="0x1000", type="0x20000")

    # Transfer 
    
    
    # TODO(Rewrite to search in whole page)
    print("Searched value: {}".format(value))
    
    # Fix padding
    if (len(value))%2 != 0:
        value = "0" + value
    
    value_bytes = []
    for i in range(len(value), 0, -2):
        value_bytes.append(value[i-2:i])
        
    print(value_bytes)
    
    # Timing
    overall_start_time = time()
    
    # Prepare result_list
    result_list = []
    
    for page in pages:
        start_address = page.BaseAddress
        end_address = page.BaseAddress + page.RegionSize
        
        # Prepare memory reading
        word_size = page.RegionSize
        buff = c.create_string_buffer(word_size)
        bufferSize = (c.sizeof(buff))
        bytesRead = c.c_ulong(0)
        
        # for address in range(start_address,end_address, word_size):
        read_start_time = time()
        
        # Read the page
        ReadProcessMemory(
            ph, c.c_void_p(start_address), buff, bufferSize, c.byref(bytesRead)
        )
        
        read_end_time = time()
        
        # Convert raw buff
        convert_start_time = time()
        
        tmp = []
        for elem in buff:
            tmp.append(binascii.hexlify(elem).decode('utf-8'))
        buff = tmp
        
        convert_end_time = time()
                
        # Search the current page for elements
        search_start_time = time()
        
        ## Get all the offsets by searching the first time
        offsets = [i for i, x in enumerate(buff) if x == value_bytes[0]]
        
        ## For every byte word (to scale with larger searches)
        for bytes in range(1, len(value_bytes)):
            for offset in offsets:
                try:
                    if (
                        start_address + offset + 1 < end_address and 
                        buff[offset+1] == value_bytes[bytes]
                        ):
                        print("{:08X}: {} {}".format(
                                start_address + offset, 
                                buff[offset], 
                                buff[offset+1]
                            )
                        )
                        result_list.append(start_address + offset)
                except IndexError as e:
                    print("Error Accessing: {:02X}+1".format(start_address + offset))
                    print(e)
                    return
                    
    return result_list

def recheck_value(addresses_list, value):

    # Debgug
    # print(addresses_list)

    # Fix padding
    if (len(value))%2 != 0:
        value = "0" + value
    
    value_bytes = []
    for i in range(len(value), 0, -2):
        value_bytes.append(value[i-2:i])
        
    print(value_bytes)
    
    # Prepare list
    still_matching = []
    
    # Prepare memory read
    word_size = 2
        
    for address in addresses_list:
        buff = c.create_string_buffer(word_size)
        bufferSize = (c.sizeof(buff))
        bytesRead = c.c_ulong(0)
        
        # Read the address
        ReadProcessMemory(
            ph, c.c_void_p(address), buff, bufferSize, c.byref(bytesRead)
        )
        
        tmp = []
        for elem in buff:
            tmp.append(binascii.hexlify(elem).decode('utf-8'))
        buff = tmp
        
        # print(buff)
        if buff == value_bytes:
            still_matching.append(address)
    
    return still_matching

def write(address, value):
    data = value.encode('utf-8')
    
    buffer = c.create_string_buffer(data)
    sizeWriten = c.c_size_t(0)
    bufferSize = c.sizeof(buffer) - 1
    
    res = WriteProcessMemory(
        ph, address, buffer, bufferSize, c.byref(sizeWriten)
    )
    
    print(res)

def get_pages(state="0x0", type="0x0"):
    """
    Get all memory pages.
    
    If type is defined, filter accordingly.
    """
    
    # Get system info
    sysinfo = SYSTEM_INFO()
    
    # Pull the base address and correct to 0 if none
    base_address = sysinfo.lpMinimumApplicationAddress
    if base_address == None:
        base_address = 0x0
        
    # Prepare list for return
    pages = []

    # You have to strt somewhere
    current_region = get_page_info(base_address) 
    
    # Walk through the pages
    while current_region.RegionSize != 0:
        try:
            # Get the page info for the current base address
            current_region = get_page_info(base_address)
            
            if state == "0x0" and type == "0x0":
                # Add the current page since there is no filtering
                pages.append(current_region)
            elif state != "0x0" and type != "0x0":
                # Only "COMMITED" pages aka. used
                region_state = "0x{:02X}".format(current_region.State)
                region_type = "0x{:02X}".format(current_region.Type)
                if state == region_state and type == region_type:
                    pages.append(current_region)
            # TODO(Other cases or make nicer...)
            
            
        except c.ArgumentError as e:
            print(e)
            break;

        # Increase base address
        base_address += current_region.RegionSize
        
    return pages

def get_page_info(base_address: int)->MEMORY_BASIC_INFORMATION:    
    """
    Get MEMORY_BASIC_INFORMATION for a given base_address.
    """
    mbi = MEMORY_BASIC_INFORMATION()
    virtual_query_ex = k32.VirtualQueryEx(ph, base_address, c.byref(mbi),c.sizeof(mbi)) 
    
    return mbi

def _print_page_info(mbi: MEMORY_BASIC_INFORMATION)->None:
    """
    Print the contents of an given mbi.
    """
    print("BaseAddress:\t\t0x{:012X}".format(
        mbi.BaseAddress if mbi.BaseAddress != None else 0)
    )
    print("AllocationBase:\t\t0x{:012X}".format(
        mbi.AllocationBase if mbi.AllocationBase != None else 0)
    )
    print("AllocationProtect:\t" + __protect_to_string(mbi.AllocationProtect))
    print("RegionSize:\t\t{}".format(mbi.RegionSize))
    print("State:\t\t\t{}".format(__state_to_string(mbi.State)))
    print("Protect:\t\t" + __protect_to_string(mbi.Protect))
    print("Type:\t\t\t{}".format(__type_to_string(mbi.Type))) # TODO(Go on here)

def _print_value_for_address(address: int)->None:
    """Print the word residing at the given address."""
    
    word_size = 4
    buff = c.create_string_buffer(word_size)
    bufferSize = (c.sizeof(buff))
    bytesRead = c.c_ulong(0)
    
    ReadProcessMemory(ph, c.c_void_p(address), buff, bufferSize, c.byref(bytesRead))
    values = b' '.join([binascii.hexlify(i) for i in buff]).decode("utf-8")
    
    print(
        "{:08X}: {}".format(
            address, 
            values
        )
    )

def _get_value_for_address(address: int)->None:
    """Print the word residing at the given address."""
    
    word_size = 2
    buff = c.create_string_buffer(word_size)
    bufferSize = (c.sizeof(buff))
    bytesRead = c.c_ulong(0)
    
    ReadProcessMemory(ph, c.c_void_p(address), buff, bufferSize, c.byref(bytesRead))
    values = b' '.join([binascii.hexlify(i) for i in buff]).decode("utf-8")
    
    return values

def __protect_to_string(protect):
    """
    Convert the protect hex value of the mempage to string.
    """
    mem_page_protect = "0x{:02X}".format(protect)
    if mem_page_protect == "0x01":
        mem_page_protect = "----"
    elif mem_page_protect == "0x02":
        mem_page_protect = "R---"
    elif mem_page_protect == "0x04":
        mem_page_protect = "RW--"
    elif mem_page_protect == "0x08":
        mem_page_protect = "-W-C"
    elif mem_page_protect == "0x10":
        mem_page_protect = "--X-"
    elif mem_page_protect == "0x20":
        mem_page_protect == "R-X-"
    elif mem_page_protect == "0x40":
        mem_page_protect = "RWX-"
    elif mem_page_protect == "0x80":
        mem_page_protect = "-WXC"
    
    return mem_page_protect
    
def __state_to_string(state):
    """
    Convert memory page state hex to string.
    """
    state = "0x{:02X}".format(state)
    if state == "0x1000":
        return "MEM_COMMIT"
    elif state == "0x10000":
        return "MEM_FREE"
    elif state == "0x2000":
        return "MEM_RESERVE"
    else:
        print(type)
        return state

def __type_to_string(type):
    """
    Convert the type of a page to string.
    """
    type = "0x{:02X}".format(type)
    if type == "0x1000000":
        return "MEM_IMAGE"
    elif type == "0x40000":
        return "MEM_MAPPED"
    elif type == "0x20000":
        return "MEM_PRIVATE"
    else:
        return type
    
def read_memory(start_address, end_address):
    # Start reading from process
    # start_address   = 0x740000 # start address
    # end_address     = 0x740100 # end address

    word_size = 2
    buff = c.create_string_buffer(word_size)
    bufferSize = (c.sizeof(buff))
    bytesRead = c.c_ulong(0)

    addresses_list = range(start_address,end_address, word_size)
    for address in addresses_list:
        ReadProcessMemory(ph, c.c_void_p(address), buff, bufferSize, c.byref(bytesRead))
        values = b' '.join([binascii.hexlify(i) for i in buff]).decode("utf-8")
        #print('0x{:08x}: {}'.format(address, values))
    
class Interface(cmd.Cmd):
    """Smal script to scan and alter application memory."""
    
    def do_set_pid(self, line):
        """set_pid [PID]
        Set the correct process id."""
        print("hello" + line)
    
    def do_new(self, line):
        """new [hex-value]
        Search the memory for a value"""
        global address_buffer
        address_buffer = search_value(line)
        print(address_buffer)
        
    def do_read(self, line):
        _print_value_for_address(int(line, 16))
        
    def do_write(self, line): # TODO(Wo ist es hin??)
        """write address value
        Write the value to address."""
        args = line.split(' ')
        write(args[0], args[1])
        print("[+] Successfully wrote value to address.")
        _print_value_for_address(args[0])
        
    def do_next(self, line):
        global address_buffer
        
        address_buffer = recheck_value(address_buffer, line)
        for address in address_buffer:
            _print_value_for_address(address)
        
    def do_rescan(self, line):
        print("hello" + line)
        
    def do_show_selected(self, line):
        for address in address_buffer:
            _print_value_for_address(address)
        
    def do_change_selected(self, id, line):
        print("hello" + line + id)
    
    def do_exit(self, line):
        return True

if __name__ == '__main__':
    Interface().cmdloop()
