import os
import shutil
import socket
import sys
import json

from qiling import *
from capstone import *
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

CONFIG = {}

class Emulate:
    def __init__(self, file):
        if not os.path.exists(file):
            raise Exception(f"File {file} does not exist!")
        self.file = os.path.abspath(file)


    @staticmethod
    @winsdkapi(cc=STDCALL, params={
        'Destination': LPVOID,
        'Length': SIZE_T
    })
    def hook_RtlZeroMemory(ql, address, params):
        if params.get('Destination'):
            dest = params['Destination']
        else:
            raise Exception('RtlZeroMemory hook failed! Destination not found in params.')

        if params.get('Length'):
            length = params['Length']
        else:
            raise Exception('RtlZeroMemory hook failed! Length not found in params.')

        # Zero out the memory
        ql.mem.write(dest, b'\x00' * length)

        # RtlZeroMemory doesn't return a value
        return 0


    @staticmethod
    @winsdkapi(cc=STDCALL, params={
        'af': INT,
        'type': INT,
        'protocol': INT
    })
    def hook_socket(ql, address, params):
        # Create a fake socket handle and ret
        fake_socket = 0x1000
        return fake_socket


    @staticmethod
    @winsdkapi(cc=STDCALL, params={
        'hostshort': WORD
    })
    def hook_htons(ql, address, params):
        if params.get('hostshort'):
            hostshort = params['hostshort']
        else:
            raise Exception('htons hook failed! hostshort not found in params.')

        # Convert host byte order to network byte order (big-endian)
        netshort = ((hostshort & 0xFF) << 8) | ((hostshort & 0xFF00) >> 8)

        return netshort


    @staticmethod
    @winsdkapi(cc=STDCALL, params={
        'cp': STRING
    })
    def hook_inet_addr_v2(ql, address, params):
        if params.get('cp'):
            ip_string = params['cp']
        else:
            raise Exception('inet_addr hook failed! cp not found in params.')

        # Use Python's socket library to convert
        packed = socket.inet_aton(ip_string)
        result = int.from_bytes(packed, byteorder='big')
        return result


    @staticmethod
    @winsdkapi(cc=STDCALL, params={
        's': SOCKET,
        'name': POINTER,
        'namelen': INT
    })
    def hook_connect(ql, address, params):
        if params.get('name'):
            sockaddr = params['name']
        else:
            raise Exception('connect hook failed! name not found in params.')

        # Read sockaddr structure
        # Read the 32-bit IP address as stored in memory
        ip_dword = int.from_bytes(ql.mem.read(sockaddr + 4, 4), 'little')

        # Extract octets from the DWORD (reverse order due to little-endian)
        octet4 = ip_dword & 0xFF
        octet3 = (ip_dword >> 8) & 0xFF
        octet2 = (ip_dword >> 16) & 0xFF
        octet1 = (ip_dword >> 24) & 0xFF

        # Build IP string from octets
        ip_str = f"{octet1}.{octet2}.{octet3}.{octet4}"

        # Read port (network byte order - big-endian)
        port = int.from_bytes(ql.mem.read(sockaddr + 2, 2), 'big')

        # Made a global temp config to ret these values as I can't pass additional args, self_obj, or ret from this in a clean way
        CONFIG["C2"] = (f"{ip_str}")
        CONFIG["Port"] = (f"{port}")

        # Stop emulation
        ql.emu_stop()


    def run_emu(self, rootfs_file):

        # Init the Qiling object with multithreading
        ql = Qiling([rootfs_file], rootfs=r"./rootfs/x8664_windows", archtype=QL_ARCH.X8664, ostype=QL_OS.WINDOWS, verbose=QL_VERBOSE.DISABLED, multithread=True)

        # Set hooks for other functions
        ql.os.set_api('connect', self.hook_connect, QL_INTERCEPT.CALL)
        ql.os.set_api('RtlZeroMemory', self.hook_RtlZeroMemory, QL_INTERCEPT.CALL)
        ql.os.set_api('socket', self.hook_socket, QL_INTERCEPT.CALL)
        ql.os.set_api('htons', self.hook_htons, QL_INTERCEPT.CALL)
        ql.os.set_api('inet_addr', self.hook_inet_addr_v2, QL_INTERCEPT.CALL)

        # Emulate it
        ql.run()


    def main(self):
        # Qiling throws a GetModuleFileNameA error if we don't copy the file to the rootfs
        rootfs_file = f"./rootfs/x8664_windows/Temp/sample.exe"
        shutil.copyfile(self.file, rootfs_file)

        try:
            self.run_emu(rootfs_file)

            # cleanup temp file
            os.remove(rootfs_file)
        except:
            # cleanup temp file
            os.remove(rootfs_file)



if __name__ == '__main__':
    file = sys.argv[1]
    emulator = Emulate(file_path)
    emulator.main()
    print(json.dumps(CONFIG, indent=4))
