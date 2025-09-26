import os
import pefile
from typing import Union

dll_names = []
dll_apis = []

MASK64 = (1 << 64) - 1

def _to_int8(b: int) -> int:
    """Interpret an 0..255 byte as signed int8 (-128..127)."""
    return b - 256 if b >= 128 else b

def mw_hash_func(value: Union[str, bytes], byte_length: int = None) -> int:
    """
    Python recreation of:
        result = 0xFFFFFFFFFFFFFFFFuLL;
        for (i = 0; i < Length; ++i)
            result ^= Length ^ (unsigned __int64)(result * ((char)Buffer[i] + 32));
        return result;
    """
    # If we got a Python str, encode like a Windows UNICODE_STRING buffer.
    if isinstance(value, str):
        data = value.encode('utf-16le')  # Windows UNICODE_STRING is UTF-16LE
    else:
        data = bytes(value)

    length = len(data) if byte_length is None else byte_length
    if length > len(data):
        raise ValueError("byte_length exceeds buffer size")

    result = 0xFFFFFFFFFFFFFFFF

    for i in range(length):
        # Read raw byte, interpret as signed char, then add 32
        b_signed_plus_32 = _to_int8(data[i]) + 32

        # Two's complement cast to unsigned 64
        mult_factor_u64 = b_signed_plus_32 & MASK64

        # Multiply with wraparound
        mixed = (result * mult_factor_u64) & MASK64

        # XOR in the (byte) length and the mixed value
        result = (result ^ (length ^ mixed)) & MASK64

    return result


def mw_hash_bytes(data: bytes, length: int = None) -> int:
    """Hash exactly like mw_hash_func when passed their fake UNICODE_STRING."""
    if length is None:
        length = len(data)
    if length > len(data):
        raise ValueError("length exceeds buffer size")

    h = 0xFFFFFFFFFFFFFFFF
    for i in range(length):
        b = _to_int8(data[i]) + 32          # signed char, then +32
        mixed = (h * (b & MASK64)) & MASK64 # 64-bit wraparound
        h = (h ^ (length ^ mixed)) & MASK64
    return h

def mw_hash_export_name(name: str) -> int:
    # The export name is ASCII in PE
    data = name.encode("ascii")
    return mw_hash_bytes(data, len(data))


def get_dll_names():
    system32_dir = "C:\\Windows\\System32"
    files = os.listdir(system32_dir)
    for file in files:
        if os.path.isfile(os.path.join(system32_dir, file)):
            if file.endswith(".dll"):
                dll_name = file.split(".")[0]
                upper_dll_name = dll_name.upper()
                dll_names.append(upper_dll_name)

def get_dll_apis(target_dll):
    dll = pefile.PE(target_dll)
    export_list = dll.DIRECTORY_ENTRY_EXPORT
    for symbol in export_list.symbols:
        if symbol.name:
            dll_apis.append(symbol.name.decode("utf8"))

def find_hash_match_dlls(target_hash, dll_names):
    match_found = False
    for dll_name in dll_names:
        dll_name = dll_name + ".dll"
        h1 = mw_hash_func(dll_name)
        if h1 == target_hash:
            match_found = True
            print("[+] Match found!")
            print(dll_name)
            break
    if not match_found:
        for dll_name in dll_names:
            dll_name = dll_name.lower()
            dll_name = dll_name + ".dll"
            h1 = mw_hash_func(dll_name)
            if h1 == target_hash:
                match_found = True
                print("[+] Match found!")
                print(dll_name)
                break

def find_hash_match_apis(target_hash, api_names):
    match_found = False
    for api_name in api_names:
        h1 = mw_hash_export_name(api_name)
        if h1 == target_hash:
            match_found = True
            print("[+] Match found!")
            print(api_name)
            break
    if not match_found:
        for api_name in api_names:
            api_name = api_name.upper()
            h1 = mw_hash_export_name(api_name)
            if h1 == target_hash:
                match_found = True
                print("[+] Match found!")
                print(api_name)
                break
    if not match_found:
        for api_name in api_names:
            api_name = api_name.lower()
            h1 = mw_hash_export_name(api_name)
            if h1 == target_hash:
                match_found = True
                print("[+] Match found!")
                print(api_name)
                break

#get_dll_names()
#find_hash_match_dlls(<DLL_HASH>, dll_names)
get_dll_apis("TARGET DLL")

hashes = ["HASHES FOUND DURING ANALYSIS GO HERE"]

for hash in hashes:
    find_hash_match_apis(hash, dll_apis)
