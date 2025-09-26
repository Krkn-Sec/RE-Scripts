
#####################################################
#                              #                    #
#  Qakbot_v5 Config Extractor  #  Author: PDaubman  #
#                              #                    #
#########################################################################
#                                                                       #
#  Description: The newest update for Qakbot no longer stores its       #
#               configuration in the resources section. Instead, it     #
#               uses a multi-layered approach to hide it and stores it  #
#               in the .data section. The process for decrypting the    #
#               configuration is as follows. First strings must be      #
#               decrypted. They're encrypted using a large XOR key but  #
#               the XOR key first needs to be AES-Decrypted. Once the   #
#               strings are decrypted, a plaintext AES key is revealed. #
#               This plaintext AES key needs to be SHA-256 hashed and   #
#               then the configuration and C2 array can be decrypted.   #
#                                                                       #
#########################################################################
#                                                                       #
#  Note: This config extractor uses the Capstone library to disassemble #
#        and read arguments passed into specific functions for a more   #
#        reliable method of acquiring the specific data blobs.          #
#                                                                       #
#########################################################################

import datetime
import json
import sys
import pefile
import yara
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
from capstone import *

#------------------------#
#       GLOBAL VARS      #
#------------------------#
config = {
    "malware": "qakbot",
    "Campaign ID": [],
    "Compile Time (Epoch)": [],
    "Compile Time (Formatted)": [],
    "C2s": []
}



#--------------------------------------------------------#
#       YARA Rules                                       #
# Used to identify specific functions within the binary. #
#--------------------------------------------------------#
funcRule = """
rule vt_win_qakbot_v5
{
    strings:
        $s1 = { 
            48 83 ec 48                 // sub rsp, 0x48
            (89|83) ?? 24 30            // [mov|and] dword [rsp+0x30]
            48 8d 05 ?? ?? ?? 00        // lea rax, [rel HASH_DATA]
            c7 44 24 28 ?? 00 00 00     // mov dword [rsp+0x28], 0x??
            (48|4c) 8d ?? ?? ?? ?? 00   // lea rcx, [rel encrypted_strings]
            41 b9 ?? ?? 00 00           // mov r9d, 0x??
            48 89 44 24 20              // mov qword [rsp+0x20], rax
        }
    
    condition:
        any of them
}
"""

configDecryptFuncRule = """
rule config_func
{
    strings:
        $s1 = {
            48 89 5C 24 10              // mov [rsp+arg_8], rbx
            48 89 4C 24 08              // mov [rsp+encKey], rcx
            57                          // push rdi
            48 83 EC 20                 // sub rsp, 0x20
            0F B7 ?? ?? ?? ?? 00        // movzx wbx, word ptr cs:length
            B9 ?? ?? 00 00              // mov ecx, 0x155
        }
        
    condition:
        any of them
}
"""

c2DecryptFuncRule = """
rule c2_func
{
    strings:
        $s1 = {
            40 55                       // push rbp
            53                          // push rbx
            56                          // push rsi
            57                          // push rdi
            41 54                       // push r12
            41 56                       // push r14
            41 57                       // push r15
            48 8b ec                    // mov rbp, rsp
            48 83 ec 30                 // sub rsp, 0x30
            48 8b ?? ?? ?? ?? 00        // mov rcx, cs:heap
            45 33 e4                    // xor r12d, r12d
            48 85 c9                    // test rcx, rcx
        }
    
    condition:
        any of them
}
"""

# Compiling YARA rules
func_rule_compiled = yara.compile(source=funcRule)
config_func_compiled = yara.compile(source=configDecryptFuncRule)
c2_func_compiled = yara.compile(source=c2DecryptFuncRule)



#------------------------------------------#
#       STRING DECRYPTION                  #
# All helper functions to decrypt strings. #
#------------------------------------------#
def xor_byte_data(data, key):
    rbytes = bytes()
    for i, b in enumerate(data):
        rbytes += (b ^ key[i % len(key)]).to_bytes(1, byteorder='little')
    return rbytes


def decrypt_aes(aes_key_data, iv_xor_ct_data):
    h = SHA256.new()
    h.update(aes_key_data)
    aes256key = h.digest()

    cipher = AES.new(aes256key, AES.MODE_CBC, iv_xor_ct_data[:16])
    xor_key_ct = iv_xor_ct_data[16:]
    xor_key = unpad(cipher.decrypt(xor_key_ct), AES.block_size)
    return xor_key


def disassemble_func(file_data, yara_matches):
    start_offsets = []

    for block in yara_matches[0].strings:
        for instance in block.instances:
            if block.identifier == "$s1":
                start_offsets.append(instance.offset)

    for offset in start_offsets:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # Beginning of code section
        begin = offset

        # end of code block
        end = offset + 0x40

        code = file_data.get_memory_mapped_image()[begin:end]
        for i in md.disasm(code, begin):
            #print(i)
            if i.mnemonic == "lea":
                if i.operands[0].reg == 35:     # hash_data_argument
                    hash_code_addr = i.address
                    hash_data_offset = hex(i.operands[1].value.mem.disp)

                if i.operands[0].reg == 38:     # encrypted_strings_table_argument
                    strings_code_addr = i.address
                    encrypted_strings_table_offset = hex(i.operands[1].value.mem.disp)

                if i.operands[0].reg == 106:    # IV_and_encrypted_xor_key
                    xor_code_addr = i.address
                    encrypted_xor_key_offset = hex(i.operands[1].value.mem.disp)

            if i.mnemonic == "mov":
                if "[rsp + 0x28]" in i.op_str:  # hash_data_blob_size
                    hash_data_size = hex(i.operands[1].reg)

                if i.operands[0].reg == 24:  # encrypted_strings_data_blob_size
                    encrypted_strings_table_size = hex(i.operands[1].reg)

                if i.operands[0].reg == 227:    # iv/xor_key_data_blob_size
                    encrypted_xor_key_size = hex(i.operands[1].reg)

        plaintext_strings = extract_blobs(file_data, hash_data_offset, hash_data_size, encrypted_strings_table_offset, encrypted_strings_table_size, encrypted_xor_key_offset, encrypted_xor_key_size, hash_code_addr, strings_code_addr, xor_code_addr)
        plaintext_strings = plaintext_strings.decode("utf-8")
        plaintext_strings = plaintext_strings.split(";")
        if ("powershell.exe" in plaintext_strings[0]):
            return plaintext_strings


def get_config_aes_keys(target_plaintext_strings):

    # Get first aes key plaintext
    key_one = target_plaintext_strings[0]
    key_one = key_one.split("\x00")
    for i in key_one:
        if len(i) == 32:
            key_one = i
    #key_one = key_one[1]
    key_one = bytes(key_one, "utf-8")

    # SHA-256 hash the plaintext key
    hasher = SHA256.new()
    hasher.update(key_one)
    aes_key_one_hashed = hasher.digest()

    # Get second aes key plaintext
    key_two = target_plaintext_strings[1]
    key_two = key_two.split("\x00")
    target_key_two = b''
    for i in key_two:
        if (len(i) == 42):
            target_key_two = i

    if target_key_two == b'':
        key_two = target_plaintext_strings[0]
        key_two = key_two.split("\x00")
        for i in key_two:
            if (len(i) == 42):
                target_key_two = i

    # SHA-256 hash the second plaintext key
    hasher = SHA256.new()
    hasher.update(bytes(target_key_two, "utf-8"))
    aes_key_two_hashed = hasher.digest()

    return aes_key_one_hashed, aes_key_two_hashed


def extract_blobs(file_data, hash_offset, hash_size, strings_offset, strings_size, xor_key_offset, xor_key_size, hash_code_addr, strings_code_addr, xor_code_addr):

    # Get hash data blob
    code = file_data.get_memory_mapped_image()
    hash_offset = int(hash_offset, 16)
    hash_blob_start = hash_code_addr + 7 + hash_offset
    hash_blob_end = hash_blob_start + int(hash_size, 16)
    hash_blob = code[hash_blob_start:hash_blob_end]

    # Get encrypted strings table blob
    strings_offset = int(strings_offset, 16)
    strings_table_start = strings_code_addr + 7 + strings_offset
    strings_table_end = strings_table_start + int(strings_size, 16)
    strings_table = code[strings_table_start:strings_table_end]

    # Get encrypted xor key blob
    xor_key_offset = int(xor_key_offset, 16)
    xor_key_start = xor_code_addr + 7 + xor_key_offset
    xor_key_end = xor_key_start + int(xor_key_size, 16)
    xor_key = code[xor_key_start:xor_key_end]

    # Decrypt strings
    decrypted_xor_key = decrypt_aes(hash_blob, xor_key)
    decrypted_strings_table = xor_byte_data(strings_table, decrypted_xor_key)
    return decrypted_strings_table




#---------------------------#
#       BASIC CONFIG        #
#---------------------------#
def decrypt_config_aes(enc_data, key):
    iv = enc_data[:16]
    rest_of_data = enc_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(rest_of_data), AES.block_size)
    return decrypted


def get_config_blob(file_data):
    yara_matches = config_func_compiled.match(data = file_data.get_memory_mapped_image())
    start_offsets = []

    for block in yara_matches[0].strings:
        for instance in block.instances:
            if block.identifier == "$s1":
                start_offsets.append(instance.offset)

    for offset in start_offsets:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # Beginning of code section
        begin = offset

        # end of code block
        end = offset + 0x40

        code = file_data.get_memory_mapped_image()[begin:end]

        #data = code[begin:end]
        for i in md.disasm(code, begin):
            if i.mnemonic == "movzx":
                config_size_addr = i.address
                config_size_offset = hex(i.operands[1].value.mem.disp)
            if i.mnemonic == "lea":
                config_code_addr = i.address
                config_data_offset = hex(i.operands[1].value.mem.disp)

        encrypted_config = extract_config(file_data, config_size_addr, config_size_offset, config_code_addr, config_data_offset)
        return encrypted_config


def extract_config(file_data, config_size_addr, config_size_offset, config_code_addr, config_data_offset):
    # Get config size
    code = file_data.get_memory_mapped_image()
    config_size_offset = int(config_size_offset, 16)
    config_size_start = config_size_addr + 7 + config_size_offset
    config_size = code[config_size_start:config_size_start + 1]
    config_size = int.from_bytes(config_size)

    # Get config blob
    config_data_offset = int(config_data_offset, 16)
    config_blob_start = config_code_addr + 7 + config_data_offset
    config_blob_end = config_blob_start + config_size
    config_blob = code[config_blob_start:config_blob_end]

    return config_blob


def parse_config(decrypted_config):
    decrypted_config = decrypted_config[32:]
    decrypted_config = decrypted_config.decode("utf-8", errors='ignore')
    decrypted_config = decrypted_config.split("\n")
    for i in decrypted_config:
        if '10=' in i:
            campaign_id = i.split("=")
            campaign_id = campaign_id[1]
            campaign_id = campaign_id.strip('\r')
        if '3=' in i:
            compile_time = i.split('=')
            compile_time = compile_time[1]
            compile_time = compile_time.strip('\r')

    compile_time_calculated = datetime.datetime.fromtimestamp(int(compile_time)).strftime('%c')

    config["Campaign ID"] = campaign_id
    config["Compile Time (Epoch)"] = compile_time
    config["Compile Time (Formatted)"] = compile_time_calculated



#-----------------------#
#       C2 EXTRACT      #
#-----------------------#
def get_c2_blob(file_data):
    yara_matches = c2_func_compiled.match(data = file_data.get_memory_mapped_image())
    start_offsets = []

    for block in yara_matches[0].strings:
        for instance in block.instances:
            if block.identifier == "$s1":
                start_offsets.append(instance.offset)

    for offset in start_offsets:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # Beginning of code section
        begin = offset + 0x95

        # end of code block
        end = begin + 0x40

        code = file_data.get_memory_mapped_image()[begin:end]
        for i in md.disasm(code, begin):
            if i.mnemonic == "movzx":
                c2_size_addr = i.address
                c2_size_offset = hex(i.operands[1].value.mem.disp)
            if i.mnemonic == "lea":
                c2_code_addr = i.address
                c2_data_offset = hex(i.operands[1].value.mem.disp)

        encrypted_c2 = extract_config(file_data, c2_size_addr, c2_size_offset, c2_code_addr, c2_data_offset)
        return encrypted_c2


def parse_c2s(decrypted_c2s):
    extracted_c2s = []
    final = []
    decrypted_c2s = decrypted_c2s[32:]
    decrypted_c2s = decrypted_c2s.split(b'\x00')
    for c2 in decrypted_c2s:
        c2 = c2.lstrip(b'\x01')
        if (c2 == b''):
            continue
        else:
            extracted_c2s.append(c2)
    for item in extracted_c2s:
        ip = []
        port = int.from_bytes(item[4:], byteorder='big')
        c2 = item[:4]
        for i in c2:
            ip.append(str(i))
        ip2 = '.'.join(ip)
        config["C2s"].append(ip2 + ":" + str(port))
    print(json.dumps(config, indent=2))



#---------#
# EXTRACT #
#---------#
def extract():
    file = sys.argv[1]
    pe_data = pefile.PE(file)

    # Get YARA matches
    yara_matches = func_rule_compiled.match(data = pe_data.get_memory_mapped_image())

    if yara_matches:
        target_plaintext_strings = disassemble_func(pe_data, yara_matches)
        aes_key_one, aes_key_two = get_config_aes_keys(target_plaintext_strings)
        encrypted_config = get_config_blob(pe_data)
        decrypted_config = decrypt_config_aes(encrypted_config[1:], aes_key_two)
        parse_config(decrypted_config)
        encrypted_c2s = get_c2_blob(pe_data)
        decrypted_c2s = decrypt_config_aes(encrypted_c2s[1:], aes_key_two)
        c2s = parse_c2s(decrypted_c2s)



#------#
# MAIN #
#------#
if __name__ == '__main__':
    extract()
