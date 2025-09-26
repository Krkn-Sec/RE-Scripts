import pefile
import yara
from capstone import *
from capstone.x86 import *
from Crypto.Cipher import ARC4
import json
import sys

#-------------------#
#   GLOBAL VARS     #
#--------------------
config = {
    "malware":"cryptbot"
}



#----------------#
#    YARA RULES  #
#----------------#
mainFuncRule = """
rule cryptbot_main_start
{
    strings:
        $s1 = { 55 89 E5 57 56 53 83 E4 F0 81 EC ?? ?? ?? ?? 8B 5D ?? 8B 7D ?? }
        $s2 = { 55 89 e5 83 e4 f0 81 ec ?? ?? ?? ?? e8 ?? ?? ?? 00 c7 05 ?? ?? ?? 00 ?? 2f 00 00 }
    condition:
        $s1 or $s2
}
"""


mainFuncRuleEnd = """
rule cryptbot_main_end
{
    strings:
        $e1 = { 
            c7 05 ?? ?? ?? ?? ?? ?? ?? ??
            c7 05 ?? ?? ?? 00 01 00 00 00
            c7 05 ?? ?? ?? 00 01 00 00 00
            c7 05 ?? ?? ?? 00 00 00 00 00
        }
        $e2 = { 90 90 90 90 90 90 90 c7 05 ?? ?? ?? 00 01 00 00 00 }
    condition:
        $e1 or $e2
}
"""


stackKeyRule = """
rule cryptbot_stack_key
{
    strings:
        $ss1 = { 
            55
            57
            56
            53
            83ec3c
            8b(4c|44)24(64|58)
            8b(44|5c)24(58|50)
         }
         $ss2 = { 55 B9 ?? ?? ?? ?? 57 56 BE ?? ?? ?? ?? 53 81 EC ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 8D 7C 24 ?? 8B 9C 24 ?? ?? ?? ??}
    condition:
        $ss1 or $ss2
}
"""


# Compiling YARA rules
main_func_compiled = yara.compile(source=mainFuncRule)
main_func_end_compiled = yara.compile(source=mainFuncRuleEnd)
stack_key_compiled = yara.compile(source=stackKeyRule)


#-----------------------#
#   HELPER FUNCTIONS    #
#-----------------------#
def HelperConvertHexToByteArray(rc4_data: list) -> bytes:
    """
    Not only used to convert the gathered bytes to an array
    that can be worked with. But also ensure that it's
    gathered in little endian.
    """
    byteArray = list()
    for item in rc4_data:
        if len(item) > 4:
            without_ox = item[2:].zfill(8)
            little_endian = bytes.fromhex(without_ox)[::-1]
            byteArray.append(little_endian)
        else:
            without_ox = item[2:].zfill(2)
            single_byte = bytes.fromhex(without_ox)
            byteArray.append(single_byte)
    result = b''.join(byteArray)
    return result


def HelperConvertHexToAscii(stack_chars):
    """
    Converts stack chars to their ASCII values.
    """
    plaintext = list()
    for item in stack_chars:
        plaintext.append(chr(int(item, 0)))
    result = ''.join(plaintext)
    return result


def ParseConfig(dec_data: str):
    """
    C2 is the first entry
    """
    dec_data = dec_data.split('\n')
    config["C2"] = dec_data[0]
    print(json.dumps(config, indent=4))


#--------------------#
#   RC4 DECRYPTION   #
#--------------------#
def RC4Decrypt(enc_data: bytes, key: str) -> str:
    """
    Once the RC4 encrypted blob is found,
    decrypt. In all samples found, the key has been the same.
    """
    key = key.encode('utf-8', 'ignore')
    dec_data = ARC4.new(key).decrypt(enc_data[8:])
    dec_data = dec_data.decode('utf-16', 'ignore')
    if "top" in dec_data:
        return dec_data
    return ""



#------------------------#
#   CAPSTONE FUNCTIONS   #
#------------------------#
def DisassembleAndFindDataBlob(file_data: bytes, yara_matches_start: int, yara_matches_end: int) -> list:
    """
    This function takes the offsets from the YARA
    matches and seeks to that area within the PE file.
    Then using Capstone, it disassembles that area looking
    for specific assembly instructions based on mnemonics and
    opcodes. Once found, it grabs the operands needed.
    In the case of Cryptbot, it first finds the main() function.
    Then it finds the first large set of MOV instructions. The
    bytes MOV'd are the RC4 encrypted bytes.
    """
    # Create a list to store the extracted RC4 encrypted blob
    RC4_data = list()

    for block in yara_matches_start[0].strings:
        for instance in block.instances:
            if block.identifier == "$s1":       # First version looks for Cryptbot that has stripped symbols
                start_offset = instance.offset
            if block.identifier == "$s2":       # Second version looks for Cryptbot that has symbols present
                start_offset = instance.offset
                return DisassembleAndFindDataBlobVer2(file_data, start_offset, yara_matches_end)        # Use a different method to disassemble due to different instructions

    if yara_matches_end != []:
        for block in yara_matches_end[0].strings:
            for instance in block.instances:
                if block.identifier == "$e1":
                    end_offset = instance.offset        # If YARA can find the end use it as an offset
    else:
        end_offset = start_offset + 45550               # Otherwise use a static value

    # Setup capstone
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = file_data[start_offset:end_offset]

    # Iterate through instructions and look for specific opcodes to get RC4 data blob
    for i in md.disasm(code, start_offset):
        if i.mnemonic == "mov":
            if i.opcode[0] == 199:
                RC4_data.append(hex(i.operands[1].reg))
    return RC4_data


def DisassembleAndFindDataBlobVer2(file_data: bytes, start_offset: int, yara_matches_end: object) -> list:
    """
    In the 2nd version of Cryptbot's update observed,
    Cryptbot does the same action of manually moving bytes to
    a data blob. However, unlike the stripped version it
    also has many single byte MOVs. Thus, the need for this
    additional function.
    """
    # Create a list to store the extracted RC4 encrypted blob
    RC4_data = list()

    if yara_matches_end != []:
        for block in yara_matches_end[0].strings:
            for instance in block.instances:
                if block.identifier == "$e2":
                    end_offset = instance.offset        # If YARA can find the end use it as an offset
    else:
        end_offset = start_offset + 127315              # This shouldn't happen but if no YARA match use a static value

    # Setup capstone
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = file_data[start_offset:end_offset]

    # Disassemble and find specific opcodes
    for i in md.disasm(code, start_offset):
        if i.mnemonic == "mov":
            if i.opcode[0] == 199 or i.opcode[0] == 198:        # Adds the opcode for single byte MOVs which is prominent in ver. 2
                RC4_data.append(hex(i.operands[1].reg))
    return RC4_data


def GetStackStrings(file_data, data_at_empty_base, yara_matches_stack_strings):
    """
    RC4 key is generated by ASCII values pushed onto the stack.
    Additionally, some values are calculated via subtraction through mini functions.
    E.G. A CALL to a function that contains SUB EAX, EDX
    """
    stack_chars = list()
    rc4_key_func_offset = None
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = file_data
    code2 = data_at_empty_base
    for block in yara_matches_stack_strings[0].strings:
        for instance in block.instances:
            if block.identifier == "$ss1":
                rc4_key_func_offset = instance.offset
            if block.identifier == "$ss2":
                stack_chars_2 = GetStackStrings2(file_data, data_at_empty_base, yara_matches_stack_strings)
                return stack_chars_2
                #rc4_key_func_offset = instance.offset

    if rc4_key_func_offset != None:
        func_code = code[rc4_key_func_offset:rc4_key_func_offset+0x92]

        for i in md.disasm(func_code, rc4_key_func_offset):
            if i.mnemonic == "call":
                hexOffset = i.op_str
                funcOffset = int(hexOffset, 16)
                call_code = code2[funcOffset:funcOffset+0x23]
                for cC in md.disasm(call_code, 0x0):
                    if cC.opcode[0] == 184:
                        stack_chars.append(hex(cC.operands[1].reg))
            if i.mnemonic == "mov":
                if i.opcode[0] == 186:  # MOV EDX
                    subtract_var = i.operands[1].reg
                    subtract_var = subtract_var & 0xFF
                if i.opcode[0] == 184:  # MOV EAX
                    value = i.operands[1].reg
                    if value > 20 and value < 0xFF:
                        true_value = ord(chr(value)) - subtract_var & 0xFF
                        stack_chars.append(hex(true_value))
        plain = HelperConvertHexToAscii(stack_chars)
        return plain


def GetStackStrings2(file_data, data_at_empty_base, yara_matches_stack_strings):
    """
    Another version observed is the usage of EDX and EAX registers
    are swapped between the original ASCII byte and the subtraction value.
    """
    stack_chars = list()
    rc4_key_func_offset = None
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = file_data
    code2 = data_at_empty_base
    for block in yara_matches_stack_strings[0].strings:
        for instance in block.instances:
            if block.identifier == "$ss2":
                rc4_key_func_offset = instance.offset

    if rc4_key_func_offset != None:
        func_code = code[rc4_key_func_offset:rc4_key_func_offset + 0xeb]

        # setup EIP for looping
        registers = {}
        registers[X86_REG_EIP] = 0

        while registers[X86_REG_EIP] != len(func_code):
            address = registers[X86_REG_EIP]

            instruction = next(md.disasm(func_code[address:address + 15], address))
            mnemonic = instruction.mnemonic
            operands = instruction.operands

            if mnemonic == "mov":
                if instruction.opcode[0] == 186:    #MOV EDX
                    next_inst = next(md.disasm(func_code[address+instruction.size:address+15], address))
                    if next_inst.opcode[0] == 184:  #MOV EAX
                        orig_value = operands[1].reg    # orig_value = EDX -> then gets moved into EAX
                        subtract_value = next_inst.operands[1].reg  # subtract_value = EAX -> then gets moved into ECX
                        stack_chars.append(hex((orig_value) - (subtract_value & 0xFF) & 0xFF))  # SUB EAX, ECX
            if mnemonic == "call":
                hex_offset = bytes(instruction.bytes[1:])
                call_offset = bytes.hex(hex_offset)
                loc = bytes.fromhex(call_offset)[::-1]
                loc = bytes.hex(loc)
                location = int(loc, 16)
                call_code = code2[rc4_key_func_offset + address + location:rc4_key_func_offset + address + location + 0x29]
                for cC in md.disasm(call_code, 0x0):
                    if cC.opcode[0] == 184:     # MOV EAX
                        stack_chars.append(hex(cC.operands[1].reg))

            # increment EIP
            registers[X86_REG_EIP] += instruction.size

        plain = HelperConvertHexToAscii(stack_chars)
        return plain


#---------#
#   MAIN  #
#---------#
def Extract():
    file = sys.argv[1]
    pe_data = pefile.PE(file)
    data = pe_data.get_memory_mapped_image()
    data_at_zero = pe_data.get_memory_mapped_image(ImageBase=0x000000000)

    # Get YARA matches
    yara_matches_start = main_func_compiled.match(data = data)
    yara_matches_end = main_func_end_compiled.match(data = data)
    yara_matches_stack = stack_key_compiled.match(data = data)

    try:
        stack_strings = ''
        if yara_matches_stack != []:
            stack_strings = GetStackStrings(data, data_at_zero, yara_matches_stack)
    except Exception as e:
        print(e)
        pass

    # If stack string key generator function found, dynamically extract the RC4 key. Otherwise, try a hardcoded key seen in most samples
    if stack_strings != '':
        RC4_data = DisassembleAndFindDataBlob(data, yara_matches_start, yara_matches_end)
        enc_data = HelperConvertHexToByteArray(RC4_data)
        dec_data = RC4Decrypt(enc_data, stack_strings)
        ParseConfig(dec_data)
    else:
        KEY = 'LkgwUi'
        RC4_data = DisassembleAndFindDataBlob(data, yara_matches_start, yara_matches_end)
        enc_data = HelperConvertHexToByteArray(RC4_data)
        dec_data = RC4Decrypt(enc_data, KEY)
        ParseConfig(dec_data)


if __name__ == "__main__":
    Extract()
