import yara
import sys
import re
import json
import struct
import logging
from capstone import *

class YARA:
    """
    Class for YARA scanning the binary.
    """

    atomic_plaintext_rule = """
    rule atomic_plaintext
    {
        strings:
            $s1 = "VMware" fullword ascii
            $s2 = "Apple Virtual Machine" fullword ascii
        condition:
            all of them
    }
    """

    atomic_v1_rule = """
    rule atomic_enc_v1
    {
        strings:
            $xor = { 8a 8d (68|70) ff ff ff 30 8c 05 (68|70) ff ff ff 48 ff c0 (48 3d 83 00 00 00 | 48 83 f8 ??) }
        condition:
            all of them
    }
    """

    @staticmethod
    def scan(filedata):
        atomic_plaintext_compiled = yara.compile(source=YARA.atomic_plaintext_rule)
        atomic_v1_compiled = yara.compile(source=YARA.atomic_v1_rule)

        atomic_plaintext_matches = atomic_plaintext_compiled.match(data=filedata)
        atomic_v1_matches = atomic_v1_compiled.match(data=filedata)

        return atomic_plaintext_matches, atomic_v1_matches



class AtomicPlaintext:
    """
    Class for unobfuscated Atomic Stealer
    """
    def __init__(self, path):
        self.file_path = path
        self.file_data = open(self.file_path, 'rb').read()
        self.regex_pattern = r'Host:.*\r\n\x00'
        self.config = {'malware':'atomic'}

    def find_ip_address(self):
        """
        The unobfuscated Atomic Stealer
        just has an IP address as a string.
        Just gotta find it.
        """
        strings = self.file_data.decode('utf-8', 'ignore')
        matches = re.findall(self.regex_pattern, strings, re.DOTALL)
        if matches:
            try:
                # Try to get the IP efficiently
                contains_ip = matches[0].split('\x00')[0]
                c2 = contains_ip.split(':')[1].rstrip().rstrip().lstrip()
                self.config['C2'] = c2
            except IndexError:
                # Try to get it more carefully
                contains_ip = matches[0]
                split = contains_ip.split(':')[1]
                if split[0:1] == ' ':
                    split = split.lstrip()
                if '\\r\\n' in split:
                    split = split.replace('\\r\\n', '')
                self.config['C2'] = split
        else:
            # Try a different pattern
            pattern = r'http:\/\/.*\/'
            matches = re.findall(pattern, strings, re.DOTALL)
            if matches:
                try:
                    split = matches[0].split('\x00')
                    contains_ip = split[0]
                    c2 = contains_ip.split('/')[2]
                    self.config['C2'] = c2
                except IndexError:
                    # Try to get it more carefully
                    contains_ip = matches[0]
                    split = contains_ip.split(':')[1]
                    if split[0:1] == ' ':
                        split = split.lstrip()
                    if '\\r\\n' in split:
                        split = split.replace('\\r\\n', '')
                    self.config['C2'] = split
            print("")



class AtomicObfuscatedVer1:
    """
    Class for obfuscated version 1 of Atomic Stealer.
    This version uses a simple XOR with key of 0x91
    """
    def __init__(self, path):
        self.file_path = path
        self.file_data = open(self.file_path, 'rb').read()
        self.regex_pattern = r'__const'
        self.config = {'malware':'atomic'}
        self.const_section = None
        self.plaintext = None
        self.xor_key = None

    def parse_header(self) -> bool:
        """
        Much quicker to find the offset and size of the __const section
        then XOR instead of XORing the entire binary.
        """
        # Let's first find the __const string offset using YARA
        # There'll probably be 2 matches because MACH-O combined binaries containing both x64 and ARM versions. (Each one has its own header)
        # We only care about one of them.
        try:
            const_yara = "rule const{ strings: $a = { 5f5f636f6e73740000000000000000005f5f5445585400000000000000000000 } condition: $a}"
            compiled_rule = yara.compile(source=const_yara)
        except yara.Error as e:
            print(f"YARA compilation error: {str(e)}")
            raise

        try:
            matches = compiled_rule.match(data=self.file_data)
        except yara.Error as e:
            print(f"YARA match error: {str(e)}")
            raise

        if matches:
            cstring_offset = matches[0].strings[0].instances[0].offset

            # After finding the __const header, we can get more information like offset and size.
            try:
                cstring_section_header = self.file_data[cstring_offset:cstring_offset + 0x40]
                cstring_section_offset = struct.unpack('<I', cstring_section_header[0x30:0x34])[0]
                cstring_section_size = struct.unpack('<I', cstring_section_header[0x28:0x2C])[0]
            except struct.error as e:
                logging.error(f"Error unpacking section header: {str(e)}")
                raise

            # Remember to add 0x4000 to the offset to deal with the MACH-O header if it's a double binary
            if self.file_data[:4] == b'\xCA\xFE\xBA\xBE':
                cstring_section_offset += 0x4000

            # Get the encrypted strings
            self.const_section = self.file_data[cstring_section_offset:cstring_section_offset + cstring_section_size]

            if self.const_section:
                return True
        else:
            logging.warnng(f"No matches found for __const section in {self.file_path}")
            return False

    def decrypt(self):
        """
        We can XOR the entire thing.
        """
        if not self.xor_key:
            logging.error("No XOR key found.")
            return False

        plain = ''
        for i in self.const_section:
            new_char = i ^ self.xor_key
            new_char = chr(new_char)
            plain += new_char

        if "osascript" in plain:
            self.plaintext = plain
            return True
        return False

    def find_ip_address(self):
        if self.plaintext:
            split = self.plaintext.split('\x00')
            pattern = r'(\d{1,3}\.){3}\d{1,3}'
            for i in split:
                match = re.match(pattern, i)
                if match:
                    self.config['C2'] = match.string
                    return True
        return False

    def find_xor_key(self) -> bool:
        try:
            xor_key_yara = """
            rule xor_key
            {
                strings:
                    $s1 = { c6 47 ff ?? }
                    $s2 = { b0 ?? }
                condition:
                    $s1 or $s2
            }
            """
            compiled_rule = yara.compile(source=xor_key_yara)
            matches = compiled_rule.match(data=self.file_data)
            if matches:
                matched_data = matches[0].strings[0].instances[0].matched_data
                xor_key = int.from_bytes(matched_data[3:])
                self.xor_key = xor_key
                return True
            else:
                logging.error("No XOR key found.")
                return False
        except Exception as e:
            logging.error(f"Error occurred when finding XOR key: {e}")
            return False

    def main(self):
        # First parse the MACH-O and get the __const section
        if not self.parse_header():
            logging.error("[!] Couldn't parse header...")
            exit(1)

        # Attempt to find the xor key
        if not self.find_xor_key():
            logging.error("[!] Couldn't find XOR key...")
            exit(1)

        # Attempt to decrypt
        if not self.decrypt():
            logging.error("[!] Couldn't decrypt...")
            exit(1)

        # Find the IP
        if not self.find_ip_address():
            logging.warning("[!] Couldn't find IP address.\nAttempting another way...")


class AtomicObfuscatedVer2:
    """
    Class for obfuscated version 2 of Atomic Stealer.
    This version uses a simple XOR but stores the IP
    in hex bytes in the disassembly instead of a constant.
    """
    def __init__(self, path):
        self.file_path = path
        self.file_data = open(self.file_path, 'rb').read()
        self.regex_pattern = r'__const'
        self.config = {'malware': 'atomic'}
        self.captured_bytes = None
        self.plaintext = None
        self.xor_key = None

    def find_mod_init(self):
        mod_init_func_yara = """
            rule mod_init {
                meta:
                    description = "Finds beginning of mod_init_func"
                    architecture = "x86_64"
                    
                strings:
                    $bytes = {
                        55                    // push    rbp {__saved_rbp} 
                        48 89 e5              // mov     rbp, rsp {__saved_rbp} 
                        41 56                 // push    r14 {__saved_r14} 
                        53                    // push    rbx {__saved_rbx} 
                        48 81 ec a0 00 00 00  // sub     rsp, 0xa0 
                        48 8b 05 ?? ?? 00 00  // mov     rax, qword [rel ___stack_chk_guard] 
                        48 8b 00              // mov     rax, qword [rax] 
                        48 89 45 e8           // mov     qword [rbp-0x18 {var_20}], rax 
                        b0 ??                 // mov     al, 0x90 
                        48 8d b5 71 ff ff ff  // lea     rsi, [rbp-0x8f {__s}] 
                        88 46 ff              // mov     byte [rsi-0x1 {var_98}], al  {0x90} 
                        88 46 40              // mov     byte [rsi+0x40 {var_57}], al  {0x90} 
                        0f 28 05 ?? ?? 00 00  // movaps  xmm0, xmmword [rel data_100017b30] 
                        0f 11 46 30           // movups  xmmword [rsi+0x30 {var_67}], xmm0 
                        0f 28 05 ?? ?? 00 00  // movaps  xmm0, xmmword [rel data_100017b40] 
                        0f 11 46 20           // movups  xmmword [rsi+0x20 {var_77}], xmm0 
                        0f 28 05 ?? ?? 00 00  // movaps  xmm0, xmmword [rel data_100017b50] 
                        0f 11 46 10           // movups  xmmword [rsi+0x10], xmm0 
                        0f 28 05 ?? ?? 00 00  // movaps  xmm0, xmmword [rel data_100017b60] 
                        0f 11 06              // movups  xmmword [rsi {__s}], xmm0 
                        b8 01 00 00 00        // mov     eax, 0x1 
                    }
                condition:
                    $bytes
            }
        """
        mod_init_compiled = yara.compile(source=mod_init_func_yara)
        matches = mod_init_compiled.match(data=self.file_data)
        if matches:
            mod_init_func_offset = matches[0].strings[0].instances[0].offset
            self.mod_init_offset = mod_init_func_offset
        else:
            logging.error("[!] Couldn't find mod_init function.\n Can't proceed.")
            exit(1)


    def gather_inline_bytes(self):
        inline_bytes = []
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # Beginning of mod_init_func
        begin = self.mod_init_offset

        # End of code block
        end = begin + 0x600

        code = self.file_data[begin:end]
        for i in md.disasm(code, begin):
            #print(i)
            if i.mnemonic == "mov":
                # Get XOR key
                if i.opcode[0] == 176:
                    if not self.xor_key:
                        self.xor_key = i.operands[1].reg
                if i.opcode[0] == 199:
                    op_str = i.op_str.split(",")[1].lstrip(" ").lstrip("0x")
                    if len(op_str) % 2 != 0:
                        op_str = "0" + op_str
                    test = bytearray.fromhex(op_str)
                    test.reverse()
                    little = ''.join(f"{n:02X}" for n in test)
                    byte_str = bytes.fromhex(little)
                    inline_bytes.append(byte_str)
            if i.mnemonic == "movabs":
                if i.opcode[0] == 184:
                    op_str = i.op_str.split(",")[1].lstrip(" ").lstrip("0x")
                    if len(op_str) % 2 != 0:
                        op_str = "0" + op_str
                    test = bytearray.fromhex(op_str)
                    test.reverse()
                    little = ''.join(f"{n:02X}" for n in test)
                    byte_str = bytes.fromhex(little)
                    inline_bytes.append(byte_str)
        self.captured_bytes = inline_bytes

    def xor_decrypt_captured(self):
        plain_array = []
        for byte_str in self.captured_bytes:
            if byte_str != b'':
                new_str = ""
                for i in byte_str:
                    new_char = i ^ self.xor_key
                    new_char = chr(new_char)
                    new_str += new_char
            if new_str:
                plain_array.append(new_str)

        # Based on the results from multiple samples the IP address can be reassembled by
        # finding the one that's like \x00xx.xxx.xx. then the one 2 items from that index and then the middle one
        # E.G ['\x00192.168.',       '245',           '152.']
        #         FIRST^           LAST^                ^SECOND
        for i in plain_array:
            pattern = r'\x00\d{1,3}\.\d{1,3}\.'
            match = re.match(pattern, i)
            if match:
                index = plain_array.index(i)
                start_of_c2 = i
                next_item = plain_array[index + 1]
                if "." in next_item:
                    end_of_c2 = next_item
                    c2 = start_of_c2 + end_of_c2
                    self.config['C2'] = c2.lstrip('\x00').rstrip('\x00')
                else:
                    end_of_c2 = next_item
                    middle_of_c2 = plain_array[index + 2]
                    c2 = start_of_c2 + middle_of_c2 + end_of_c2
                    self.config['C2'] = c2.lstrip('\x00').rstrip('\x00')



if __name__ == '__main__':
    file = sys.argv[1]

    plaintext_match, enc_match = YARA.scan(open(file, 'rb').read())

    if plaintext_match:
        ap = AtomicPlaintext(file)
        ap.find_ip_address()
        if ap.config.get('C2'):
            print(json.dumps(ap.config, indent=4))
            exit(0)
        else:
            print("No C2 found.")
            exit(1)
    elif enc_match:
        atomic = AtomicObfuscatedVer1(file)
        atomic.main()
        if atomic.config.get('C2'):
            print(json.dumps(atomic.config, indent=4))
            exit(0)
        else:
            # Try final method
            atomic2 = AtomicObfuscatedVer2(file)
            atomic2.find_mod_init()
            atomic2.gather_inline_bytes()
            atomic2.xor_decrypt_captured()
            if atomic2.config.get('C2'):
                print(json.dumps(atomic2.config, indent=4))
                exit(0)
            else:
                print("No C2 found.")
                exit(1)
    else:
        logging.error("Did not match supported variants.")
        exit(1)
