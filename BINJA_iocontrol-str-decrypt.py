aesDecrypt=Transform['AES-256 CBC']

KEY = "{SHA-256 HASH OF GUID}"

enc_str_offsets = set()

func = bv.get_functions_by_name("IOCONTROL_ARM_StrDecryptByIndex") # Rename the string decrypt function to this or modify this to whatever you named it

for ref in current_function.caller_sites:
    if isinstance(ref.hlil, Call):
        offset = ref.hlil.params[0].constant * 0x96 + 0x10010
        str_len = bv.read(offset, 1)
        enc_str = bv.read(offset + 1, ord(str_len))
        decrypted = aesDecrypt.decode(enc_str, {'key':KEY[:32].encode('utf-8'), 'iv':KEY[31:31+16].encode('utf-8')})
        dec_str = decrypted.decode('utf-8','ignore')        
        bv.write(offset + 1, dec_str)   
