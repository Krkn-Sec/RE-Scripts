# Based off of this config extractor: https://github.com/kevthehermit/RATDecoders/blob/master/malwareconfig/decoders/darkcomet.py
# That config extractor uses the "malwareconfig" Python library.
# It was ported to only require pefile and pycryptodome.

import sys
import pefile
import json
from Crypto.Cipher import ARC4

def jsonifyParse(plainConfig):
    # Empty config
    prettyConfig = {}

    # Split config entries by key and value
    config_list = plainConfig.split('\r\n')
    for entries in config_list[1:-1]:
        key, value = entries.split('=')
        value = value.rstrip()[1:-1]
        prettyConfig[key] = value

    # Print json
    print(json.dumps(prettyConfig, indent=4))

def decryptConfig(key, ciphertext):
    # RC4 decrypt the malware configuration
    key = bytes(key, 'utf-8')
    cipher = ARC4.new(key)
    config = cipher.decrypt(ciphertext)
    plainConfig = config.decode('utf-8', errors='ignore')
    return plainConfig

def getVersion(raw_data):
    # Determine key for decryption based on value found in binary. These cannot be changed by the threat actor. It's version dependent.
    if b'#KCMDDC2#' in raw_data:
        return '#KCMDDC2#-890'
    elif b'#KCMDDC4#' in raw_data:
        return '#KCMDDC4#-890'
    elif b'#KCMDDC42#' in raw_data:
        return '#KCMDDC42#-890'
    elif b'#KCMDDC42F#' in raw_data:
        return '#KCMDDC42F#-890'
    elif b'#KCMDDC5#' in raw_data:
        return '#KCMDDC5#-890'
    elif b'#KCMDDC51#' in raw_data:
        return '#KCMDDC51#-890'
    else:
        return None

if __name__ == '__main__':
    # Open file to read raw data to determine version and key
    file = sys.argv[1]
    data = open(file, 'rb').read()
    key = getVersion(data)

    # Open file using pefile to search for resource where the configuration is stored. Configuration is stored in the DCDATA resource.
    pe = pefile.PE(file)
    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
    for entry in rt_string_directory.directory.entries:
        if str(entry.name) == "DCDATA":
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            encryptedCfg = pe.get_memory_mapped_image()[data_rva : data_rva + size]
            configBytes = bytes.fromhex(encryptedCfg.decode("utf-8", errors='ignore'))
            
            # After configuration is located, decrypt and jsonify
            plainConfig = decryptConfig(key, configBytes)
            jsonifyParse(plainConfig)
