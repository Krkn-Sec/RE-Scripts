full = b""
xor_key = <INPUT_FROM_DISASSEMBLY>

xor_key = xor_key.to_bytes(8, 'little')

for head in Heads(read_selection_start(),read_selection_end()):
    operand = print_operand(head,1).rstrip("h")
    if len(operand) < 2:
        operand = "0" + operand
    if len(operand) > 2:
        operand = operand.lstrip("0")
    full += bytes.fromhex(operand)
    
def xor_decrypt(data, key):
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

plain = xor_decrypt(full, xor_key)
print(f"[+] Decrypted: {plain.decode('utf8')}")
