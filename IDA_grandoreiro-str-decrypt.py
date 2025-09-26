import idautils
import idaapi
import ida_lines
import ida_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

string_table_locations = []
KEY = "D9JL@2]790B{P_D}Z-MXR&EZLI%3W>#VQ4UF+O6XVWB16713NIO!E8MY2<[NRHY(¨)GAT5SCA0.5SC8FKKQP:HU$G4*TJKMOW65&_Z*JCVVDQP8RLHL7F%UR)MJOUT.I0NX}BSX2S]¨A!A+3YPG3$N919YQ,4Z(8@-7H4WGF<D}{#2C:6K1TI05E[EBYCX2T<F31#Z(RMEV%5,8L]$YJAG[RTQ+S}V)ZHJE2X¨05I0W_3NO&P7D1HA7GK!*6ND.C>LIQ-O4BM8UFK@BSP6{4W:U99)4V%NS_JMPHI!I$KS71:VBWDCF#3<0+]¨MG2TAX-C{LRQ@PJ56E8B75LA2&Y(61H8.,ZZE[D0XY*4U9Q}OK3OWRFNU9TGX0D_{KP>(Z&#:XWJDM0BV2HCNLIJU.<4*9EQ-])C8UG%E!KH1@29TM5L7YP+[ON4W1A8R6T¨ROSVQ6Y3S5BFAFZ7,}$IG39B{Z9HG@IE1L%R¨WJS}H[BZ>SG6&U)QR8]LAO4:UPM2!K,7(VVWT-P1DKC68M5Y2TIY5FX#O<3NFXD3C7JA00$+Q_E4N*.XYWA¨#]!{PBO1NIV@O,1EZKD(RL40FIY}753$>52&UQXLN%J)_D406HM-K2E99GSFQ.H7C*[WTS6CZJ+8GRBMA3TUP8:VKT4H$W95D@ELFD2Z*,PTX-#A+UYMR(C1CM!H5U30G%3S&YL4GRXOV_QB)SJP:87{0BJ]Z9.O>N7126[IWNV}EK6<I8F¨AQJ)7O-ZKM#B1,XG:4ZF@Y_EHR8IWN4T(VXU8!%W5L6AUBACST6DJSE{<YIK9>M&QO0F*R9}]0LP3+3Q¨H1P57G22N.CDYQ8RXQBXZ[)A2UDZPMT¨C.*5MS{43-*JLK0EJI6C0776H@,NR]BAO29N814HDSOVF!YLEWI5_1%K3>W<GGF#UT(9}VLOD1&XA9Y4QFZP!J@XJG¨:-GS02}AM6CHU]P[305T%WYPX:3]TS6CZJ+8GRBMA3TUP8:V'SB.V<UW}C]PY:R,5DB%OAH(TR[B8<&EFV+SU6P3DZYX_WX7!7Z{2N>O.9$4T1QFJGKME580@A*C9MKJQG2-UL4V#I¨H361SI0N1H7DJVW6UG&GT%4SHE-IB612RXOM5S{43-*JLK0IJ6K46(KJ1KK2R9H8L{OSB.V<U¨LD1&A9Y4QFZP!J@E$&JPM3{OMC6+PCKZ0G]4FAD-V1BW.4FSLYRQZ1_5853;N0NTGLT0ZYP(9]TM5ULTYCOD6HKM-K2E99GSFQ.D©E991UA0>N5VH91RFC6Z*XMT%EMZ(O4OC&W¨QF:Z4L3]NFXD3C7JA00$4AB)ET55AB)IG3X8D7293E9CTKJ2R9H8L{OSB.V<U12[E9HWSH(-3>87+Y2G@M08,P1GCY:F3FK*]4LXTJXKPOVAWQ!¨J@E$D9JL@2]790B{P_D}Z-MXR&EZLI%3W>#VQ4UF+O6XVWB16713NIO!E8MY2<[NRHY(¨)GAT5SCA0.5SC8FKKQP:HU$G4*TJKMOW65&_Z*JCVVDQP8RLHL7F%UR)MJOUT.I0NX}BSX2S]¨A!A+3YPG3$N919YQ,4Z(8@-7H4WGF<D}{#2C:6K1TI05E[EBYCX2T<F31#Z(RMEV%5,8L]$YJAG[RTQ+S}V)ZHJE2X¨05I0W_3NO&P7D1HA7GK!*6ND.C>LIQ-O4BM8UFK@BSP6{4W:U99)4V%NS_JMPHI!I$KS71:VBWDCF#3<0+]¨MG2TAX-C{LRQ@PJ56E8B75LA2&Y(61H8.,ZZE[D0XY*4U9Q}OK3OWRFNU9TGX0D_{KP>(Z&#:XWJDM0BV2HCNLIJU.<4*9EQ-])C8UG%E!KH1@29TM5L7YP+[ON4W1A8R6T¨ROSVQ6Y3S5BFAFZ7,}$IG39B{Z9HG@IE1L%R¨WJS}H[BZ>SG6&U)QR8]LAO4:UPM2!K,7(VVWT-P1DKC68M5Y2TIY5FX#O<3NFXD3C7JA00$+Q_E4N*.XYWA¨#]!{PBO1NIV@O,1EZKD(RL40FIY}753$>52&UQXLN%J)_D406HM-K2E99GSFQ.H7C*[WTS6CZJ+8GRBMA3TUP8:VKT4H$W95D@ELFD2Z*,PTX-#A+UYMR(C1CM!H5U30G%3S&YL4GRXOV_QB)SJP:87{0BJ]Z9.O>N7126[IWNV}EK6<I8F¨AQJ)7O-ZKM#B1,XG:4ZF@Y_EHR8IWN4T(VXU8!%W5L6AUBACST6DJSE{<YIK9>M&QO0F*R9}]0LP3+3Q¨H1P57G22N.CDYQ8RXQBXZ[)A2UDZPMT¨C.*5MS{43-*JLK0EJI6C0776H@,NR]BAO29N814HDSOVF!YLEWI5_1%K3>W<GGF#UT(9}VLOD1&XA9Y4QFZP!J@XJG¨:-GS02}AM6CHU]P[305T%WYPX:3]TS6CZJ+8GRBMA3TUP8:V'SB.V<UW}C]PY:R,5DB%OAH(TR[B8<&EFV+SU6P3DZYX_WX7!7Z{2N>O.9$4T1QFJGKME580@A*C9MKJQG2-UL4V#I¨H361SI0N1H7DJVW6UG&GT%4SHE-IB612RXOM5S{43-*JLK0IJ6K46(KJ1KK2R9H8L{OSB.V<U¨LD1&A9Y4QFZP!J@E$&JPM3{OMC6+PCKZ0G]4FAD-V1BW.4FSLYRQZ1_5853;N0NTGLT0ZYP(9]TM5ULTYCOD6HKM-K2E99GSFQ.D©E991UA0>N5VH91RFC6Z*XMT%EMZ(O4OC&W¨QF:Z4L3]NFXD3C7JA00$4AB)ET55AB)IG3X8D7293E9CTKJ2R9H8L{OSB.V<U12[E9HWSH(-3>87+Y2G@M08,P1GCY:F3FK*]4LXTJXKPOVAWQ!¨J@E$D9JL@2]790B{P_D}Z-MXR&EZLI%3W>#VQ4UF+O6XVWB16713NIO!E8MY2<[NRHY(¨)GAT5SCA0.5SC8FKKQP:HU$G4*TJKMOW65&_Z*JCVVDQP8RLHL7F%UR)MJOUT.I0NX}BSX2S]¨A!A+3YPG3$N919YQ,4Z(8@-7H4WGF<D}{#2C:6K1TI05E[EBYCX2T<F31#Z(RMEV%5,8L]$YJAG[RTQ+S}V)ZHJE2X¨05I0W_3NO&P7D1HA7GK!*6ND.C>LIQ-O4BM8UFK@BSP6{4W:U99)4V%NS_JMPHI!I$KS71:VBWDCF#3<0+]¨MG2TAX-C{LRQ@PJ56E8B75LA2&Y(61H8.,ZZE[D0XY*4U9Q}OK3OWRFNU9TGX0D_{KP>(Z&#:XWJDM0BV2HCNLIJU.<4*9EQ-])C8UG%E!KH1@29TM5L7YP+[ON4W1A8R6T¨ROSVQ6Y3S5BFAFZ7,}$IG39B{Z9HG@IE1L%R¨WJS}H[BZ>SG6&U)QR8]LAO4:UPM2!K,7(VVWT-P1DKC68M5Y2TIY5FX#O<3NFXD3C7JA00$+Q_E4N*.XYWA¨#]!{PBO1NIV@O,1EZKD(RL40FIY}753$>52&UQXLN%J)_D406HM-K2E99GSFQ.H7C*[WTS6CZJ+8GRBMA3TUP8:VKT4H$W95D@ELFD2Z*,PTX-#A+UYMR(C1CM!H5U30G%3S&YL4GRXOV_QB)SJP:87{0BJ]Z9.O>N7126[IWNV}EK6<I8F¨AQJ)7O-ZKM#B1,XG:4ZF@Y_EHR8IWN4T(VXU8!%W5L6AUBACST6DJSE{<YIK9>M&QO0F*R9}]0LP3+3Q¨H1P57G22N.CDYQ8RXQBXZ[)A2UDZPMT¨C.*5MS{43-*JLK0EJI6C0776H@,NR]BAO29N814HDSOVF!YLEWI5_1%K3>W<GGF#UT(9}VLOD1&XA9Y4QFZP!J@XJG¨:-GS02}AM6CHU]P[305T%WYPX:3]TS6CZJ+8GRBMA3TUP8:V'SB.V<UW}C]PY:R,5DB%OAH(TR[B8<&EFV+SU6P3DZYX_WX7!7Z{2N>O.9$4T1QFJGKME580@A*C9MKJQG2-UL4V#I¨H361SI0N1H7DJVW6UG&GT%4SHE-IB612RXOM5S{43-*JLK0IJ6K46(KJ1KK2R9H8L{OSB.V<U¨LD1&A9Y4QFZP!J@E$&JPM3{OMC6+PCKZ0G]4FAD-V1BW.4FSLYRQZ1_5853;N0NTGLT0ZYP(9]TM5ULTYCOD6HKM-K2E99GSFQ.D©E991UA0>N5VH91RFC6Z*XMT%EMZ(O4OC&W¨QF:Z4L3]NFXD3C7JA00$4AB)ET55AB)IG3X8D7293E9CTKJ2R9H8L{OSB.V<U12[E9HWSH(-3>87+Y2G@M08,P1GCY:F3FK*]4LXTJXKPOVAWQ!¨J@E$"


def decrypt(ciphertext, key):
    plain = ''

    cipher = bytes.fromhex(ciphertext)
    for i in range(1, len(cipher)):
        n = cipher[i] ^ ord(key[(i - 1) % len(key)])
        c = cipher[i - 1]
        c = n - c if c < n else n + int(0xff) - c
        plain += chr(c)
    return plain


def finalDecrypt(b64Text):
    cipherText = bytes.fromhex(b64Text)
    aesKey = b"J)7O-ZKM#B1,XG:4"
    cipher = AES.new(aesKey, AES.MODE_ECB)
    plain_text = cipher.decrypt(pad(cipherText, AES.block_size))
    return plain_text


def customHexEncoding(encrypted, mode):
    STANDARD_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    CUSTOM_ENCODING   = 'XTWGVSQUPC@)%*#$!&_-=?:;[]{}|<>/\\"`~'

    translation_table = str.maketrans(CUSTOM_ENCODING, STANDARD_ALPHABET)

    hex_encoded = encrypted.translate(translation_table)

    # remove the beginnning empty bytes
    if mode == 0:
        hex_encoded = hex_encoded[8:]
    return hex_encoded


def decrypt_str_main(enc_str):
    enc_str = enc_str.decode('ascii', 'ignore')
    hex_encoded_1 = customHexEncoding(enc_str, 0)
     
    # Make sure there's proper amount of bytes
    if (len(hex_encoded_1) % 2 != 0):
        # Get last character
        last_char = hex_encoded_1[len(hex_encoded_1)-1:len(hex_encoded_1)]
        encoded = hex_encoded_1[:-1]
        encoded += '0'
        encoded += last_char
        
    decrypted_string = finalDecrypt(hex_encoded_1)
    decrypted_string = decrypted_string.decode('ascii', 'ignore')
    
    if '\x00' in decrypted_string:
        decrypted_string = decrypted_string.split('\x00')
        decrypted_string = decrypted_string[0]
    elif '\x8d' in decrypted_string:
        decrypted_string = decrypted_string.split('\x8d')
        decrypted_string = decrypted_string[0]
    elif '\x08' in decrypted_string:
        decrypted_string = decrypted_string.split('\x08')
        decrypted_string = decrypted_string[0]
        
    encoded_2 = customHexEncoding(decrypted_string, 1)
    
    output = decrypt(encoded_2, KEY)
    return output


def lookupString(func_location, str_value):
     str_func = idaapi.get_func(func_location)
     cur_addr = str_func.start_ea
     end_addr = str_func.end_ea
     while cur_addr <= end_addr:
          disas = idc.GetDisasm(cur_addr)
          if 'mov' in disas:
               if 'case ' + str(str_value) in disas:
                   target_str_disasm_addr = idc.next_head(cur_addr, end_addr)
                   str_offset = get_operand_value(target_str_disasm_addr, 1)
                   string = idc.get_strlit_contents(str_offset, -1, STRTYPE_C_16)
                   return string
          cur_addr = idc.next_head(cur_addr, end_addr)


def getArgAtXref(xrefs):
     previous_ins = xref - 5
     str_value_to_lookup = idc.get_operand_value(previous_ins, 1)
     return str_value_to_lookup
          


for func in idautils.Functions():
     if ('StringTable' in idc.get_func_name(func)) or ('StringLookup' in idc.get_func_name(func)):
          string_table_locations.append(func)
          
print("[+] Found string table functions!")
print(string_table_locations)
print("-----------------------------------")
print("[!] Looking for XREFS!")

for st in string_table_locations:
     xrefs = idautils.CodeRefsTo(st, 0)
     print("[+] Found XREFS to: " + hex(st) + " : " + idc.get_func_name(st))
     
     for xref in xrefs:
          try:
               str_value = getArgAtXref(xref)
               str_lookup = lookupString(st, str_value)
               print("[!] Encrypted str: " + str_lookup.decode('ascii', 'ignore'))
               dec_str = decrypt_str_main(str_lookup)
               cfunc = idaapi.decompile(xref)
               tl = idaapi.treeloc_t()
               tl.ea = xref
               tl.itp = idaapi.ITP_SEMI
               cfunc.set_user_cmt(tl, dec_str)
               cfunc.save_user_cmts()
          except:
               continue
          
     print("-----------------------------------------")
print("[+] Done.")
