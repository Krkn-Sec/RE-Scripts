import re
import sys
import base64
import json
import yara

#---------------------------------------------------------------------
# YARA Rules used to match each method observed used in various Qakbot
# OneNote samples
#---------------------------------------------------------------------
b64Rule = """
rule qakbotnotePowershellBase64Method {
    meta:
        author = "pdaubman - Flashpoint"
        description = "Detects Qakbot OneNote notebooks using the Base64FromString method."
    strings:
        $note_5 = "Copyright @ 2023 Microsoft. All rights reserved. " fullword wide
        $payload_1 = "[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('" ascii
    condition:
        all of them
}
"""

alternatePowershellRule = """
rule alternatePowershellMethod {
    meta:
        author = "pdaubman - Flashpoint"
        description = "Detects Qakbot OneNote notebooks using the Powershell char array method."
    strings:
        $payload_1 = "-Split ' ' ^|" ascii
        $payload_2 = "foreach" ascii
        $payload_3 = "{[char]([convert]::toint16" ascii
        $payload_4 = "cmd&&start"
    condition:
        all of them
}
"""

htaRule = """
rule htaMethod {
    meta:
        author = "pdaubman - Flashpoint"
        description = "Detects Qakbot OneNote notebooks using the HTA method."
    strings:
        $payload_1 = "WScript.Shell"
        $payload_2 = "<html>"
        $payload_3 = "</html>"
        $payload_4 = "RegDelete"
    condition:
        3 of them
}
"""

config = {}

#---------------------------------------------------------------------
# Compiling the YARA rules
#---------------------------------------------------------------------
base64YaraRule = yara.compile(source=b64Rule)
alternatePSYaraRule = yara.compile(source=alternatePowershellRule)
htaYaraRule = yara.compile(source=htaRule)


#---------------------------------------------------------------------
# Branch to take if the HTA YARA rule is matched.
# Qakbot uses an HTA to perform the download and execute.
# Searches for HTTP addresses via Regex.
#---------------------------------------------------------------------
def getURLFromHTML(text):
    # Get HTML chunk
    htmlPattern = r'<html>.*<\/html>'
    htmlData = re.findall(htmlPattern, text, flags=re.DOTALL)

    # Get HTTP from within the HTML
    htmlUrlPattern = r'"http:\/\/.*"'
    htmlUrlMatch = re.findall(htmlUrlPattern, htmlData[0])
    if htmlUrlMatch:
        try:
            htmlUrlString = ''.join(htmlUrlMatch)
            htmlUrlString = htmlUrlString[1:-1]
            htmlUrlArray = htmlUrlString.split(',')
            for item in htmlUrlArray:
                config['Method'] = 'HTML'
                config['URL'] = item
                print(json.dumps(config, indent = 4))
        except:
            print("Failed")


#---------------------------------------------------------------------
# Branch to take if the alternative Powershell YARA rule is matched.
# Qakbot uses a Powershell script containing a char array to
# download and execute.
# First extracts the full powershell command with regex and extracts
# the char array. The char array is then converted to ascii and the
# server address is extracted.
#---------------------------------------------------------------------
def alternatePowershell(text):
    # Get powershell chunk
    powershellPattern = r"powershell.*\.cmd"
    psMatches = re.findall(powershellPattern, text, flags=re.DOTALL)

    # Get the first half of powershell chunk containing the char array
    startPattern = r'.*&&'
    psAltMatch = re.findall(startPattern, psMatches[0], flags=re.DOTALL)

    # Extract only the char array, convert it to ascii from hex, and extract the URL
    if psAltMatch:
        try:
            psString = ''.join(psAltMatch)
            psString = psString[:-2]
            x = psString.split(';')
            z = x[1]
            charArray = z.split("'")
            charString = charArray[1].replace(",", "")
            charString = charString.replace(" ", "")
            plaintext = bytearray.fromhex(charString).decode()
            a = plaintext.split(" ")
            c2 = a[4]
            config['Method'] = 'Alternate Powershell'
            config['URL'] = c2
            print(json.dumps(config, indent = 4))
        except:
            print("Failed")


#---------------------------------------------------------------------
# Branch to take if the Base64 Powershell YARA rule is matched.
# Qakbot uses a Powershell command containing Base64.
# First extracts the full powershell command with regex and extracts
# the Base64. The Base64 is then decoded and the server address is
# extracted.
#---------------------------------------------------------------------
def getBase64(text):
    # Get powershell chunk
    powershellPattern = r"powershell.*\.cmd"
    b64Matches = re.findall(powershellPattern, text, flags=re.DOTALL)

    # Get Base64 chunk within powershell chunk
    b64Pattern = r"\('.*'\)"
    b64match = re.findall(b64Pattern, b64Matches[0], flags=re.DOTALL)

    # Extract Base64 string, decode it, and grab URL from it
    if b64match:
        try:
            b64String = ''.join(b64match)
            b64String = b64String[2:-2]
            decoded = base64.b64decode(b64String)
            asciiRes = decoded.decode('ascii')
            splitAsciiRes = asciiRes.split(' ')
            config['Method'] = 'Powershell Base64'
            config['URL'] = splitAsciiRes[4]
            print(json.dumps(config, indent = 4))
        except:
            print("Failed")


#---------------------------------------------------------------------
# The main function
# Determines the workflow to take based on the YARA rule matches
#---------------------------------------------------------------------
def extract():
    # Open file and read data
    file = sys.argv[1]
    oneNoteData = open(file, 'rb').read()
    text = oneNoteData.decode('utf-8', errors='ignore')

    # Get YARA matches
    b64Matches = base64YaraRule.match(data = text)
    alternatePSMatches = alternatePSYaraRule.match(data = text)
    htaMatches = htaYaraRule.match(data = text)

    # YARA matches decision tree
    if b64Matches:
        getBase64(text)
    elif alternatePSMatches:
        alternatePowershell(text)
    elif htaMatches:
        getURLFromHTML(text)
    else:
        print("No match on %s", file)

#---------------------------------------------------------------------

if __name__ == "__main__":
    extract()
