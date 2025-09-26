import re
import sys
import hashlib
import json

# Get pattern to match
# This regex pattern looks for a valid IP before ':8081' because when building an implant, the threat actor can't specify or change the port
pattern = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):8081')

# Read the binary and search using the regex pattern
def regexSearch():

    # Open and read the binary
    file = sys.argv[1]
    pe = open(file, 'rb')
    data = pe.read()

    # Hash the binary
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # Use the regex to find the C2 server
    text = data.decode('utf-8', errors='ignore')
    match = re.findall(pattern, text)
    return match, md5, sha1, sha256

# Strip the port number for output
def cleanOutput(match):
    string = ''.join(match)
    string = string[:-5]
    return string

# Generate valid output
def jsonFormat(string, md5, sha1, sha256):
    config = {
        "Tag": "malware:aurora",
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256,
        "C2": string,
        "Port": "8081"
    }
    cfg = json.dumps(config, indent=4)
    return cfg

def main():
    match, md5, sha1, sha256 = regexSearch()
    if not match:
        # Only output the hashes if regex pattern proved unsuccessful
        config = {
            "Tag": "malware:aurora",
            "MD5": md5,
            "SHA1": sha1,
            "SHA256": sha256
        }
        cfg = json.dumps(config, indent=4)
        print(cfg)
    else:
        string = cleanOutput(match)
        cfg = jsonFormat(string, md5, sha1, sha256)
        print(cfg)

if __name__ == "__main__":
    main()
