import pefile
import re
import json
import os
import sys

#--------------------
# Config dictionary
#--------------------
config = {
    'malware':'havoc',
    'Version': [],
    'Inject_Targets': [],
    'Server': [],
    'UserAgent': [],
    'ExeName': []
}

#------------------------
# Extract version number
#------------------------
def extractVersion(pe):
    for section in pe.sections:
        if b'.text' in section.Name:
            textRaw = section.get_data()

    textRaw = textRaw.decode('ascii', 'ignore')
    versionMatch = re.findall(r'v.\..\.\d{3}H', textRaw, re.DOTALL)
    config['Version'].append(versionMatch[0])

#----------------------
# Extract exe name
#----------------------
def extractorExeName(pe):
    for section in pe.sections:
        if b'.edata' in section.Name:
            edataRaw = section.get_data()
    
    edataRaw = edataRaw.decode('ascii', 'ignore')
    filenameMatch = re.findall(r'(\S{10}\.exe)', edataRaw, re.DOTALL)
    ExeName = filenameMatch[0]
    config['ExeName'].append(ExeName)

#-------------------------
# Extraction function
#-------------------------
def extractorMainConfig(rawConf):
    # Vars
    injectTargets = []
    
    # Decode bytes to utf-16
    rawConfDecoded = rawConf.decode('utf-16', errors='ignore')

    # Split data by null bytes
    splitData = rawConfDecoded.split('\x00')
    #print(splitData)
    
    # For each split item, find each config setting through regex rules
    for item in splitData:

        # Search for injection targets through a regex that looks for C:\<anything>.exe
        injectTargetMatch = re.search(r"C:\\.*\.exe", item)
        
        # Search for C2 through a standard IP regex
        ipMatch = re.search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", item)
        
        # Search for a user-agent string using a regex for Mozilla<anything>
        userAgentMatch = re.search(r"Mozilla.*", item)

        # If the regex matches, add the match to the config dict
        if ipMatch:
            c2address = ipMatch.string
            c2address = c2address.encode("ascii", "ignore")
            c2address = c2address.decode()
            c2address = c2address.rstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        if userAgentMatch:
            userAgent = userAgentMatch.string
            userAgent = userAgent.encode("ascii", "ignore")
            userAgent = userAgent.decode()
            userAgent = userAgent.rstrip("\u0000\u0001\u0002\u0003")
        if injectTargetMatch:
            injectTarget = injectTargetMatch.string
            injectTarget = injectTarget.encode("ascii", "ignore")
            injectTarget = injectTarget.decode()
            injectTarget = injectTarget.rstrip("\u0000\u001f\u0001\u0002\u0003")
            injectTargets.append(injectTarget)

    # If any of them are empty, try the same process again but with a different decoding for the raw config data
    # This is necessary as some samples have had a couple of config entries that are in ascii while the rest of the settings are in unicode.
    # Theoretically the config settings that are in ascii were ones that were modified from their default values.
    if not injectTargets or not userAgent or not injectTargets:
        rawConf = rawConf.decode('ascii', errors='ignore')
        splitAgain = rawConf.split('\x00')
        for item in splitAgain:
            injectTargetMatch = re.search(r"C:\\.*\.exe", item)
            ipMatch = re.search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", item)
            userAgentMatch = re.search(r"Mozilla.*", item)
            if ipMatch:
                c2address = ipMatch.string
                c2address = c2address.encode("ascii", "ignore")
                c2address = c2address.decode()
                c2address = c2address.rstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\u0001")
            if userAgentMatch:
                userAgent = userAgentMatch.string
                userAgent = userAgent.encode("ascii", "ignore")
                userAgent = userAgent.decode()
                userAgent = userAgent.rstrip("\u0000\u0001\u0002\u0003")
            if injectTargetMatch:
                injectTarget = injectTargetMatch.string
                injectTarget = injectTarget.encode("ascii", "ignore")
                injectTarget = injectTarget.decode()
                injectTarget = injectTarget.rstrip("\u0000\u001f\u0001\u0002")
                injectTargets.append(injectTarget)

    config['Inject_Targets'].append(injectTargets)
    config['Server'].append(c2address)
    config['UserAgent'].append(userAgent)


#----------------------------
# Get configuration section
#----------------------------
def getRawConfig(pe):
    for section in pe.sections:
        if b'.data' in section.Name:
            configData = section.get_data()
            return configData
            
#--------------------
# Main function
#--------------------
if __name__ == "__main__":
    file = sys.argv[1]
    pe = pefile.PE(file)
    rawConf = getRawConfig(pe)

    try:
        extractorMainConfig(rawConf)
    except Exception as e:
        print(e)

    # Sometimes ExeName and Version entries aren't present in samples.
    # Return None if not present to allow the rest of the extractor to work as expected.
    try:
        extractorExeName(pe)
    except:
        config['ExeName'].append(None)
        
    try:
        extractVersion(pe)
    except:
        config['Version'].append(None)

    print(json.dumps(config, indent=4))
