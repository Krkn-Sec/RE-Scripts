import frida
import sys

def on_message(message, data):
    print(message)

js_code = """
var bcrypt = Module.load("bcrypt.dll");
var advapi32 = Module.load("advapi32.dll");

Interceptor.attach(bcrypt.findExportByName("BCryptImportKey"), {
    onEnter: function(args) {
        var hAlgorithm = args[0];
        var hImportKey = args[1];
        var pbKeyObject = args[2];
        var dwKeyObjectLength = args[3];
        var pbInput = args[4];
        var dwInputLength = args[5];
        var dwFlags = args[6];
        // Print key data (up to 64 bytes for visibility)
        var keyData = Memory.readByteArray(pbInput, Math.min(64, dwInputLength.toInt32()));
        console.log('BCryptImportKey: Key data:', keyData);
    }
});

Interceptor.attach(bcrypt.findExportByName("BCryptEncrypt"), {
    onEnter: function(args) {
        var hKey = args[0];
        var pbInput = args[1];
        var cbInput = args[2];
        var pPaddingInfo = args[3];
        var pbIV = args[4];
        var cbIV = args[5];
        var pbOutput = args[6];
        var cbOutput = args[7];
        var pcbResult = args[8];
        var dwFlags = args[9];
        // Print input data to be encrypted (up to 64 bytes for visibility)
        var dataToEncrypt = Memory.readByteArray(pbInput, Math.min(64, cbInput.toInt32()));
        // Print IV if available
        var ivData = pbIV !== NULL ? Memory.readByteArray(pbIV, cbIV.toInt32()) : null;
        console.log('BCryptEncrypt: Data to encrypt:', dataToEncrypt, ' IV:', ivData);
    }
});

Interceptor.attach(advapi32.findExportByName("CryptAcquireContextA"), {
    onEnter: function(args) {
        var phProv = args[0];
        var szContainer = args[1];
        var szProvider = Memory.readCString(args[2]);
        var dwProvType = args[3];
        var dwFlags = args[4];
        console.log('CryptAcquireContextA: Provider:', szProvider, ' Type:', dwProvType);
    }
});

Interceptor.attach(advapi32.findExportByName("CryptAcquireContextW"), {
    onEnter: function(args) {
        var phProv = args[0];
        var szContainer = args[1];
        var szProvider = Memory.readUtf16String(args[2]);
        var dwProvType = args[3];
        var dwFlags = args[4];
        console.log('CryptAcquireContextW: Provider:', szProvider, ' Type:', dwProvType);
    }
});

Interceptor.attach(advapi32.findExportByName("CryptImportKey"), {
    onEnter: function(args) {
        var hProv = args[0];
        var pbData = args[1];
        var dwDataLen = args[2];
        var hPubKey = args[3];
        var dwFlags = args[4];
        // Print key blob, considering it's in a common format like PLAINTEXTKEYBLOB
        var keyBlob = Memory.readByteArray(pbData, dwDataLen);
        console.log('CryptImportKey: Key Blob:', keyBlob);
    }
});

Interceptor.attach(advapi32.findExportByName("CryptEncrypt"), {
    onEnter: function(args) {
        var hKey = args[0];
        var hHash = args[1];
        var Final = args[2];
        var dwFlags = args[3];
        var pbData = args[4];
        var pdwDataLen = args[5];
        var dwBufLen = args[6];
        // Print input data to be encrypted (up to 64 bytes for visibility)
        var dataToEncrypt = Memory.readByteArray(pbData, Math.min(64, pdwDataLen.toInt32()));
        console.log('CryptEncrypt: Data to encrypt:', dataToEncrypt);
    }
});

// Hook other functions similarly as needed...
"""

if len(sys.argv) < 2:
    print("Usage: {} <path_to_target_application>".format(sys.argv[0]))
    sys.exit(1)

# Get the target executable from the command line argument
target_exe = sys.argv[1]
target_pid = frida.spawn([target_exe])
session = frida.attach(target_pid)
script = session.create_script(js_code)
script.on('message', on_message)
script.load()
frida.resume(target_pid) # Resume the process if needed
input("Press [Enter] to exit...") # Keep the Python script running
