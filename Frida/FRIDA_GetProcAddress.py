import frida
import sys

def on_message(message, data):
	print(message)

js_code = """

var pGetProcAddress = Module.findExportByName("kernel32.dll", "GetProcAddress");

Interceptor.attach(pGetProcAddress, {
	onEnter: function(args) {
		var funcLookup = args[1].readUtf8String()
		console.log('[+] GetProcAddress: ', funcLookup);
	}
});

"""

if len(sys.argv) < 2:
	print("Usage: {} <path_to_target_application>".format(sys.argv[0]))
	sys.exit(1)

target_exe = sys.argv[1]
target_pid = frida.spawn([target_exe])
session = frida.attach(target_pid)
script = session.create_script(js_code)
script.on('message', on_message)
script.load()
frida.resume(target_pid)
input("Press [Enter] to exit...\n")
