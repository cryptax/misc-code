'use strict';

console.log("[*] In Memory Dex Dump v0.1 - @cryptax");

Java.perform(function () {
    var memoryclassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
    memoryclassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(dexbuffer, loader) {
	console.log("[*] Hooking InMemoryDexClassLoader");
	var object = this.$init(dexbuffer, loader);

	/* dexbuffer is a Java ByteBuffer 
	   you cannot dump to /sdcard unless the app has rights to
	 */
	var remaining = dexbuffer.remaining();
	const filename = '/data/data/YOUR-PACKAGE-NAME/dump.dex';
	
	console.log("[*] Opening file name="+filename+" to write "+remaining+" bytes");
	const f = new File(filename,'wb');
	var buf = new Uint8Array(remaining);
	for (var i=0;i<remaining;i++) {
	    buf[i] = dexbuffer.get();
	    //debug: console.log("buf["+i+"]="+buf[i]);
	}
	console.log("[*] Writing "+remaining+" bytes...");
	f.write(buf);
	f.close();
	
	// checking
	remaining = dexbuffer.remaining();
	if (remaining > 0) {
	    console.log("[-] Error: There are "+remaining+" remaining bytes!");
	} else {
	    console.log("[+] Dex dumped successfully in "+filename);
	}

	return object;
    }


});

