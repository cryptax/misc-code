console.log("[*] DexClassLoader/PathClassLoader/InMemoryDexClassLoader Dump v0.9 - @cryptax");

/* Inspired from https://awakened1712.github.io/hacking/hacking-frida/ */
Java.perform(function () {
    const classLoader = Java.use("dalvik.system.DexClassLoader");
    const pathLoader = Java.use("dalvik.system.PathClassLoader");
    const memoryLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
    const delegateLoader = Java.use("dalvik.system.DelegateLastClassLoader");
    const File = Java.use('java.io.File');
    const FileInputStream = Java.use("java.io.FileInputStream");
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const ActivityThread = Java.use("android.app.ActivityThread");
    var counter = 0;

    function dump(filename) {
        var sourceFile = File.$new(filename);
        var fis = FileInputStream.$new(sourceFile);
        var inputChannel = fis.getChannel();

        var application = ActivityThread.currentApplication();
        if (application == null) return ;
        var context = application.getApplicationContext();

        // you cannot dump to /sdcard unless the app has rights to!
        var fos = context.openFileOutput('dump_'+counter, 0);
        counter = counter + 1;

        var outputChannel = fos.getChannel();
        inputChannel.transferTo(0, inputChannel.size(), outputChannel);
        fis.close();
        fos.close();

        console.log("[*] Dumped DEX to dump_"+counter);
    }


    classLoader.$init.implementation = function(filename, b, c, d) {
	    console.log("[*] DexClassLoader hook: file="+filename);  
        dump(filename);
        return this.$init(filename, b, c, d);
    }

    pathLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, parent) {
        console.log("[*] PathClassLoader(file="+filename+', parent)');
        dump(filename);
        return this.$init(filename, parent);
    }

    pathLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, librarySearchPath, parent) {
        console.log("[*] PathClassLoader(file="+filename+", librarySearchPath, parent)");
        dump(filename);
        return this.$init(filename, librarySearchPath, parent);
    }

    delegateLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, parent) {
        console.log("[*] DelegateLastClassLoader(file="+filename+', parent)');
        dump(filename);
        return this.$init(filename, parent);
    }

    delegateLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, librarySearchPath, parent) {
        console.log("[*] DelegateLastClassLoader(file="+filename+", librarySearchPath, parent)");
        dump(filename);
        return this.$init(filename, librarySearchPath, parent);
    }

    delegateLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader', 'boolean').implementation = function(filename, librarySearchPath, parent, resourceLoading) {
        console.log("[*] DelegateLastClassLoader(file="+filename+", librarySearchPath, parent, resourceLoading)");
        dump(filename);
        return this.$init(filename, librarySearchPath, parent, resourceLoading);
    }

    memoryLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(dexbuffer, loader) {
	    var object = this.$init(dexbuffer, loader);

	    /* dexbuffer is a Java ByteBuffer */
	    var remaining = dexbuffer.remaining();
	
        var filename = 'dump_' + counter;
        counter = counter + 1;
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

