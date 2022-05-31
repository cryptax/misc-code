'use strict';

console.log("[*] DexClassLoader Dump v0.1 - buggy - @cryptax");

Java.perform(function () {
    var classLoader = Java.use("dalvik.system.DexClassLoader");
    var pathLoader = Java.use("dalvik.system.PathClassLoader");
    var File = Java.use('java.io.File');
    const FileInputStream = Java.use('java.io.FileInputStream');
    const FileOutputStream = Java.use('java.io.FileOutputStream');
    const BufferedInputStream = Java.use('java.io.BufferedInputStream');
    const BufferedOutputStream = Java.use('java.io.BufferedOutputStream');

    classLoader.$init.implementation = function(filename, b, c, d) {
	    console.log("[*] Hooking DexClassLoader: file="+filename);  
        var sourceFile = File.$new.overload('java.lang.String').call(File, filename);
        var destinationFile = File.$new.overload('java.lang.String').call(File, '/sdcard/dump.dex');
        destinationFile.createNewFile();
        if (sourceFile.exists() && sourceFile.canRead()) {
            console.log("File found")
            var fileInputStream = FileInputStream.$new.overload('java.io.File').call(FileInputStream, sourceFile);
            var fileOutputStream = FileOutputStream.$new.overload('java.io.File').call(FileOutputStream, destinationFile);
            var bufferedInputStream = BufferedInputStream.$new.overload('java.io.InputStream').call(BufferedInputStream, fileInputStream);
            var bufferedOutputStream = BufferedOutputStream.$new.overload('java.io.OutputStream').call(BufferedOutputStream, fileOutputStream);
            var data = 0;
            while ((data = bufferedInputStream.read()) != -1) {
                bufferedOutputStream.write(data);
                console.log('buffuredInputStream : ' + data);
            }
            bufferedInputStream.close();
            fileInputStream.close();
            bufferedOutputStream.close();
            fileOutputStream.close();
        } else {
            console.log("[-] Could not find file="+filename)
        }

        console.log("[*] continuing...")
        return this.$init(filename, b, c, d);
    }

    pathLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, b) {
        console.log("[*] Hooking PathClassLoader 1: file="+filename);
        return this.$init(filename, b);
    }

    pathLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(filename, b, c) {
        console.log("[*] Hooking PathClassLoader 2: file="+filename);
        return this.$init(filename, b, c);
    }

    File.delete.implementation = function() {
        var s = this.getAbsolutePath();
        console.log("[*] dont delete: "+s);
        return true;
    }

    var memoryclassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
    memoryclassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(dexbuffer, loader) {
	    console.log("[*] Hooking InMemoryDexClassLoader");
	    var object = this.$init(dexbuffer, loader);
        return object;
    }


});

