// De-obfuscating strings from Flubot sample
// sha256: fd5f7648d03eec06c447c1c562486df10520b93ad7c9b82fb02bd24b6e1ec98a
// Uses https://github.com/MichaelRocks/paranoid
// this code is inspired from https://gist.github.com/eybisi/abb844ebde00e6c0d5f6896d61dae911

console.log("=== Deobfuscating strings v3 - @cryptax + thanks to @eybisi ===")
Java.perform(function(){
    // colors are nice
    let Color = {
        Reset: '\x1b[39;49;00m',
        Black: '\x1b[30;01m', Blue: '\x1b[34;01m', Cyan: '\x1b[36;01m', Gray: '\x1b[37;11m',
        Green: '\x1b[32;01m', Purple: '\x1b[35;01m', Red: '\x1b[31;01m', Yellow: '\x1b[33;01m',
        Light: {
            Black: '\x1b[30;11m', Blue: '\x1b[34;11m', Cyan: '\x1b[36;11m', Gray: '\x1b[37;01m',
            Green: '\x1b[32;11m', Purple: '\x1b[35;11m', Red: '\x1b[31;11m', Yellow: '\x1b[33;11m'
        }
    };
    let dalvik = Java.use("dalvik.system.DexFile")
    let dalvik2 = Java.use("dalvik.system.DexClassLoader")
    let dexclassLoader = Java.use("dalvik.system.DexClassLoader");
    dexclassLoader.$init.implementation = function(dexpath,b,c,d){
        console.log(Color.Green+"\n[+] DexClassLoader $init called !\n Hooking dynamically loaded classes from file=",dexpath,Color.Reset)
        this.$init(dexpath,b,c,d)
        try{
            hook_loaded_functions(this)
        }
        catch(e){
            console.log(Color.Red+e,Color.Reset)
        }

    }
    
    function hook_loaded_functions(dexclassloader){
        Java.classFactory.loader = dexclassloader 
        let target_class = "io.michaelrocks.paranoid.Deobfuscator$app$Release"
        try{
            let res = dexclassloader.findClass(target_class)
        }
        catch(e){
            console.log(Color.Red+e,Color.Reset)
            return
        }

        // Class found, you can hook with Java.use since current loader is dexclassloader
        let class_ref = Java.use(target_class)
        console.log(Color.Green+"[+] Found "+class_ref+" hooking getString()...",Color.Reset)
        class_ref.getString.implementation = function(l){
	    var s = this.getString(l);
	    console.log("[+] De-obfuscating: getString("+l+") = "+s)
	    return s;
        }
        // Java.classFactory.loader = oldloader

    }


})
