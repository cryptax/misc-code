// De-obfuscating strings from Flubot sample
// sha256: fd5f7648d03eec06c447c1c562486df10520b93ad7c9b82fb02bd24b6e1ec98a
// Uses https://github.com/MichaelRocks/paranoid
// this code is inspired from https://gist.github.com/eybisi/abb844ebde00e6c0d5f6896d61dae911

console.log("=== Dealing with Android/Flubot v1.4 - @cryptax ===")
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

    // hooking DexClassLoader
    let dalvik = Java.use("dalvik.system.DexFile")
    let dalvik2 = Java.use("dalvik.system.DexClassLoader")
    let dexclassLoader = Java.use("dalvik.system.DexClassLoader");
    dexclassLoader.$init.implementation = function(dexpath,b,c,d){
        console.log(Color.Green+"\n[+] DexClassLoader $init called !\n Hooking dynamically loaded classes from file=",dexpath,Color.Reset)
        this.$init(dexpath,b,c,d)
        try{
            hook_in_loaded_classes(this)
        }
        catch(e){
            console.log(Color.Red+e,Color.Reset)
        }

    }

    // hooking URLs
    let url = Java.use("java.net.URL");
    url.$init.overload("java.lang.String").implementation = function(s) {
	console.log("[*] URL="+s)
	return this.$init(s);
    }

    // hooking dynamically loaded classes
    function hook_in_loaded_classes(dexclassloader){
        Java.classFactory.loader = dexclassloader

	// Hook the obfuscator
        /*let target_class = "io.michaelrocks.paranoid.Deobfuscator$app$Release"
        try{
            let res = dexclassloader.findClass(target_class)
        }
        catch(e){
            console.log(Color.Red+e,Color.Reset)
            return
        }

        let class_ref = Java.use(target_class)
        console.log(Color.Green+"[+] Found "+class_ref+" hooking getString()...",Color.Reset)
        class_ref.getString.implementation = function(l){
	    var s = this.getString(l);
	    console.log("[+] De-obfuscating: getString("+l+") = "+s)
	    return s;
        }*/

	// Hook communication with the C&C
	let target_panel = "com.example.myapplicationtest.PanelReq"
	try{
            let res = dexclassloader.findClass(target_panel)
        }
        catch(e){
            console.log(Color.Red+e,Color.Reset)
            return
        }
	let class_panel = Java.use(target_panel)
        console.log(Color.Green+"[+] Found "+class_panel+" hooking Send()...",Color.Reset)
        class_panel.Send.overload('java.lang.String', 'java.lang.String').implementation = function(host, plaintext){
	    console.log("[+] Send: host="+host+" plaintext="+plaintext)
	    var answer = this.Send(host, plaintext)
	    console.log("[+] Send: received="+answer)
	    return answer
        }

	// Hook DGA algo
	let target_dga = "com.example.myapplicationtest.DGA"
	try{
            let res = dexclassloader.findClass(target_panel)
        }
        catch(e){
            console.log(Color.Red+e,Color.Reset)
            return
        }
	let class_dga = Java.use(target_dga)
        console.log(Color.Green+"[+] Found "+class_dga+" hooking GetHost()...",Color.Reset)
        class_dga.GetHost.implementation = function(){
	    let answer = this.GetHost()
	    console.log("[+] GetHost(): host="+answer)
	    return answer
        }

	
        // Java.classFactory.loader = oldloader

    }


})
