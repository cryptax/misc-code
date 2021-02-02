'use strict';

console.log("[*] Hooking dynamic class / method ");

Java.perform(function(){
    var dexclassLoader = Java.use("dalvik.system.DexClassLoader");
    
    dexclassLoader.loadClass.overload('java.lang.String').implementation = function(name){
        var dyn_class_name = "PUT COMPLETE NAME OF DYNAMICALLY LOADED CLASS";
        var result = this.loadClass(name,false);
        if(name == dyn_class_name){
	    var active_classloader = result.getClassLoader();
	    var factory = Java.ClassFactory.get(active_classloader);
	    var class_hook = factory.use(dyn_class_name);
	    class_hook.PUTNAMEOFMETHOD.implementation = function(encrypted) {
		// WRITE HOOK FOR a()
		// HERE
		return decrypted;
	    }
		    
            return result;
	    
        }
        return result;
    }
});

