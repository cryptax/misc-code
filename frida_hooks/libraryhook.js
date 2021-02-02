'use strict';

console.log("[*] Hooking native library  ");

Java.perform(function(){
    var library = Java.use("com.android.a");

    library.a.implementation = function(ctx, s) {
	console.log("[+] native.a: s="+s);
	var ret = this.a(ctx,s);
	console.log("[+] native.a returns ret="+ret);
	return ret;
    }

    library.b.implementation = function(ctx, a, s) {
	console.log("[+] native.b: s="+s);
	var ret = this.b(ctx,a,s);
	console.log("[+] native.b returns ret="+ret);
	return ret;
    }
    

});

