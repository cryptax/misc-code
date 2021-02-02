'use strict';
console.log("[*] Hooking URL constructor");
Java.perform(function(){
    var url = Java.use("java.net.URL");
    url.$init.overload('java.lang.String').implementation = function(url) {
	console.log("URL: "+url);
	return this.$init(url);
    }
});
