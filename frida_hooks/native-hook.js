// I am not the author of this: this is taken from https://pentest.blog/android-malware-analysis-dissecting-hydra-dropper/ and I found it interesting :)

var unlinkPtr = Module.findExportByName(null, 'unlink');
// remove bypass
Interceptor.replace(unlinkPtr, new NativeCallback( function (a){
     console.log("[+] Unlink : " +  Memory.readUtf8String(ptr(a)))
}, 'int', ['pointer']));
var timePtr = Module.findExportByName(null, 'time');
// time bypass
Interceptor.replace(timePtr, new NativeCallback( function (){
    console.log("[+] native time bypass : ")
    return 1554519179
},'long', ['long']));
Java.perform(function() {
    var f = Java.use("android.telephony.TelephonyManager")
    var t = Java.use('java.util.Date')
    //country bypass
    f.getSimCountryIso.overload().implementation = function(){
        console.log("Changing country from " + this.getSimCountryIso() + " to tr ")
        return "tr"
    }
    t.getTime.implementation = function(){
    console.log("[+] Java date bypass ")
    return 1554519179000 
    }
 })
