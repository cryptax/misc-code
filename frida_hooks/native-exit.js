// https://github.com/frida/frida/issues/2156
function anti_exit() {
    const exit_ptr = Module.findExportByName(null, 'exit');
        if (null == exit_ptr) {
            return;
        }
        Interceptor.replace(exit_ptr, new NativeCallback(function (code) {
            if (null == this) {
                return 0;
            }
            return 0;
        }, 'int', ['int', 'int']));
}
