# -*- coding: utf-8 -*-
#?description=Create Frida hook for highlighted method
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext
from com.pnfsoftware.jeb.core import Artifact
import re
'''
This is a JEB script to automatically generate a basic Frida hook for the highlighted method in JEB
@cryptax - March 3, 2022

With inspiration from https://bhamza.me/2019/10/06/Automated-Frida-hook-generation-with-JEB.html !
'''
def generate_hook(label, clazz, method, signature, arguments):
    # creates the Frida hook based on label (just a name to for the hook), its class (dotted notation), method
    # signature is expected to be an array (possibly empty)
    # arguments is expected to be an array (possibly empty) of argument names
    hook = "  var jeb2frida_class_{} = Java.use('{}');\n".format(label,clazz)
    hook = hook + "  var jeb2frida_method_{} = jeb2frida_class_{}.{}".format(label, label, method)

    # adding overloads if we have some
    if len(signature) == 0:
        hook = hook + ';\n'
    else:
        hook = hook + '.overload('
    for i in range(0, len(signature)):
        hook = hook + "'{}'".format(signature[i])
        if i < len(signature) -1:
            hook = hook + ','
        if i == len(signature) - 1:
            hook = hook + ");\n"
    
    hook = hook + "  jeb2frida_method_{}.implementation = function({}) {{\n".format(label,','.join(arguments))
    hook = hook + "    console.log('[{}] Hooking {}.{}( {} ):".format(label,clazz,method, ''.join(signature))

    # adding arguments, if we have some
    if len(arguments) == 0:
        hook = hook +  ");\n"
    for i in range(0, len(arguments)):
        hook = hook + " arg{}='+{}".format(i, arguments[i])
        if i < len(arguments) - 1:
            hook = hook + "+'"
        if i == len(arguments) - 1:
            hook = hook + ');\n'

    hook = hook + "    var ret = this.{}({});\n".format(method, ','.join(arguments))
    hook = hook + "    console.log('[{}] returns '+ret);\n".format(label)
    hook = hook + "    return ret;\n  };\n"
    return hook

def generate_file(hooks):
    # generates the Frida script header
    # hooks is expected to be an array of strings
    return "Java.perform(function() {{\n{}}});".format(''.join(hooks))

def convert_class(java_class):
    # converts Landroid/content/Context; to android.content.Context
    if java_class[0] == 'L':
        ret = java_class.replace('/','.')[1:]
    else:
        ret = java_class.replace('/','.')
    return ret

class Jeb2Frida(IScript):

    def run(self, ctx):
        print("[+] Jeb2Frida")

        f = ctx.getFocusedFragment()
        if not f:
            print("[-] Select a text (no focused fragment)")
            return

        sel = f.getSelectedText() or f.getActiveItemAsText()
        if not sel:
            print("[-] Select a text (no selected text)")
            return

        a = f.getActiveAddress()
        splitted_line = a.split(';->')
        if len(splitted_line) != 2:
            print("[-] No method? ", splitted_line)
            print("[-] Have you selected a line with a method?")
            return

        clazz = convert_class(splitted_line[0])
        print("[debug] clazz: "+clazz)

        splitted_method = splitted_line[1].split('(')
        if len(splitted_method) != 2:
            print("[-] No Java Signature? ", splitted_line)
            print("[-] Have you selected a line with a method?")
            return
        method = splitted_method[0]
        if method == "<init>":
            method = "$init"
        print("[debug] method: "+method)

        # remove before (
        splitted_method[1] = re.sub('.*\(', '', splitted_method[1])
        splitted_method[1] = re.sub('\).*', '', splitted_method[1])
        sigs = splitted_method[1].split(';')
        try:
            sigs.remove('')
        except:
            # ok we had no empty field
            pass
        args = [] 
        for i in range(0, len(sigs)):
            sigs[i] = convert_class(sigs[i])
            # args will be generated with names arg0, arg1, arg2...
            args.append('arg{}'.format(i))
        print("[debug] signature: "+' '.join(sigs))
        print("[debug] args: "+ ' '.join(args))

        # we're using method name as label because we don't have anything significantly better to use
        label = method.replace('$','')
        hook = generate_hook(label, clazz, method, sigs, args)

        # print the hook in the console
        print('-'*100)
        print(generate_file(hook))
        print('-'*100)
        
        
        
