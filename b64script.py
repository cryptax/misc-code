from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext, IUnitView
from com.pnfsoftware.jeb.core.units import IUnit, IXmlUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units import IInteractiveUnit

import base64

'''
This is a JEB script to automatically perform Base64 decoding of a selected string 
in the disassembly / decompiled class
Adds the decoded string as comment

Coded with inspiration from https://github.com/pnfsoftware/jeb2-samplecode/blob/master/scripts/TranslateString.py :)
'''

class b64script(IScript):
    def run(self, ctx):
        f = ctx.getFocusedFragment()
        if not f:
            print("[-] Select a text (no focused fragment)")
            return

        sel = f.getSelectedText() or f.getActiveItemAsText()
        if not sel:
            print("[-] Select a text (no selected text)")
            return

        b64encoded_string = sel.strip(' \'\"')
        b64decoded_string = self.decode(b64encoded_string)
        print("Base64 decoding: {} --> {}".format(b64encoded_string, b64decoded_string))

        a = f.getActiveAddress()
        if a and isinstance(f.getUnit(), IInteractiveUnit):
            comment0 = f.getUnit().getComment(a)
            comment = b64decoded_string + '\n' + comment0 if comment0 else b64decoded_string
            f.getUnit().setComment(a, comment)

    def decode(self, thestring):
        # print("Base64 decoding: {}".format(thestring)
        return base64.b64decode(thestring)
