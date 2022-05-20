#?description=De-obfuscate strings in Android/Ermac2 malware
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext, IUnitView
from com.pnfsoftware.jeb.core.units import IUnit, IXmlUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units import IInteractiveUnit
from Crypto.Cipher import AES
import base64

'''
This is a JEB script to automatically decrypt strings in Ermac2 malware
Malicious sample: 2cc727c4249235f36bbc5024d5a5cb708c0f6d3659151afc5ae5d42d55212cb5
Coded with inspiration from https://github.com/pnfsoftware/jeb2-samplecode/blob/master/scripts/TranslateString.py :)
'''

def create_byte_array(s):
    return list(bytearray.fromhex(s.decode('utf-8')))

class DecryptErmac2(IScript):
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
        decrypted_string = self.do_decrypt(b64encoded_string)
        print("Obfuscated: {} --> Cleartext: {}".format(b64encoded_string, decrypted_string))

        a = f.getActiveAddress()
        if a and isinstance(f.getUnit(), IInteractiveUnit):
            comment0 = f.getUnit().getFullComment(a)
            comment = decrypted_string + '\n' + comment0 if comment0 else decrypted_string
            f.getUnit().setPrimaryComment(a, comment)

    def decrypt(self,  encrypted, key="sosi_sosison____"):
        # the encrypted string consists of 2 base64 chunks: ciphertext::iv
        decoded = base64.b64decode(encrypted)
        ciphertext, iv = decoded.split('::')

        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext)


