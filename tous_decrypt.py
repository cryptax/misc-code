from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext, IUnitView
from com.pnfsoftware.jeb.core.units import IUnit, IXmlUnit
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit
from com.pnfsoftware.jeb.core import RuntimeProjectUtil
from com.pnfsoftware.jeb.core.units import IInteractiveUnit

import base64

'''
This is a JEB script to automatically decrypt Base64+encrypting strings
inside DEX 5a4b556ab46d9e1e86e9cc1f7a233d53c589ecd3ba820ee7255a488f1c145311

Coded with inspiration from https://github.com/pnfsoftware/jeb2-samplecode/blob/master/scripts/TranslateString.py :)
'''

def swap_values(arg2, arg3, arg4):
    '''
    porting dad.calm.invest.c.a(int arg2, int arg3, int[] arg4)
    '''
    prev = arg4[arg2]
    arg4[arg2] = arg4[arg3]
    arg4[arg3] = prev
    
def transform_key(buf):
    '''
    this is a port of int [] dad.calm.invest.c.c(byte [] arg)
    '''
    v1 = []
    v2 = 0

    for v3 in range(0, 0x100):
        v1.append(v3)

    v3_1 = 0
    while v2 < 0x100:
        v3_1 = (v3_1 + v1[v2] + ord(buf[v2 % len(buf)]) + 0x100) % 0x100;
        swap_values(v2, v3_1, v1);
        v2 = v2+1

    return v1

def create_byte_array(s):
    '''
    converts a byte string to a byte array
    '''
    return list(bytearray.fromhex(s.decode('utf-8')))


class DecryptDad:
    def __init__(self, key='dcpmeyucapxy'):
        self.transformed_key = transform_key(list(key))
        self.b = 0
        self.c = 0

    def decrypt(self, buf):
        '''
        this is a port of byte [] dad.calm.invest.c.b(byte [])
        it uses a "transformed key" and applies an ugly algorithm on the buffer
        buf is expected to be an array of bytes
        '''
        result = []
        for i in range(0, len(buf)):
            self.b = (self.b + 1) % 0x100
            v3 = self.transformed_key
            v4 = self.b
            self.c = (self.c + v3[v4]) % 0x100
            swap_values(v4, self.c, v3)
            result.append(self.transformed_key[(self.transformed_key[self.b] + self.transformed_key[self.c]) % 0x100] ^ buf[i]);
        return ''.join([chr(c) for c in result])


class tous_decrypt(IScript):
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
        print("Decrypting: {} --> {}".format(b64encoded_string, decrypted_string))

        a = f.getActiveAddress()
        if a and isinstance(f.getUnit(), IInteractiveUnit):
            comment0 = f.getUnit().getComment(a)
            comment = decrypted_string + '\n' + comment0 if comment0 else decrypted_string
            f.getUnit().setComment(a, comment)


    def do_decrypt(self,  encrypted):
        d = DecryptDad() # initialize the key
        unb64 = base64.b64decode(encrypted) # first, decoded base64 - returns a byte string
        array = create_byte_array(unb64) # convert to an array of bytes
        result = d.decrypt(array) # decrypt
        #print("Decrypted string: {}".format(result))
        return result

