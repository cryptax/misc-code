#!/usr/bin/env python3
from itertools import cycle
import base64
import re

'''
Decrypts messages/files from Android/Bahamut.BRT!tr
sha256 : fd1aac87399ad22234c503d8adb2ae9f0d950b6edf4456b1515a30100b5656a7

@cryptax - July 9, 2021
'''

def xor(message=b'hello world', key=b'dude'):
    # expects byte string as input
   return bytes(''.join(chr(x ^ y) for (x,y) in zip(message, cycle(key))), 'utf-8')

def decrypt_bahamut(encrypted, key=b'\x30\x31\x31'):
    ''' Performs Base64 decoding + XOR with key
    expects byte string as input
    '''
    plaintext = xor(base64.b64decode(encrypted), key)
    return plaintext

def decrypt_bahamut_file(filename):
    print(f'===== Decrypting {filename} =======')
    buffer = open(filename, 'rb').read()
    parts = re.split(b';', buffer)
    result = ''
    for p in parts:
        plaintext = decrypt_bahamut(p)
        result = result + plaintext.decode('utf-8') + ';'
    # remove trailing ;
    result = result[:-1]
    print(result)
    return result


if __name__ ==   "__main__":
    decrypt_bahamut_file('cn.sed')
    decrypt_bahamut_file('wi.sed')
    encrypted_cnc = b'WEVFQEILHx5YXkVUQl9UREZYVFRTUV9VHlJeXR5EQ1RDHw=='
    print(f"===== CnC =====")
    print(decrypt_bahamut(encrypted_cnc).decode('utf-8'))

