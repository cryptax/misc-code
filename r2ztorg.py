#! /usr/bin/env python
#
# A. Apvrille - April 28, 2017
#
# radare2 script to decode Android/Ztorg obfuscated strings
#
# Requirement: r2pipe (e.g. pip install r2pipe)
# Run from r2: #!pipe python r2ztorg.py address length
# e.g. #!pipe python ../r2ztorg.py 0x0007bedc 4

import r2pipe
import sys

def decodeBytes(buf):
    '''Decodes the buffer and returns the decoded result
    Similar to La/b/c;->a([B)Ljava/lang/String;
    '''
    key0 = buf[0]
    key1 = buf[len(buf)-1]

    # copy buffer
    result = buf[1:len(buf)-1]

    # decode
    for i in range(0, len(result)):
      result[i] = result[i] ^ key1
      result[i] = result[i] ^ key0

    return ''.join(map(chr,result))

def usage():
    print 'Usage: python r2ztorg.py address length'
    print 'address: beginning of obfuscated string e.g. 0x0007bedc'
    print 'length: nb of bytes of obfuscated string'

# -----------------------------------------
# quick argument check
if len(sys.argv) != 3:
    usage()
    quit()

# go to address and retrieve bytes    
r2p=r2pipe.open()  
cmd = 's '+ sys.argv[1] + ' ; p8 '+ sys.argv[2];
obfuscated_u = r2p.cmd(cmd) # unicode string
tab = [ ord(i) for i in list(obfuscated_u.decode('hex')) ] # convert to int tab
print 'Decoding ', tab
print 'Result: ', decodeBytes(tab)
