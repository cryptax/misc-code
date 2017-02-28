#!/usr/bin/env python

'''
Standalone Python program to de-obfuscate Android/Ztorg strings
Example:

$ python string-decode.py -i '50, 64, 63, 42, 70, 41'
[$1]
'''


import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description='Ztorg string de-obfuscation')
    parser.add_argument('-i', '--input', help='bytes to decode - provide something like 1,2,3', action='store')
    args = parser.parse_args()
    return args

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

    return result

if __name__ == "__main__":
    args = get_arguments()
    array = [ int(i) for i in args.input.split(',') ]
    result = decodeBytes(array)
    print ''.join(map(chr,result))


