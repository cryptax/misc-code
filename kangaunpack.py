#!/usr/bin/env python3
import struct
import argparse
import logging
from Crypto.Cipher import AES

'''
Decrypts classes.dex when packed with "KangaPack"
June 19, 2023
@cryptax
'''

__version__ = '0.1'

logging.basicConfig(format='%(message)s', level=logging.INFO)

def get_payload(filename:str) -> None:
    logging.debug(f'Reading {filename}...')
    classesdex = open(filename,'rb').read()
    payload_size = struct.unpack('>I', classesdex[-4:])[0]
    logging.debug(f'[+] Payload size: {payload_size}')
    return classesdex[-payload_size-4: -4]

def decrypt(ciphertext:str, filename:str, key: bytes, iv: bytes) -> None:
    logging.debug(f'key={key} iv={iv}')
    cipher=AES.new(key, AES.MODE_CBC, iv)
    plaintext=cipher.decrypt(ciphertext)
    f = open(filename,'wb')
    f.write(plaintext)
    f.close()
    logging.info(f'[+] KangaUnpack: Successfully decrypted to {filename}')

def get_arguments() -> None:
    parser = argparse.ArgumentParser(description='KangaPack unpacker',
                                     prog='kangaunpack.py',
                                     epilog='Version ' + __version__ + ' Greetz from @cryptax')
    parser.add_argument('-f', '--file',
                        help='Packed classes.dex, to unpack',
                        action='store',
                        default='classes.dex')
    parser.add_argument('-o', '--output',
                        help = 'Output filename',
                        action='store',
                        default='decrypted.zip')
    parser.add_argument('-i', '--iv',
                        help='AES Initialization Vector',
                        action='store',
                        default='j2K10uXshMh9UGPS')
    parser.add_argument('-k', '--key',
                        help='AES Decryption Key',
                        action='store',
                        default='j2K10uXshMh9UGPS')
    parser.add_argument('-V', '--version',
                        help='displays version number',
                        action='version',
                        version="%(prog)s "+__version__)
    parser.add_argument('-v', '--verbose',
                        help='displays more verbose info',
                        action='store_true')
    
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    return args
    

if __name__ == "__main__":
    args = get_arguments()
    try: 
        ciphertext = get_payload(args.file)
        decrypt(ciphertext, filename=args.output, key=bytes(args.key,'utf-8'), iv=bytes(args.iv,'utf-8'))
    except FileNotFoundError:
        logging.error(f'Error: File not found: {args.file}')
        
    except (struct.error, IndexError, ValueError):
        logging.error(f'Error: either this is not KangaPack, or you didnt supply the correct packed payload {args.file}')
    
    
    


    
    
    
