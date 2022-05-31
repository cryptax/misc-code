#!/usr/bin/env python3

# Decrypts the encrypted payload found in malicious sample b2398fea148fbcab0beb8072abf47114f7dbbccd589f88ace6e33e2935d1c582
# Cryptax - May 31, 2022

# uses pycryptodome on python 3.10
from Crypto.Cipher import AES
import argparse
import logging
import sys

FORMAT = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig(stream = sys.stdout, 
                    filemode = "w",
                    format = FORMAT, 
                    level = logging.INFO)
logger = logging.getLogger()


def get_arguments():
    """Read arguments for the program and returns the ArgumentParser"""

    parser = argparse.ArgumentParser(description="Decrypting payload for sample \
        b2398fea148fbcab0beb8072abf47114f7dbbccd589f88ace6e33e2935d1c582 - BianLian", prog="decryptb23")
    parser.add_argument('-i', '--input', help='encrypted asset file to decrypt', action='store',)
    parser.add_argument('-o', '--output', help='analysis of input files is written into subdirectories of this directory', action='store', default='.')
    parser.add_argument('-c', '--clearoutput', help='erase the output directory at the end. Indicates you want something quick.', action='store_true')

    args = parser.parse_args()
    return args
    
def decrypt_payload(inputfile, outputfile):
    key = b'Mary has one cat'   
    cipher = AES.new(key, AES.MODE_ECB)

    logger.info(f"Reading {inputfile}...")
    ciphertext = open(inputfile,'rb').read()

    logger.info("Decrypting...")
    plaintext = cipher.decrypt(ciphertext)

    logger.info(f"Writing to {outputfile}...")
    output = open(outputfile, 'wb')
    output.write(plaintext)
    output.close()


if __name__ == '__main__':
    args = get_arguments()
    decrypt_payload(args.input, args.output)
