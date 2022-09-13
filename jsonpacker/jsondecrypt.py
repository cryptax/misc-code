#!/usr/bin/env python3
import argparse
import logging
from typing import List

'''
JsonPacker unpacker
@cryptax - Sept 13, 2022
'''

log = logging.getLogger('json-decrypt')
log_format = '[%(asctime)s] [%(levelname)s] %(module)s%(funcName)20s() - %(message)s'
logging.basicConfig(level=logging.WARNING, format=log_format)


def parse_args():
    parser = argparse.ArgumentParser(description='JsonPacker unpacker', prog='jsondecrypt')
    parser.add_argument('-i', '--input', help='encrypted payload', action='store', required=True)
    parser.add_argument('-o', '--output', help='decrypted payload', action='store', default='unpacked.zip')
    parser.add_argument('-k', '--key', help='short key', action='store', default='PIFnp')
    parser.add_argument('-v', '--verbose', help='print debug messages', action='store_true')
    return parser.parse_args()


def swap(array, i: int, j: int):
    # Swap array[i] and array[j]. Beware, this modifies "array"
    temp = array[i]
    array[i] = array[j]
    array[j] = temp
    return array


class JsonDecrypt:
    def __init__(self, filename: str, short_key: str):
        # filename: file path to encrypted payload
        # short key present in the packer
        log.debug(f'Reading {filename}...')
        with open(filename, 'rb') as f:
            self.input = f.read()
        self.short_key = short_key
        self.expanded_key = []  # array of int

    def _expand_key(self) -> List[int]:
        # expands the short key to an array of ints - this expanded key is used for decryption
        log.debug(f'Expanding key...')
        for i in range(0, 256):
            self.expanded_key.append(i)

        j = 0
        for i in range(0, 256):
            j = (j + self.expanded_key[i] + ord(self.short_key[i % len(self.short_key)])) % 256
            swap(self.expanded_key, i, j)

        return self.expanded_key

    def _decrypt_payload(self) -> List[bytes]:
        # decrypts self.input (read during construction) and returns output
        # the decryption key self.expanded_key
        i = 0
        j = 0
        output = []
        assert len(self.expanded_key) > 0, "key hasn't been expanded"
        log.debug('Decrypting payload...')

        for k in range(0, len(self.input)):
            i = (i + 1) % 256
            j = (j + self.expanded_key[i]) % 256
            swap(self.expanded_key, i, j)
            key_loop = self.expanded_key[(self.expanded_key[i] + self.expanded_key[j]) % 256]  # int
            out_int = key_loop ^ self.input[k]
            out_byte = (out_int & 0xff).to_bytes(1, byteorder='big')
            # log.debug(f'k={k} key_loop={key_loop} output={out_byte}')
            output.append(out_byte)
        return output

    def decrypt(self, output_file='unpacked.zip'):
        # decrypts the encrypted payload (self.input) and writes the decrypted bytes to output file
        with open(output_file, 'wb') as f:
            self._expand_key()
            output_bytes = self._decrypt_payload()
            log.debug(f'Writing {output_file}...')
            for o in output_bytes:
                f.write(o)


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)
        log.debug('Setting DEBUG messages')
    log.info('JsonDecrypt unpacking - Greetings from @cryptax')
    jd = JsonDecrypt(args.input, args.key)
    jd.decrypt(args.output)
    log.debug('Done. Bye!')
