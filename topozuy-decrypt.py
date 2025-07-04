import base64
import argparse

def do_xor(text : bytes, key = '4sI02`LaI<qIDP$?') -> bytes:
    key_bytes = key.encode()
    key_length = len(key)
    return bytes([b ^ key_bytes[i % key_length] for i, b in enumerate(text)])

def get_arguments():
    parser = argparse.ArgumentParser(description='Topozuy string de-obfuscation')
    parser.add_argument('-i', '--input', help='string to decode')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = get_arguments()
    b64d = base64.b64decode(args.input)
    print(f"De-obfuscated: {do_xor(b64d)}")
