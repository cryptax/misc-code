#!/usr/bin/env python3
import sys

INPUT_FILE = "topozuy.exe"
OUTPUT_FILE = "output.bin"
OFFSET = 0xe9e20
SIZE = 0x890600
KEY = b'4sI02`LaI<qIDP$?'

def main():
    with open(INPUT_FILE, "rb") as f:
        f.seek(OFFSET)
        data = f.read(SIZE)

    print("Read:", ' '.join(f"{b:02x}" for b in data[:10]))
    # XOR with repeating key
    xored = bytes([b ^ KEY[i % len(KEY)] for i, b in enumerate(data)])

    with open(OUTPUT_FILE, "wb") as f:
        f.write(xored)

    print(f"Wrote {len(xored)} bytes to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
