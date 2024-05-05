"""
Python script to print Dart object uses 
in Object Pool of flutter libapp.so Aarch64

Usage:
~ $ python ppSearch.py [-h] binary hex_value

positional arguments:
  binary      Path to the binary file
  hex_value   Hex value to search

options:
  -h, --help  show this help message and exit

Example:
~$ python ppSearch.py libapp.so 0x88f0
The First Target is 8
The Second Target is 0x8f0
ERROR: Cannot determine entrypoint, using 0x00120000
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
            0x003076fc      70234091       add x16, x27, 8, lsl 12
            0x00307700      107a44f9       ldr x16, [x16, 0x8f0]       ; 0xea


            0x003095bc      60234091       add x0, x27, 8, lsl 12
            0x003095c0      007844f9       ldr x0, [x0, 0x8f0]         ; 0xda


            0x00309fdc      60234091       add x0, x27, 8, lsl 12
            0x00309fe0      007844f9       ldr x0, [x0, 0x8f0]         ; 0xda


            0x00481778      70234091       add x16, x27, 8, lsl 12
            0x0048177c      107a44f9       ldr x16, [x16, 0x8f0]       ; 0xea


            0x00489dfc      70234091       add x16, x27, 8, lsl 12
            0x00489e00      107a44f9       ldr x16, [x16, 0x8f0]       ; 0xea

Script execution time: 12.362151384353638 seconds
"""

import os
import re
import time
import argparse
import importlib
import subprocess
import sys


def import_library(library_name: str, package_name: str = None):
    """
    Loads a library, or installs it in ImportError case
    :param library_name: library name (import example...)
    :param package_name: package name in PyPi (pip install example)
    :return: loaded module
    """
    if package_name is None:
        package_name = library_name

    try:
        return importlib.import_module(library_name)
    except ImportError as exc:
        completed = subprocess.run(
            [sys.executable, "-m", "pip", "install", package_name], check=True
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"Failed to install library {package_name} (pip exited with code {completed.returncode})"
            ) from exc
        return importlib.import_module(library_name)


r2pipe = import_library("r2pipe")


def extract_addresses(file_path):
    """Get addresses"""
    with open(file_path, "r") as file:
        contents = file.read()

    lines = contents.split("\n")

    addresses = []

    for line in lines:
        if line.strip():
            parts = line.split(" ", 1)
            address = parts[0]
            addresses.append(address)

    return addresses


def run_command(binary, first_target, second_target):
    """Running our r2pipe"""
    r2 = r2pipe.open(binary)
    cmd = r2.cmd(
        f"/ad/a add.*, x27, {first_target}, lsl 12; ldr.*, [.*, {second_target}]"
    )
    with open("out.txt", "w") as file:
        file.write(cmd)

    file_path = "out.txt"
    addresses = extract_addresses(file_path)
    for address in addresses:
        cmd2 = r2.cmd(f"s {address};pd3")
        with open("result.txt", "a") as file:
            file.write(cmd2)

    if os.path.exists(file_path):
        os.remove(file_path)

    r2.quit()


def search_patterns(file_path, pattern1, pattern2):
    """
    Searches for two specific instruction patterns
    in consecutive lines of a disassembly output file.

    Parameters:
    :param file_path: Path to the disassembly output file.
    :param pattern1: A regular expression pattern to match the first instruction.
    :param pattern2: A regular expression pattern to match the second instruction.

    Returns:
    - A list of matches found in the disassembly output.
    """
    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    matches = []

    for i in range(len(lines) - 1):  # -1 to avoid IndexError
        if pattern1.search(lines[i]) and pattern2.search(lines[i + 1]):
            matches.append((lines[i], lines[i + 1]))

    return matches


def main():
    """Main function to run the program."""

    start_time = time.time()

    parser = argparse.ArgumentParser(
        description="Search for Dart object uses in Object Pool of flutter libapp.so Aarch64."
    )
    parser.add_argument("binary", type=str, help="Path to the binary file")
    parser.add_argument("hex_value", type=str, help="Hex value to search")
    args = parser.parse_args()

    binary = args.binary
    hex_value = args.hex_value

    first_target = hex_value[0:-3]
    check_first = first_target.strip("0x")

    if len(check_first) == 1:
        first_target = check_first

    if hex_value[-3:-1] =='00':
        second_target = hex_value[-1:]
    elif hex_value[-3:-2] == '0':
        second_target = '0x' + hex_value[-2:] 
    else: 
        second_target = '0x' + hex_value[-3:]

    print("The First Target is", first_target)
    print("The Second Target is", second_target)
    run_command(binary, first_target, second_target)

    instr_pattern1 = re.compile(f"add\s+(\w+),\s+x27,\s+{first_target},\s+lsl\s+12")
    instr_pattern2 = re.compile(f"ldr\s+([\w]+),\s+\[([\w]+),\s+{second_target}\]")

    file_path = "result.txt"
    matches = search_patterns(file_path, instr_pattern1, instr_pattern2)

    for match in matches:
        print(f"{match[0]}{match[1]}\n")

    if os.path.exists("result.txt"):
        os.remove("result.txt")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Script execution time: {execution_time} seconds")


if __name__ == "__main__":
    main()
  
