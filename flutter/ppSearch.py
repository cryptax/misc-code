"""
Python script to print Dart object usages
in Object Pool of flutter libapp.so Aarch64

usage: ppSearch.py [-h] [--binary BINARY] [-f] hex_value

positional arguments:
  hex_value        Hex value to search

options:
  -h, --help       show this help message and exit
  --binary BINARY  Path to the binary file
  -f               Print Matches along with their function address

Example(s):
1. Outside r2-shell:
~$ python ppSearch.py --binary libapp.so 0x88f0
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

2. Within r2-shell:
$ r2 -e log.quiet=true ../libapp.so
 -- This is fine.
[0x00370000]> #!pipe python3 flutter/ppSearch.py 0x1a020 | tee /dev/null
The First Target is: 0x1a
The Second Target is: 0x20
Found 4 direct matches:
            0x004b2c74      706b4091       add x16, x27, 0x1a, lsl 12
            0x004b2c78      101240f9       ldr x16, [x16, 0x20]

            0x008b2da8      706b4091       add x16, x27, 0x1a, lsl 12
            0x008b2dac      101240f9       ldr x16, [x16, 0x20]

            0x008b3634      706b4091       add x16, x27, 0x1a, lsl 12
            0x008b3638      101240f9       ldr x16, [x16, 0x20]

            0x008b3654      616b4091       add x1, x27, 0x1a, lsl 12
            0x008b3658      211040f9       ldr x1, [x1, 0x20]

Script execution time: 9.47 seconds
[0x009c921c]>

3. Use `-f` to print function address along with the matches:
$ python3 flutter/ppSearch.py --binary ../libapp.so 0x1a020 -f
The First Target is: 0x1a
The Second Target is: 0x20
Found 4 direct matches:
Function: 0x004b2a98
│           0x004b2c74      706b4091       add x16, x27, 0x1a, lsl 12
│           0x004b2c78      101240f9       ldr x16, [x16, 0x20]

Function: 0x008b2514
│           0x008b2da8      706b4091       add x16, x27, 0x1a, lsl 12
│           0x008b2dac      101240f9       ldr x16, [x16, 0x20]

Function: 0x008b3610
│           0x008b3634      706b4091       add x16, x27, 0x1a, lsl 12
│           0x008b3638      101240f9       ldr x16, [x16, 0x20]

Function: 0x008b3610
│           0x008b3654      616b4091       add x1, x27, 0x1a, lsl 12
│           0x008b3658      211040f9       ldr x1, [x1, 0x20]

Script execution time: 22.95 seconds
"""

import re
import time
import argparse
import importlib
import subprocess
import sys

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
BLUE = "\033[0;34m"
NC = "\033[0m"


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


def run_command(binary, first_target, second_target, fcn_addr=False):
    """Running our r2pipe"""
    if r2pipe.in_r2():
        r2 = r2pipe.open()
        r2.cmd("e log.quiet=true")
        r2.cmd("e bin.strings=false")
    else:
        r2 = r2pipe.open(binary, flags=["-z", "-e", "log.quiet=true"])

    if fcn_addr:
        r2.cmd("aac")
    output = []
    for line in r2.cmd(
        f"/ad/ add.*, x27, {first_target}, lsl 12; .*, [.*, {second_target}]"
    ).split("\n"):
        if line.strip():
            match_address = line.split(" ")[0]
            r2.cmd(f"s {match_address}")
            disasm = r2.cmd("pd3")
            if fcn_addr:
                func_address = r2.cmd("afl.").strip()
                output.append((func_address, disasm.strip()))
            else:
                output.append(("", disasm.strip()))

    r2.quit()
    return output


def search_patterns(output, pattern1, pattern2):
    """
    Searches for two specific instruction patterns
    in consecutive lines of a disasm output file.

    Parameters:
    :param file_path: Path to the disasm output file.
    :param pattern1: A regular expression pattern to match the first instruction.
    :param pattern2: A regular expression pattern to match the second instruction.

    Returns:
    - A list of matches found in the disasm output.
    """
    matches = []
    for func_addr, disasm in output:
        lines = disasm.split("\n")
        for i in range(len(lines) - 1):  # -1 to avoid IndexError
            if pattern1.search(lines[i]) and pattern2.search(lines[i + 1]):
                matches.append((func_addr, lines[i], lines[i + 1]))
    return matches


def main():
    """Main function to run the program."""

    start_time = time.time()

    parser = argparse.ArgumentParser(
        description="Search for Dart object usages in Object Pool of flutter libapp.so Aarch64."
    )
    parser.add_argument(
        "--binary", type=str, help="Path to the binary file", required=False
    )
    parser.add_argument("hex_value", type=str, help="Hex value to search")
    parser.add_argument(
        "-f",
        action="store_true",
        help="Print Matches along with their function address",
        required=False,
    )
    args = parser.parse_args()

    binary = args.binary
    hex_value = args.hex_value

    first_target = hex_value[0:-3]

    values = {"a", "b", "c", "d", "e", "f"}

    check_first = first_target.lstrip("0x")
    check_first = check_first[1:] if check_first.startswith("0") else check_first

    if len(check_first) == 1 and check_first not in values:
        first_target = check_first

    if hex_value[-3:-1] == "00":
        second_target = hex_value[-1:]
    elif hex_value[-3:-2] == "0":
        second_target = "0x" + hex_value[-2:]
    else:
        second_target = "0x" + hex_value[-3:]
    print(f"The First Target is: {BLUE}{first_target}{NC}")
    print(f"The Second Target is: {BLUE}{second_target}{NC}")

    sys.stdout.write(f"{YELLOW}Looking for matches...{NC}" + "\r")

    output = run_command(binary, first_target, second_target, fcn_addr=args.f)

    instr_pattern1 = re.compile(f"add\s+(x\d+),\s+x27,\s+{first_target},\s+lsl\s+12")
    instr_pattern2 = re.compile(f"ldr\s+(x\d+),\s+\[(x\d+),\s+{second_target}]")

    matches = search_patterns(output, instr_pattern1, instr_pattern2)

    if matches:
        print(f"Found {GREEN}{len(matches)}{NC} direct matches:")
        for func_addr, line1, line2 in matches:
            if args.f and func_addr:
                print(f"Function: {GREEN}{func_addr.split()[0]}{NC}")
            print(f"{line1}")
            print(f"{line2}\n")
    else:
        print(f"{RED}No matches found.{NC}")

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Script execution time: {execution_time:.2f} seconds")


if __name__ == "__main__":
    main()
