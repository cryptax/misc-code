"""
Standalone program to find Flutter snapshots and read their header from libapp.so
@cryptax - Feb 13, 2024
"""
import re
import logging
import argparse
from struct import unpack
from enum import Enum

# Constants
MAGIC_VALUE = b'\xf5\xf5\xdc\xdc'

# Logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s-%(levelname)s-%(message)s')


class Libapp:
    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'rb') as f:
            self.buf = f.read()

    def find_snapshots(self):
        # returns offsets of found snapshots
        return [m.start() for m in re.finditer(MAGIC_VALUE, self.buf)]

    def parse(self):
        snapshot_offsets = self.find_snapshots()
        for offset in snapshot_offsets:
            snapshot = Snapshot(self.buf, offset)
            snapshot.parse_snapshot()
            print(snapshot)
            print("-----------")


class SnapshotKindEnum(Enum):
    # See https://github.com/dart-lang/sdk/blob/main/runtime/vm/snapshot.h
    kFull = 0  # Full snapshot of core libraries or an application.
    kFullCore = 1 # Full snapshot of core libraries. Agnostic to null safety.
    kFullJIT = 2  # Full + JIT code
    kFullAOT = 3  # Full + AOT code
    kNone = 4  # gen_snapshot
    kInvalid = 5 


class Snapshot:
    def __init__(self, buf, offset):
        self.features = None
        self.version = None
        self.version_hash = None
        self.kind = None
        self.size = None
        self.buf = buf
        self.offset = offset

    def parse_snapshot(self):
        # skip magic (4 bytes)
        # see https://blog.tst.sh/reverse-engineering-flutter-apps-part-1/
        # u64 size
        self.size = unpack('<q', self.buf[self.offset + 4:self.offset + 4 + 8])[0]
        # u64 kind
        kind = unpack('<q', self.buf[self.offset + 4 + 8:self.offset + 4 + 8 + 8])
        if kind is None or kind[0] < 0 or kind[0] > 5:
            logging.error(f"Unknown snapshot Kind: {kind} (snapshot offset={self.offset})")
            self.kind = SnapshotKindEnum.kInvalid
        else:
            self.kind = SnapshotKindEnum(kind[0])
        self.version_hash = self.buf[self.offset + 4 + 8 + 8:self.offset + 4 + 8 + 8 + 32].decode('ascii')
        self.version = self.reverse_version(self.version_hash)

        # features is a null terminated string
        end_features = self.buf[self.offset + 52:].find(b'\x00')
        self.features = self.buf[self.offset + 52:self.offset + 52 + end_features].decode('ascii')

    def __str__(self):
        return f"\033[1;37;1mSnapshot\033[0m\n\toffset  = {self.offset} ({hex(self.offset)})\n\t" + \
               f"size    = {self.size}\n\tkind    = {self.kind}\n\t" + \
               f"dart sdk version = {self.version}\n\tfeatures= {self.features}"

    @staticmethod
    def reverse_version(snapshot_version):
        # beware, there are Flutter versions and Dart SDK versions
        # our table returns the Dart SDK version
        # from https://gist.github.com/nfalliere/84803aef37291ce225e3549f3773681b
        version_table = {}
        with open('snapshot_hashes', 'r') as f:
            lines = f.readlines()
            for l in lines:
                hash, version = l.strip().split(',')
                version_table[hash] = version

        if snapshot_version in version_table:
            return version_table[snapshot_version]
        return snapshot_version


def get_arguments():
    parser = argparse.ArgumentParser(description='Read Flutter Snapshot header')
    parser.add_argument('-i', '--input', help='libapp.so file to analyze', action='store')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    print("========== Flutter Snapshot Header Parser ============")
    args = get_arguments()
    libapp = Libapp(args.input)
    libapp.parse()
