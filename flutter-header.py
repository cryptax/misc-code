"""
Standalone program to find Flutter snapshots and read their header from libapp.so
@cryptax - May 9, 2022
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
    # See https://github.com/dart-lang/sdk/blob/7c148d029de32590a8d0d332bf807d25929f080e/runtime/vm/snapshot.h
    kFull = 0  # Full snapshot of core libraries or an application.
    kFullJIT = 1  # Full + JIT code
    kFullAOT = 2  # Full + AOT code
    kMessage = 3  # A partial snapshot used only for isolate messaging.
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
        self.size = unpack('<q', self.buf[self.offset + 4:self.offset + 4 + 8])[0]
        kind = unpack('<q', self.buf[self.offset + 4 + 8:self.offset + 4 + 8 + 8])
        if kind is None or kind[0] < 0 or kind[0] > 5:
            logging.error(f"Unknown snapshot Kind: {kind} (snapshot offset={self.offset})")
            self.kind = SnapshotKindEnum.kInvalid
        else:
            self.kind = SnapshotKindEnum(kind[0])
        self.version_hash = self.buf[0x6004 + 8 + 8:0x6004 + 8 + 8 + 32].decode('ascii')
        self.version = self.reverse_version(self.version_hash)

        # features is a null terminated string
        end_features = self.buf[self.offset + 52:].find(b'\x00')
        self.features = self.buf[self.offset + 52:self.offset + 52 + end_features].decode('ascii')

    def __str__(self):
        return f"\033[1;37;1mSnapshot\033[0m\n\toffset  = {self.offset} ({hex(self.offset)})\n\t" + \
               f"size    = {self.size}\n\tkind    = {self.kind}\n\t" + \
               f"version = {self.version}\n\tfeatures= {self.features}"

    @staticmethod
    def reverse_version(snapshot_version):
        # to do: add more from https://github.com/mildsunrise/darter/blob/master/info/versions.md
        version_table = {'e4a09dbf2bb120fe4674e0576617a0dc': '2.13',
                          '3318fe66091c0ffbb64faec39976cb7d': '2.9.0 -> 0.1pre',
                         'adf563436d12ba0d50ea5beb7f3be1bb': '2.8.0 -> 2.8.1',
                         '24d9d411c2f90c8fbe8907f99e89d4b0': '2.7.0',
                         '9cf77f4405212c45daf608e1cd646852': '2.5.0 -> 2.5.3',
                         'f10776149bf76be288def3c2ca73bdc1': '2.6.0 -> 5.2pre',
                         '659a72e41e3276e882709901c27de33d': '2.4.0',
                         '7a5b240780941844bae88eca5dbaa7b8': '2.3.0 -> 2.4.1.pre',
                         '34f6eec64e9371856eaaa278ccf56538': '2.2.0-10.1.pre',
                         '5b97292b25f0a715613b7a28e0734f77': '2.0.6',
                         '9e2165577cef0f0f70f9ff072107920c': '1.25.0',
                         'a2bdb58c7edf9471da9180bf8185e7f7': '1.24.0-10.2.pre',
                         '953aa80d78c4d8886e3e4d784fd9d95f': '1.23.0-18.1.pre',
                         '8ee4ef7a67df9845fba331734198a953': '1.22.1 -> 1.22.6',
                         '04645b6182fad3d68350d84669869ce5': '1.20.0 -> 1.20.4',
                         '5f40b0a9f04b5018fa08a9b67fd316cd': '1.21.0',
                         }
        if snapshot_version in version_table:
            return version_table[snapshot_version]
        return 'Unknown'


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
