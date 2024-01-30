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
        self.version_hash = self.buf[self.offset + 4 + 8 + 8:self.offset + 4 + 8 + 8 + 32].decode('ascii')
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
        # to do: add more from https://gist.github.com/nfalliere/84803aef37291ce225e3549f3773681b
        # to do: fix inconsistencies: some versions are Flutter versions, while other are Dart versions...
        version_table = {'adb4292f3ec25074ca70abcd2d5c7251': '2.19.1',
                         'b0e899ec5a90e4661501f0b69e9dd70f': '2.18.0',
                         'e4a09dbf2bb120fe4674e0576617a0dc': '2.13',
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
                         'b0e899ec5a90e4661501f0b69e9dd70f': '3.3.4',
                         '90b56a561f70cd55e972cb49b79b3d8b': '3.10.3',
                        '16ad76edd19b537bf6ea64fdd31977a7': '3.12.0',
                        '36b0375d284ee2af0d0fffc6e6e48fde': '3.11.0-0.0.pre',
                        'aa64af18e7d086041ac127cc4bc50c5e': '3.10.0-1.1.pre',
                        'adb4292f3ec25074ca70abcd2d5c7251': '3.7.1',
                        '618084be871d017013dc342a8ecadba6': '3.9.0-0.1.pre',
                        '8860f13fdeacf945548b94e3293739dc': '3.8.0-10.1.pre',
                        '501ef5cbd64ca70b6b42672346af6a8a': '3.7.0-1.2.pre',
                        'b6d0a1f034d158b0d37b51d559379697': '3.3.10',
                        'c7dc2f8f88f49836586d90b0dbf9d45d': '3.7.0-1.1.pre',
                        'b0e899ec5a90e4661501f0b69e9dd70f': '3.3.0-0.0.pre',
                        '1bd8ca171064c8b8d387e47f96375a6f': '3.6.0-0.1.pre',
                        'b6a1c0b8562a7680adedfbb8fcc5a065': '3.4.0-34.1.pre',
                        '1044d5d7857485639caee4798a5dcbb7': '3.4.0-17.1.pre',
                        '1441d6b13b8623fa7fbf61433abebd31': '2.13.0-0.1.pre',
                        '8e50e448b241be23b9e990094f4dca39': '3.1.0-9.0.pre',
                        '6a9b5a03a7e784a4558b10c769f188d9': '3.1.0',
                        'd56742caf7b3b3f4bd2df93a9bbb5503': '2.10.0-0.1.pre',
                        'a0cb0c928b23bc17a26e062b351dc44d': '2.12.0-4.1.pre',
                        'ded6ef11c73fdc638d6ff6d3ad22a67b': '2.11.0-0.1.pre',
                        'adf563436d12ba0d50ea5beb7f3be1bb': '2.8.0-3.1.pre',
                        '3318fe66091c0ffbb64faec39976cb7d': '2.9.0-0.1.pre',
                        '24d9d411c2f90c8fbe8907f99e89d4b0': '2.7.0-3.0.pre',
                        '9cf77f4405212c45daf608e1cd646852': '2.5.0-5.1.pre',
                        'f1db3415a45bf430607898342ec95936': '2.6.0-11.0.pre',
                        'f10776149bf76be288def3c2ca73bdc1': '2.6.0-5.1.pre',
                        'f2ed175878eb1ab377414135b301edb8': '2.6.0-0.0.pre',
                        '47d2fd85fe2d669fbde6102e01968b36': '2.5.0-6.0.pre',
                        'b555f636e5ed67c4cd65ec7250ff2930': '2.5.0-5.0.pre',
                        '0ace76156789dce96e2a5d89e2895a4b': '2.5.0-1.0.pre',
                        '659a72e41e3276e882709901c27de33d': '2.4.0-4.0.pre',
                        '179244c371e0a111ba4142c8cdd14de1': '2.4.0-0.0.pre',
                        'e4a09dbf2bb120fe4674e0576617a0dc': '2.2.0-10.2.pre',
                        '7a5b240780941844bae88eca5dbaa7b8': '2.3.0-24.0.pre',
                        'b94a04a25144701785e6e30df9f2d66d': '2.3.0-16.0.pre',
                        '03e6d2a403f559edb69f9e16146a50f2': '2.3.0-12.1.pre',
                        '960c5f6e01bf057848eae4f97e563a36': '2.3.0-1.0.pre',
                        '5b97292b25f0a715613b7a28e0734f77': '1.26.0-17.5.pre',
                        'e89bb14ef57e26574631b8178f11ee79': '2.3.0-0.1.pre',
                        '34f6eec64e9371856eaaa278ccf56538': '2.2.0-10.1.pre',
                        '39a9141bbcc3cae43e6f9f6b7fbaafe3': '2.1.0-12.1.pre',
                        'f6a6cef736ffc4c3af80bffd37d6e45b': '2.1.0-10.0.pre',
                        'e8b7543ba0865c5bac45bf158bb3d4c1': '1.27.0-4.0.pre',
                        '3309d422163e238c4f079ab2eff8468e': '1.27.0-1.0.pre',
                        'f825989a7b7325a3cb548893706a89cd': '1.26.0-17.1.pre',
                        '8ee4ef7a67df9845fba331734198a953': '1.22.0-12.0.pre',
                        '37f5a68f6d9885a875de9587a2fb600c': '1.26.0-12.0.pre',
                        '9e2165577cef0f0f70f9ff072107920c': '1.25.0-8.0.pre',
                        'aec2861b8a7fb93059cdbfbaf230c8a4': '1.26.0-8.0.pre',
                        '829d11a5989e6bd2526c514b9c2e410e': '1.26.0-1.0.pre',
                        '9a7ca53956616eff82b5118a5646ecd7': '1.25.0-4.0.pre',
                        'a2bdb58c7edf9471da9180bf8185e7f7': '1.24.0-10.1.pre',
                        '5f5dd71f0d89fecf2ed8f6e87c213275': '1.24.0-6.0.pre',
                        '2271cfbd1a08b3bb99ea8727cdd0e564': '1.24.0-3.0.pre',
                        '1448a25ffd3b0f8d97bcd5eb5980feb6': '1.24.0-1.0.pre',
                        '953aa80d78c4d8886e3e4d784fd9d95f': '1.23.0-18.0.pre',
                        '49f28fbe1e16c41d8bc794b024c9171b': '1.23.0-13.0.pre',
                        '70cbcf7b49d7e90b8b50ec409457f1f2': '1.23.0-7.0.pre',
                        'ebd546b338c127fc12395d652327c084': '1.23.0-4.0.pre',
                        '04645b6182fad3d68350d84669869ce5': '1.20.0-7.3.pre',
                        'f5de31057025dabaeb9262ec1b8ef33b': '1.22.0-9.0.pre',
                        '5f40b0a9f04b5018fa08a9b67fd316cd': '1.21.0-9.0.pre',
                        '3fbb5898e1b2294b3b432e5a9baa47c3': '1.22.0-1.0.pre',
                        'd87fcd044a4c80e6c35920fc6cdb2942': '1.21.0-7.0.pre',
                        '8b2ca977d1d2920b9839d1b60eade6a7': '1.20.0-7.0.pre',
                        'cf28bbe6b5e0f24ecb48ca8abbcb5f57': '1.21.0-1.0.pre',
                        'ec7f41beae0c8f00109820695ab99a20': '1.20.0-3.0.pre',
                        '59da07d9da5a83be4ce75b7913b63dbd': '1.19.0-4.0.pre',
                        '76070dd606744a9afc332cb66b613df2': '1.20.0-2.0.pre',
                        'be7d304ff826e2dfac63538e227c3cc5': '1.17.2',
                        '5a08c49b17aec9162c816303a1433354': '1.20.0-0.0.pre',
                        'e81d7685ffc22e522c8dde5061e3e0f8': '1.19.0-5.0.pre',
                        '92b48f782c20c41a191a2298e8c4a537': '1.19.0-2.0.pre',
                        'b58ead73b2c5dfec69565df469bba387': '1.18.0-10.0.pre',
                        '74edb834fac3fcea79d7ac2d1d6f1fb2': '1.17.0-3.2.pre',
                        'f5ea1e9940b6aaf4df2649a6d379928b': '1.19.0-1.0.pre',
                        '2692b1e03fdf2af47afad07f294e9a9c': '1.18.0-13.0.pre',
                        '591abdc59f04644e4d7645c3f0a0f31b': '1.18.0-9.0.pre',
                        '593ab10defb2c9b323d552241c790db7': '1.18.0-7.0.pre',
                        '584f76703bdc27bf8e9cf560354e873b': '1.18.0-6.0.pre',
                        '20e5c4f7dc44368ac5a17643b93665f6': 'v1.12.9',
                        '28e5a4c9b745e287b24fc03101d8c4d1': '1.18.0-dev.5.0',
                        '8d250dca7ec13e13f7ee6d4dc6e4c866': '1.18.0-dev.2.0',
                        '9e7cb7c9394c24c2398410b902673e13': '1.17.0-dev.1.0',
                        '5755f145e518c3a3e5467bc0e4206ca0': '1.18.0-dev.0.0',
                        'd577004bdd4b0ae4aff1fe9418f8e108': '1.17.0-dev.4.0',
                        'fcf5987e9905b9cb0284432dfa1ea2ff': 'v1.16.3',
                        'dca728a34350ead7a40d66ae49898ab3': 'v1.16.2',
                        'f98026d2245e5193b4c4766d883cf831': 'v1.16.1',
                        '3ed814dc5ba54b83877622f07f8efe6a': 'v1.16.0',
                        'ee91a9191a5286c31d91a89754ba36af': 'v1.15.13',
                        '21c64959ddcffbbe98dd50bf0f56acbe': 'v1.15.22',
                        'bcb42ad731bb2252562cf7119e8d38bf': 'v1.15.21',
                        'eec64b4f56ed7083f6b3f9215bc00ee4': 'v1.15.10',
                        '8df17e43f5d039756a4be463bd53f16c': 'v1.15.4',
                        '1ef14c4736dbf4b1913c1159a52912f7': 'v1.15.3',
                        'ea0806b1a49f2f2088770b414ead0a35': 'v1.15.2',
                        '7e3316e180825d1f779f78c2d77a47d8': 'v1.15.0',
                        'e739779cc1d28f0f697a92f2daf5f10f': 'v1.14.6',
                        '8647fa5ecfc24d126d8256b30b1ff5c6': 'v1.14.5',
                        'e7c20657d2570e8390cf59131adde9f6': 'v1.14.3',
                        'b1db3321978c921cba0461fcaef73d23': 'v1.14.2',
                        '0d7dc8e47a3bed1850c97ee43898a84c': 'v1.14.1',
                        '803754e538cf1a438b1221a2b5faf840': 'v1.14.0',
                        '81662522448cdd4d02eb060669e5d48b': 'v1.13.6',
                        'fbfd877143383e38eee8a3f1eaeafeb5': 'v1.13.9',
                        '5f03aa6ee25b575c9f3d075a19fb2043': 'v1.13.8',
                        'd0cc0d54d92b623c9d369ca3537dc635': 'v1.13.7',
                        '675c10104e4334c9da289ab872fea2e2': 'v1.13.3',
                        '0d40051733a4ee7e7793a91ed77fed67': 'v1.13.1',
                        '69045f81def452ca6187efd1cb5e6b54': 'v1.13.0',
                        '2fb364d659ea53f7892be9ba5e036047': 'v1.11.0',
                        '7f885169821cf7a89d8f4a49c44d414a': 'v1.12.5',
                        'd48b81bd7c0b41868a303d010886d8d8': 'v1.12.3',
                        '903f3e0c943f024d682b10f894f2e76d': 'v1.12.2',
                        'bd73301b201fa442c56420bbc9c5448c': 'v1.12.1',
                        '4d6be598cd9c0869b7062e8a4344d386': 'v1.10.16',
                        '8c373bc801ef8907b997963d19234a03': 'v1.10.15',
                        'c8562f0ee0ebc38ba217c7955956d1cb': 'v1.9.1',
                        'c3bbfe8f226120ad0569d7b78ed2d9ef': 'v1.10.7',
                        'bbfd190df732926328ba445a771febf7': 'v1.10.9',
                        'd0e6d7626e06ab31bf67270b37ff292a': 'v1.10.8',
                        '4d75e7eb64b77034b9e3e19577811de7': 'v1.10.6',
                        '96e8a17629cf9d73208d2cfccc930a7f': 'v1.10.4',
                        '9bde2343868bcfc4814fb79599613344': 'v1.10.3',
                        '48360207b8ee283a359d27ca7352d8a6': 'v1.10.1',
                        '68cf77b6d1fc9b557802c26dd144297f': 'v1.10.0',
                        'e39caccf4752459650d09c0abf4d167d': 'v1.9.6',
                        '8408a7c5bd51af20e71f9a66e808f8fe': 'v1.9.4',
                        '762228c411824d5a7ce32f844858415f': 'v1.9.3',
                        '6e44a52d8990d853d90cd3de014d1149': 'v1.9.2',
                        '3bc1b74a777079816871f4b923bf77bc': 'v1.9.0',
                        '34948253b59d5a56b2ec161e17975a4e': 'v1.8.3',
                        '9bc6f6130d64837dd7213aa478e1d6f1': 'v1.8.4',
                        '1d7acad1540192ac459cf60344efb7c1': 'v1.7.4',
                        '4997265621b29e882e50456ab42d8856': 'v1.8.1',
                        '25ed5741a98d25aafa175175dd75f52b': 'v1.7.3',
                        '0b4e4e38095461a47b6052ec747497ea': 'v1.7.1',
                        'eac01d2272aaccf1102b49911d9861a1': 'v1.7.0',
                        'd674137c8a194053e04a8358a92c2e2a': 'v1.6.7',
                        'c89592e3e4956c33956c8ba0f691dbd0': 'v1.6.3',
                        '18595b5f46eab396a85f20129914639a': 'v1.6.1',
                        '063c66cf3ae51e48c330780656345989': 'v1.6.0',
                        'eed485c757fba5d731e4054412c99f2e': 'v1.5.4',
                        '29f268f2197cadde0b55ba05fbaafbb8': 'v1.5.5',
                        'd6e24d65b1bf49f4cd41daddfe2d515b': 'v1.5.3',
                        'a2967d784bf01190add298db8b62285b': 'v1.5.2',
                        'f84d8d001eedd3a97333e1b2a3fd054c': 'v1.5.0',
                        'f630ecdf457e27dd24d3b9e0a6bc1c13': 'v1.4.9',
                        '9e1fa667daca1ecf538db8507091794e': 'v1.4.13',
                        '3383321009c0898417a99b9df9a73876': 'v1.4.10',
                        '3a77dc0e4b817ac9954a776220a09629': 'v1.4.8',
                        'fdcf6c4b13c56e5ba32ccc991fc0d80c': 'v1.4.6',
                        '12ede50e1442e2577bce79348e3bc031': 'v1.4.5',
                        '8d7ca9eab85b719a6371e8d851b51044': 'v1.4.0',
                        '34262bf031ae3b5c8fb9375bf45e037f': 'v1.3.14',
                        'e7c8a6096e8cb3ada7a6550e3f87ea88': 'v1.3.12',
                        '31d853261e7a9884297e9a39762a5107': 'v1.3.11',
                        '9a66dcb2da955dffdbdb0eafa0288784': 'v1.3.7',
                        'b44d84a50bc3dcd23e0979b1bf79849b': 'v1.3.10',
                        'cde614e2103dec94e73556e623ae89e3': 'v1.3.9',
                        'a1aaab2706cefc32dd1df8e973509540': 'v1.3.1',
                        '089cfea6f089ab5f4bf8ccd2f7fc27b7': 'v1.3.0',
                        '67d5e890b128b2d4141263de5f1ac0d1': 'v1.2.2',
                        '0c73eb70aa4d30f450273cb424be8c62': 'v1.2.1',
                        '1a4f095af4bcb46ca81bb57339e9667a': 'v1.2.0',
                        '317d4c7e607b1fd7d682c0010aadf1d0': 'v1.1.8',
                        '8343f188ada07642f47c56e518f1307c': 'v0.11.6',
                        'd124ce50a30741a188e41c52c424c127': 'v0.11.1',
                        '46b2bfb57b5647c5f7527ff9aa56c69b': 'v0.10.2',
                        '787a4777f88a79e31da4816394307ae1': 'v0.10.1',
                        '62ef4dfcf98329d5284e035d0513511a': 'v0.10.0',
                        'a135b1a4c6790a272609c9405379bc63': 'v0.9.4',
                        'a8259ee8cefb98a6f997d8518f7971c2': 'v0.9.6',
                        '45a2b041cb2fd244807ef704d221ceba': 'v0.9.5',
                        'd6f42425feaac5aa95a1973e376bad82': 'v0.9.3',
                        'f3cf6417f170a4b4eb7fcdfd07cf28b4': 'v0.9.2',
                        '7571f3801809ac20f48b0e38647900e1': 'v0.8.7',
                        '1b444eb4796616ea2f955f3f1e440801': 'v0.7.4',
                        '42e9e3a62930abf238d6ebb1ffe56a9c': 'v0.8.4',
                        'da2016f767d32cfe970546ea3ae63026': 'v0.8.3',
                        'd0cf500478165d79bdefccb0847ffb33': 'v0.7.1',
                        '35224090f45cbae1402bafd97a112a40': 'v0.6.0',
                        '20e1c85108022aa0da0b6116a5430f19': 'v0.6.2',
                        '77ed80617eb2b1627e6c51ae7252c677': 'v0.5.8',
                        'ffb1195e9b89c663b3728d1c31618334': 'v0.5.6',
                        '04cb98b58e7d69109004454c20b492f7': 'v0.5.1',
                        '620e7a3f6ea0629bfbf138cfda2b61fa': 'v0.5.5',
                        'fd5b7e46645767083d8f2b8433d7f761': 'v0.5.2',
                        '129c1a9917052c59c17229d1d019a956': 'v0.5.0',
                        '1b155eedbb3a2640a88d2e54d2f2d204': 'v0.4.4',
                        'e005a87ed1e2a5f982744b8074199787': 'v0.3.6',
                        '39646f79e9336fb65ac68c8568544c92': 'v0.3.1',
                        '4bef249ea9718a0b708f17a4a98f9b59': 'v0.3.0',
                        '5dc50b7942c1acdc5e20d7a99b981227': 'v0.2.11',
                        'c43eada86a2f4834d028602dc4840e01': 'v0.2.10',
                        'd72bf5003e5924b61a7943f58e7b6814': 'v0.2.7',
                        '0d015018f02a6de0c92ac1ac59191b55': 'v0.2.2',
                        '8f8bcefc1534f548f00d8d817877e101': 'v0.2.6',
                        '0053515318c68502ae0307040ac1746b': 'v0.2.5',
                        '48af31030bbb45e2f3e620514fd8a27d': 'v0.2.4',
                        '9bc066b6e8ef5a9f7224c2926c6ad2f4': 'v0.1.6',
                        '667a3bf9d477f047a8d88dddf6d8bfd1': 'v0.2.1',
                        '1461982fa5039fab6ecead9f19228670': 'v0.1.9'
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
