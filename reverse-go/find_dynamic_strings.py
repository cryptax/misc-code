# Initially taken from https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/find_dynamic_strings.py, fixed a few Python typos and improved by LLM
#
#
#Find and rename strings in Go (and other) binaries.
# type stringStruct struct {
#     str unsafe.Pointer
#     len int
# }
#Different instructions per architecture. Multiple solutions are possible.
#@author padorka@cujoai
#@category goscripts
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.lang import OperandType
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import StringDataType, UnicodeDataType
import re

def sanitize_label(s, max_len=48):
    name = s.strip()
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    name = re.sub(r'^[^a-zA-Z]+', '', name)
    if not name:
        return None
    if len(name) > max_len:
        name = name[:max_len]
    name = name.rstrip('_')
    if not name:
        return None
    return "s_" + name

def rename_string_label(address, data_value):
    text = str(data_value)
    label = sanitize_label(text)
    if label is None:
        return False
    try:
        sym = getSymbolAt(address)
        if sym is not None and sym.getName().startswith("s_"):
            return False
        createLabel(address, label, True)
        print("  %s -> %s" % (address, label))
        return True
    except:
        try:
            sym = getSymbolAt(address)
            if sym is not None:
                sym.setName(label, SourceType.USER_DEFINED)
                print("  %s -> %s" % (address, label))
                return True
        except:
            pass
    return False

def rename_all_strings():
    count = 0
    monitor = ConsoleTaskMonitor()
    try:
        string_manager = currentProgram.getListing().getStringManager()
        strings = string_manager.getStrings(monitor)
        for s in strings:
            try:
                text = s.getStringValue()
                if text and len(text) > 0:
                    addr = s.getAddress()
                    # Ensure data is defined as string type
                    try:
                        data = getDataAt(addr)
                        if data is None or not data.isDefined():
                            createAsciiString(addr, len(text))
                        elif not isinstance(data.getDataType(), (StringDataType, UnicodeDataType)):
                            continue
                    except:
                        pass
                    if rename_string_label(addr, text):
                        count += 1
            except:
                pass
    except:
        print("  StringManager not available, falling back to data iteration")
        data_iter = currentProgram.getListing().getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            try:
                dt = data.getDataType()
                if isinstance(dt, (StringDataType, UnicodeDataType)):
                    rep = data.getDefaultValueRepresentation()
                    if rep and len(rep) > 0:
                        if rename_string_label(data.getAddress(), rep):
                            count += 1
            except:
                pass
    print("Renamed %d string labels" % count)
    return count

def try_create_str(address, length):
    try:
        data = getDataAt(address)
        if data is not None and data.isDefined():
            dt = data.getDataType()
            if isinstance(dt, (StringDataType, UnicodeDataType)):
                rep = data.getDefaultValueRepresentation()
                if rep and len(rep) > 0:
                    rename_string_label(address, rep)
                    return True
            if str(dt.getName()).startswith("undefined"):
                try:
                    currentProgram.getListing().clearCodeUnits(address, address.add(length - 1))
                except:
                    pass
                createAsciiString(address, length)
                data = getDataAt(address)
                if data is not None and data.isDefined():
                    rep = data.getDefaultValueRepresentation()
                    if rep and len(rep) > 0:
                        rename_string_label(address, rep)
                        return True
            return False
        createAsciiString(address, length)
        data = getDataAt(address)
        if data is not None and data.isDefined():
            dt = data.getDataType()
            if isinstance(dt, (StringDataType, UnicodeDataType)):
                rep = data.getDefaultValueRepresentation()
                if rep and len(rep) > 0:
                    rename_string_label(address, rep)
                    return True
    except:
        return False
    return False

#x86
#LEA REG, [STRING_ADDRESS]
#MOV [ESP + ..], REG
#MOV [ESP + ..], STRING_SIZE

def get_lea_data_ref(ins):
    ref = ins.getPrimaryReference(1)
    if ref is not None and ref.getReferenceType().isData():
        return ref
    ref = ins.getPrimaryReference(0)
    if ref is not None and ref.getReferenceType().isData():
        return ref
    for r in getReferencesFrom(ins.getAddress()):
        if r.getReferenceType().isData():
            return r
    return None

def string_rename_x86():
    found = 0
    for block in getMemoryBlocks():
        if not block.isExecute():
            continue
        start = block.getStart()
        ins = getInstructionAt(start)
        while ins is not None:
            try:
                reg = ins.getRegister(0)
                if ins.getMnemonicString() != "LEA" or reg is None:
                    ins = getInstructionAfter(ins)
                    continue

                ref = get_lea_data_ref(ins)
                if ref is None:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next = getInstructionAfter(ins)
                if ins_next is None:
                    break
                if ins_next.getMnemonicString() != "MOV" or ins_next.getRegister(1) != reg:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next2 = getInstructionAfter(ins_next)
                if ins_next2 is None:
                    break
                op_type2 = ins_next2.getOperandType(1)
                if ins_next2.getMnemonicString() != "MOV" or OperandType.isScalar(op_type2) is False:
                    ins = getInstructionAfter(ins)
                    continue

                address = ref.getToAddress()
                length = ins_next2.getOpObjects(1)[0].getValue()
                if length <= 0 or length > 0x10000:
                    ins = getInstructionAfter(ins)
                    continue

                if try_create_str(address, length):
                    found += 1
                    print("  SUCCESS at %s len=%d" % (address, length))
            except Exception as e:
                print("  Error at %s: %s" % (ins.getAddress(), e))

            ins = getInstructionAfter(ins)
    print("x86: found %d strings" % found)
    return found

#x86_64
#LEA REG, [STRING_ADDRESS]
#MOV [RSP + ..], REG
#MOV [RSP + ..], STRING_SIZE

def string_rename_x86_64():
    found = 0
    for block in getMemoryBlocks():
        if not block.isExecute():
            continue
        start = block.getStart()
        ins = getInstructionAt(start)
        while ins is not None:
            try:
                reg = ins.getRegister(0)
                if ins.getMnemonicString() != "LEA" or reg is None:
                    ins = getInstructionAfter(ins)
                    continue

                ref = get_lea_data_ref(ins)
                if ref is None:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next = getInstructionAfter(ins)
                if ins_next is None:
                    break
                if ins_next.getMnemonicString() != "MOV" or ins_next.getRegister(1) != reg:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next2 = getInstructionAfter(ins_next)
                if ins_next2 is None:
                    break
                op_type2 = ins_next2.getOperandType(1)
                if ins_next2.getMnemonicString() != "MOV" or OperandType.isScalar(op_type2) is False:
                    ins = getInstructionAfter(ins)
                    continue

                address = ref.getToAddress()
                length = ins_next2.getOpObjects(1)[0].getValue()
                if length <= 0 or length > 0x10000:
                    ins = getInstructionAfter(ins)
                    continue

                if try_create_str(address, length):
                    found += 1
                    print("  SUCCESS at %s len=%d" % (address, length))
            except Exception as e:
                print("  Error at %s: %s" % (ins.getAddress(), e))

            ins = getInstructionAfter(ins)
    print("x86_64: found %d strings" % found)
    return found

#ARM, 32-bit
#LDR REG, [STRING_ADDRESS_POINTER]
#STR REG, [SP, ..]
#MOV REG, STRING_SIZE
#STR REG, [SP, ..]

def string_rename_arm():
    found = 0
    for block in getMemoryBlocks():
        if not block.isExecute():
            continue
        start = block.getStart()
        ins = getInstructionAt(start)
        while ins is not None:
            try:
                reg = ins.getRegister(0)
                if ins.getMnemonicString() != "ldr" or reg is None:
                    ins = getInstructionAfter(ins)
                    continue

                ref = ins.getPrimaryReference(1)
                if ref is None:
                    ref = ins.getPrimaryReference(0)
                if ref is None:
                    ins = getInstructionAfter(ins)
                    continue
                addr_ptr = ref.getToAddress()

                ins_next = getInstructionAfter(ins)
                if ins_next is None:
                    break
                if ins_next.getMnemonicString() != "str" or ins_next.getRegister(0) != reg:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next2 = getInstructionAfter(ins_next)
                if ins_next2 is None:
                    break
                op_type = ins_next2.getOperandType(1)
                if ins_next2.getMnemonicString() != "mov" or ins_next2.getRegister(0) is None or OperandType.isScalar(op_type) is False:
                    ins = getInstructionAfter(ins)
                    continue

                reg2 = ins_next2.getRegister(0)
                ins_next3 = getInstructionAfter(ins_next2)
                if ins_next3 is None:
                    break
                if ins_next3.getMnemonicString() != "str" or ins_next3.getRegister(0) != reg2:
                    ins = getInstructionAfter(ins)
                    continue

                try:
                    address_pointer = getInt(addr_ptr)
                    address = currentProgram.getAddressFactory().getAddress(hex(address_pointer))
                except:
                    ins = getInstructionAfter(ins)
                    continue

                length = ins_next2.getOpObjects(1)[0].getValue()
                if length <= 0 or length > 0x10000:
                    ins = getInstructionAfter(ins)
                    continue

                if try_create_str(address, length):
                    found += 1
                    print("  SUCCESS at %s len=%d" % (address, length))
            except Exception as e:
                print("  Error at %s: %s" % (ins.getAddress(), e))

            ins = getInstructionAfter(ins)
    print("ARM: found %d strings" % found)
    return found

#ARM, 64-bit - version 1
#ADRP REG, [STRING_ADDRESS_START]
#ADD REG, REG, INT
#STR REG, [SP, ..]
#ORR REG, REG, STRING_SIZE
#STR REG, [SP, ..]
#
#ARM, 64-bit - version 2
#ADRP REG, [STRING_ADDRESS_START]
#ADD REG, REG, INT
#STR REG, [SP, ..]
#MOV REG, STRING_SIZE
#STR REG, [SP, ..]

def string_rename_arm_64():
    found = 0
    for block in getMemoryBlocks():
        if not block.isExecute():
            continue
        start = block.getStart()
        ins = getInstructionAt(start)
        while ins is not None:
            try:
                op_type = ins.getOperandType(1)
                reg = ins.getRegister(0)
                if ins.getMnemonicString() != "adrp" or reg is None or OperandType.isScalar(op_type) is False:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next = getInstructionAfter(ins)
                if ins_next is None:
                    break
                op_type2 = ins_next.getOperandType(2)
                if ins_next.getMnemonicString() != "add" or ins_next.getRegister(0) != reg or OperandType.isScalar(op_type2) is False:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next2 = getInstructionAfter(ins_next)
                if ins_next2 is None:
                    break
                if ins_next2.getMnemonicString() != "str" or ins_next2.getRegister(0) != reg:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next3 = getInstructionAfter(ins_next2)
                if ins_next3 is None:
                    break
                reg3 = ins_next3.getRegister(0)

                if ins_next3.getMnemonicString() == "orr" and reg3 is not None and OperandType.isScalar(ins_next3.getOperandType(2)) is True:
                    length = ins_next3.getOpObjects(2)[0].getValue()
                elif ins_next3.getMnemonicString() == "mov" and reg3 is not None and OperandType.isScalar(ins_next3.getOperandType(1)) is True:
                    length = ins_next3.getOpObjects(1)[0].getValue()
                else:
                    ins = getInstructionAfter(ins)
                    continue

                ins_next4 = getInstructionAfter(ins_next3)
                if ins_next4 is None:
                    break
                if ins_next4.getMnemonicString() != "str" or ins_next4.getRegister(0) != reg3:
                    ins = getInstructionAfter(ins)
                    continue

                page_addr = ins.getOpObjects(1)[0].getValue()
                page_offset = ins_next.getOpObjects(2)[0].getValue()
                address_int = int(page_addr + page_offset)
                address = currentProgram.getAddressFactory().getAddress(hex(address_int))

                if length <= 0 or length > 0x10000:
                    ins = getInstructionAfter(ins)
                    continue

                if try_create_str(address, length):
                    found += 1
                    print("  SUCCESS at %s len=%d" % (address, length))
            except Exception as e:
                print("  Error at %s: %s" % (ins.getAddress(), e))

            ins = getInstructionAfter(ins)
    print("ARM64: found %d strings" % found)
    return found

def scan_undefined_strings(chunk_size=65536):
    count = 0
    for block in getMemoryBlocks():
        if not block.isInitialized():
            continue
        name = block.getName()
        if name in (".text", ".bss", ".noptrbss", ".shstrtab"):
            continue
        start = block.getStart()
        size = block.getSize()
        pos = 0
        while pos < size:
            chunk_sz = min(chunk_size, size - pos)
            try:
                raw = getBytes(start.add(pos), chunk_sz)
            except:
                pos += chunk_sz
                continue
            if raw is None:
                pos += chunk_sz
                continue
            buf = [b & 0xFF for b in raw]
            i = 0
            while i < len(buf):
                b = buf[i]
                if 0x20 <= b <= 0x7e:
                    seq_start = pos + i
                    seq_len = 0
                    while i < len(buf) and 0x20 <= buf[i] <= 0x7e:
                        seq_len += 1
                        i += 1
                    if seq_len >= 4:
                        scan_addr = start.add(seq_start)
                        try:
                            data = getDataAt(scan_addr)
                            if data is not None and data.isDefined():
                                dt = data.getDataType()
                                if isinstance(dt, (StringDataType, UnicodeDataType)):
                                    rep = data.getDefaultValueRepresentation()
                                    if rep and len(rep) > 0:
                                        if rename_string_label(scan_addr, rep):
                                            count += 1
                                    continue
                                if not str(dt.getName()).startswith("undefined"):
                                    continue
                                try:
                                    currentProgram.getListing().clearCodeUnits(scan_addr, scan_addr.add(seq_len - 1))
                                except:
                                    pass
                            createAsciiString(scan_addr, seq_len)
                            data = getDataAt(scan_addr)
                            if data is not None and data.isDefined():
                                rep = data.getDefaultValueRepresentation()
                                if rep and len(rep) > 0:
                                    if rename_string_label(scan_addr, rep):
                                        count += 1
                        except:
                            pass
                else:
                    i += 1
            pos += chunk_sz
    print("Scanned and renamed %d undefined strings" % count)
    return count


#Main
language_id = currentProgram.getLanguageID()
print("Language: %s" % language_id)
pointer_size = currentProgram.getDefaultPointerSize()

total = 0

print("--- Renaming all existing strings ---")
total += rename_all_strings()

print("--- Scanning for undefined strings ---")
total += scan_undefined_strings()

if language_id.toString().startswith("ARM"):
    print("--- Scanning for Go dynamic strings (ARM 32-bit) ---")
    total += string_rename_arm()
elif language_id.toString().startswith("AARCH64"):
    print("--- Scanning for Go dynamic strings (ARM 64-bit) ---")
    total += string_rename_arm_64()
elif language_id.toString().startswith("x86") and pointer_size == 4:
    print("--- Scanning for Go dynamic strings (x86 32-bit) ---")
    total += string_rename_x86()
elif language_id.toString().startswith("x86") and pointer_size == 8:
    print("--- Scanning for Go dynamic strings (x86_64) ---")
    total += string_rename_x86_64()
else:
    print("Unknown arch, skipping Go pattern scan")

print("TOTAL strings renamed: %d" % total)
