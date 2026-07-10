# SplitGoStrings.py
# Fix oversized Go string blobs in x86-32 Go binaries
#
# How to run: Script Manager -> SplitGoStrings.py -> Run
#
#@author  adapted for gogra analysis
#@category goscripts

import re

def read_u32_le(addr):
    b0 = getByte(addr) & 0xFF
    b1 = getByte(addr.add(1)) & 0xFF
    b2 = getByte(addr.add(2)) & 0xFF
    b3 = getByte(addr.add(3)) & 0xFF
    return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0

def calc_mov_len(mod, rm):
    """Return addressing bytes AFTER opcode (includes modrm)."""
    if mod == 3: return 1      # just modrm, reg-to-reg
    if mod == 1:
        if rm == 4: return 3   # modrm + sib + disp8
        return 2              # modrm + disp8
    # mod == 0
    if rm == 4: return 6      # modrm + sib + disp32
    if rm == 5: return 5      # modrm + disp32
    return 1                  # modrm only (register indirect, no displacement)

def try_pattern(addr):
    b0 = getByte(addr) & 0xFF
    if b0 != 0x8D:
        return None

    modrm = getByte(addr.add(1)) & 0xFF
    # LEA r32, [disp32]: mod=00, rm=101 -> (modrm & 0xC7) == 0x05
    if (modrm & 0xC7) != 0x05:
        return None

    debug_addr = addr.getOffset() in [0x082868bb, 0x08285cc7]
    if debug_addr:
        print(f"[DBG] LEA match at 0x{addr.getOffset():08x}, modrm=0x{modrm:02x}")

    # Try to find length MOV before the LEA (some patterns set length first)
    # Look back up to 16 bytes
    prev_str_len = -1
    for back_offset in range(1, 17):
        check_addr = addr.add(-back_offset)
        try:
            check_byte = getByte(check_addr) & 0xFF
            # Look for: C7 41 04 XX XX XX XX (MOV dword ptr [ECX+4], imm32)
            if check_byte == 0xC7:
                check_mrm = getByte(check_addr.add(1)) & 0xFF
                # Expect mod=01 (disp8), rm=1 (ECX), reg=0
                if (check_mrm & 0xC0) == 0x40 and (check_mrm & 0x7) == 1:
                    disp8 = getByte(check_addr.add(2)) & 0xFF
                    if disp8 == 0x4:  # offset 4 (length field of Go string)
                        prev_str_len = read_u32_le(check_addr.add(3))
                        if debug_addr:
                            print(f"[DBG]   Found backward length MOV at 0x{check_addr.getOffset():08x}: len=0x{prev_str_len:x}")
                        break
        except:
            pass

    disp32 = read_u32_le(addr.add(2))
    string_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(disp32)

    # Quick check: string address should point to printable content
    try:
        sample = getByte(string_addr) & 0xFF
        if sample == 0:
            if debug_addr:
                print(f"[DBG]   SKIP: string_addr 0x{string_addr.getOffset():08x} starts with null byte")
            return None
    except:
        if debug_addr:
            print(f"[DBG]   SKIP: cannot read string_addr 0x{string_addr.getOffset():08x}")
        return None

    # LEA is 6 bytes total: opcode(1) + modrm(1) + disp32(4)
    after_lea = addr.add(6)

    # First MOV after LEA: MOV [esp+off], r32 or MOV [esp+off], imm32
    mov1_byte = getByte(after_lea) & 0xFF
    mov1_len = 0

    if debug_addr:
        print(f"[DBG]   First MOV at 0x{after_lea.getOffset():08x}: opcode=0x{mov1_byte:02x}")

    if mov1_byte == 0x89:
        # MOV r/m32, r32
        mrm1 = getByte(after_lea.add(1)) & 0xFF
        mod1 = (mrm1 >> 6) & 3
        rm1 = mrm1 & 7
        mov1_len = calc_mov_len(mod1, rm1) + 1
        if debug_addr:
            print(f"[DBG]     MOV r/m32,r32: mod={mod1}, rm={rm1}, len={mov1_len}")
    elif mov1_byte == 0xC7:
        # MOV r/m32, imm32
        mrm1 = getByte(after_lea.add(1)) & 0xFF
        mod1 = (mrm1 >> 6) & 3
        rm1 = mrm1 & 7
        mov1_len = calc_mov_len(mod1, rm1) + 5
        if debug_addr:
            print(f"[DBG]     MOV r/m32,imm32: mod={mod1}, rm={rm1}, len={mov1_len}")
    else:
        # Not a MOV pattern we handle
        if debug_addr:
            print(f"[DBG]   SKIP: first MOV opcode 0x{mov1_byte:02x} not recognized")
        return None

    # If we found a backward length MOV, use that directly
    if prev_str_len >= 0:
        str_len = prev_str_len
        mov2_len = 0  # backward MOV is not in forward sequence
        if debug_addr:
            print(f"[DBG]   Using backward length: {str_len}")
    else:
        # Second MOV: MOV [esp+off], imm32 (the string length)
        second_mov = after_lea.add(mov1_len)
        mov2_byte = getByte(second_mov) & 0xFF

        if debug_addr:
            print(f"[DBG]   Second MOV at 0x{second_mov.getOffset():08x}: opcode=0x{mov2_byte:02x}")

        mov2_len = 0
        str_len = -1

        if mov2_byte == 0xC7:
            # MOV r/m32, imm32
            mrm2 = getByte(second_mov.add(1)) & 0xFF
            mod2 = (mrm2 >> 6) & 3
            rm2 = mrm2 & 7
            base_offset = calc_mov_len(mod2, rm2)
            str_len = read_u32_le(second_mov.add(1 + base_offset))
            mov2_len = 1 + base_offset + 4
            if debug_addr:
                print(f"[DBG]     MOV r/m32,imm32: mod={mod2}, rm={rm2}, len={mov2_len}, str_len={str_len}")
        elif mov2_byte == 0x66:
            # 66 C7 -> MOV r/m16, imm16
            mov2_opc = getByte(second_mov.add(1)) & 0xFF
            if mov2_opc == 0xC7:
                mrm2 = getByte(second_mov.add(2)) & 0xFF
                mod2 = (mrm2 >> 6) & 3
                rm2 = mrm2 & 7
                base_offset = calc_mov_len(mod2, rm2)
                lo = getByte(second_mov.add(2 + base_offset)) & 0xFF
                hi = getByte(second_mov.add(3 + base_offset)) & 0xFF
                str_len = (hi << 8) | lo
                mov2_len = 2 + base_offset + 2
                if debug_addr:
                    print(f"[DBG]     MOV r/m16,imm16: mod={mod2}, rm={rm2}, len={mov2_len}, str_len={str_len}")
            else:
                if debug_addr:
                    print(f"[DBG]   SKIP: 66 prefix but opcode not C7")
                return None
        else:
            if debug_addr:
                print(f"[DBG]   SKIP: second MOV opcode 0x{mov2_byte:02x} not recognized")
            return None

    if str_len <= 0 or str_len > 10000:
        if debug_addr:
            print(f"[DBG]   SKIP: str_len={str_len} out of range")
        return ("skip", 6 + mov1_len + 1)

    # Verify string is mostly printable
    printable = 0
    check_len = min(32, str_len)
    for i in range(check_len):
        ch = getByte(string_addr.add(i)) & 0xFF
        if (32 <= ch <= 126) or ch == ord('\n') or ch == ord('\t'):
            printable += 1
    if printable * 10 < check_len * 7:
        if debug_addr:
            print(f"[DBG]   SKIP: not printable (printable={printable}/{check_len})")
        return ("skip", 6 + mov1_len + mov2_len)

    if debug_addr:
        print(f"[DBG]   MATCH! saddr=0x{string_addr.getOffset():08x}, len={str_len}")
    return ("found", string_addr, str_len, 6 + mov1_len + mov2_len)

def fix_string_at(saddr, length):
    debug_addr = saddr.getOffset() in [0x08392540]
    if debug_addr:
        print(f"[DBG] fix_string_at(0x{saddr.getOffset():08x}, {length})")

    # Check if data already exists at this address
    existing = getDataAt(saddr)
    if debug_addr:
        print(f"[DBG]   existing at saddr: {existing}")
    if existing is not None:
        val = existing.getValue()
        if debug_addr:
            print(f"[DBG]   val type: {type(val)}, len: {len(val) if val else 'N/A'}")
        if val is not None and len(val) == length:
            if debug_addr:
                print(f"[DBG]   SKIP: already correct length ({length})")
            return
        if val is not None and len(val) < length:
            if debug_addr:
                print(f"[DBG]   SKIP: existing shorter ({len(val)} < {length})")
            return
        preview = val[:min(20, len(val))]
        print("[+] Fixing %s: len %d -> %d |%s..." % (saddr, len(val), length, preview))

    # Clear exact location first
    d = getDataAt(saddr)
    if debug_addr:
        print(f"[DBG]   d at saddr: {d}")
    if d is not None:
        if debug_addr:
            print(f"[DBG]   clearing data at saddr")
        clearData(d)

    # Try to create string
    if debug_addr:
        print(f"[DBG]   attempting createAsciiString")
    try:
        createAsciiString(saddr, length)
        if debug_addr:
            print(f"[DBG]   SUCCESS")
        print("    Created string: len=%d" % length)
    except Exception as e:
        error_msg = str(e)
        if debug_addr:
            print(f"[DBG]   FAILED: {error_msg}")

        # If conflict, clear from the start of conflicting range
        if "Conflicting data exists at address" in error_msg:
            if debug_addr:
                print(f"[DBG]   parsing conflict range from error")
            import re
            match = re.search(r'address\s+([0-9a-fA-F]+)\s+to\s+([0-9a-fA-F]+)', error_msg)
            if match:
                conflict_start_str = match.group(1)
                if debug_addr:
                    print(f"[DBG]   conflict starts at: {conflict_start_str}")
                try:
                    conflict_start_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(conflict_start_str)
                    d_conflict = getDataAt(conflict_start_addr)
                    if debug_addr:
                        print(f"[DBG]   found conflict data: {d_conflict}")
                    if d_conflict is not None:
                        if debug_addr:
                            print(f"[DBG]   clearing from conflict start")
                        clearData(d_conflict)
                        if debug_addr:
                            print(f"[DBG]   retrying createAsciiString")
                        createAsciiString(saddr, length)
                        if debug_addr:
                            print(f"[DBG]   SUCCESS after clearing")
                        print("    Created string: len=%d" % length)
                except Exception as e3:
                    if debug_addr:
                        print(f"[DBG]   FAILED after clearing: {e3}")
            else:
                if debug_addr:
                    print(f"[DBG]   could not parse conflict range")

# ---- main ----
print("====== Beginning of SplitGoStrings script ======")
print("[*] SplitGoStrings: starting")

text_start = None
text_end = None
for block in getMemoryBlocks():
    if block.getName() == ".text":
        text_start = block.getStart()
        text_end = block.getEnd()
        break

if text_start is None:
    print("[!] No .text block found")
else:
    print("[*] .text: 0x%x - 0x%x" % (text_start.getOffset(), text_end.getOffset()))

    fixed = 0
    skipped = 0
    addr = text_start

    while addr.compareTo(text_end) <= 0:
        try:
            res = try_pattern(addr)
            if res is None:
                addr = addr.add(1)
                continue
            if res[0] == "found":
                if res[1].getOffset() == 0x0838a834:
                    print(f"[DBG] Match at 0x{addr.getOffset():08x}: saddr={res[1]}, len={res[2]}, ins_len={res[3]}, existing={getDataAt(res[1])}")
                fix_string_at(res[1], res[2])
                fixed += 1
                addr = addr.add(res[3])
            else:
                addr = addr.add(res[1] if res[1] > 0 else 1)
        except:
            skipped += 1
            addr = addr.add(1)

    print("[=] Done: fixed=%d  skipped=%d" % (fixed, skipped))
