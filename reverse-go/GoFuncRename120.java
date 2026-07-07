// Recover function names in stripped Go binaries (Go 1.18 / 1.20+)
// Based on getCUJO ThreatIntel GoFuncRename120.py, rewritten as Java GhidraScript
//
// Magic 0xFFFFFFF0 = Go 1.18, 0xFFFFFFF1 = Go 1.20 (identical layout)
//
// Run from Ghidra: Script Manager -> GoFuncRename120.java -> Run
//
//@author  adapted from padorka@cujoai
//@category goscripts
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class GoFuncRename120 extends GhidraScript {

    private Memory mem;

    private int readU32LE(Address base, long off) throws Exception {
        int b0 = mem.getByte(base.add(off)) & 0xFF;
        int b1 = mem.getByte(base.add(off + 1)) & 0xFF;
        int b2 = mem.getByte(base.add(off + 2)) & 0xFF;
        int b3 = mem.getByte(base.add(off + 3)) & 0xFF;
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    private long readU64LE(Address base, long off) throws Exception {
        long lo = readU32LE(base, off) & 0xFFFFFFFFL;
        long hi = readU32LE(base, off + 4) & 0xFFFFFFFFL;
        return lo | (hi << 32);
    }

    private String readCString(Address addr) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 512; i++) {
            byte b = mem.getByte(addr.add(i));
            if (b == 0) break;
            sb.append((char)(b & 0xFF));
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        mem = currentProgram.getMemory();

        // Find .gopclntab
        MemoryBlock pclntabBlock = null;
        for (MemoryBlock block : mem.getBlocks()) {
            if (block.getName().equals(".gopclntab")) {
                pclntabBlock = block;
                break;
            }
        }
        if (pclntabBlock == null) {
            println("[!] .gopclntab not found - aborting");
            return;
        }

        Address start = pclntabBlock.getStart();
        println("[*] .gopclntab at 0x" + Long.toHexString(start.getOffset()));

        // Check magic
        int magic = readU32LE(start, 0);
        println("[*] magic = 0x" + Integer.toHexString(magic & 0xFFFFFFFF));

        if (magic == 0xfffffff0 || magic == 0xfffffff1) {
            println("[*] Go 1.18/1.20 layout detected");
            renameFunctions118(start);
        } else if (magic == 0xfffffffa) {
            println("[!] Go 1.16 detected - layout not handled by this script");
        } else if (magic == 0xfffffffb) {
            println("[!] Go 1.2-1.15 detected - layout not handled by this script");
        } else {
            println("[!] Unknown magic 0x" + Integer.toHexString(magic) + " - attempting 1.18 layout");
            renameFunctions118(start);
        }
    }

    private void renameFunctions118(Address start) throws Exception {
        int ptrsize = mem.getByte(start.add(7)) & 0xFF;
        println("[*] ptrsize = " + ptrsize);

        long nfunctab, textStart, funcnametabOff, functabOff;
        if (ptrsize == 8) {
            nfunctab      = readU64LE(start, 8);
            textStart     = readU64LE(start, 8 + 2 * ptrsize);
            funcnametabOff = readU64LE(start, 8 + 3 * ptrsize);
            functabOff    = readU64LE(start, 8 + 7 * ptrsize);
        } else {
            nfunctab      = readU32LE(start, 8) & 0xFFFFFFFFL;
            textStart     = readU32LE(start, 8 + 2 * ptrsize) & 0xFFFFFFFFL;
            funcnametabOff = readU32LE(start, 8 + 3 * ptrsize) & 0xFFFFFFFFL;
            functabOff    = readU32LE(start, 8 + 7 * ptrsize) & 0xFFFFFFFFL;
        }

        println("[*] nfunctab    = " + nfunctab);
        println("[*] textStart   = 0x" + Long.toHexString(textStart));
        println("[*] funcnametab offset = 0x" + Long.toHexString(funcnametabOff));
        println("[*] functab     offset = 0x" + Long.toHexString(functabOff));

        Address funcnametab = start.add(funcnametabOff);
        Address functab     = start.add(functabOff);

        int renamed = 0, created = 0, errors = 0;
        int fieldSize = 4; // both fields are uint32 in Go 1.18+

        for (long i = 0; i < nfunctab; i++) {
            try {
                Address entry = functab.add(i * 2 * fieldSize);
                long pcOff       = readU32LE(entry, 0) & 0xFFFFFFFFL;
                long funcdataOff = readU32LE(entry, fieldSize) & 0xFFFFFFFFL;

                long funcAddrVal = textStart + pcOff;
                Address funcAddr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(funcAddrVal);

                // nameOff is at offset 4 in the _func struct (relative to functab base)
                long nameOff = readU32LE(functab.add(funcdataOff), fieldSize) & 0xFFFFFFFFL;
                Address nameAddr = funcnametab.add(nameOff);

                String funcName = readCString(nameAddr).trim().replace(" ", "");
                if (funcName.isEmpty()) continue;

                Function func = getFunctionAt(funcAddr);
                if (func != null) {
                    String old = func.getName();
                    func.setName(funcName, SourceType.USER_DEFINED);
                    println("[+] " + old + " -> " + funcName);
                    renamed++;
                } else {
                    createFunction(funcAddr, funcName);
                    println("[+] Created " + funcName + " @ 0x" + Long.toHexString(funcAddrVal));
                    created++;
                }
            } catch (Exception e) {
                errors++;
            }
        }

        println("\n[=] Done: renamed=" + renamed + "  created=" + created + "  errors=" + errors);
    }
}
