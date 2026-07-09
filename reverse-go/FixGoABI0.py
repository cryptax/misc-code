# Fix Go ABI0 function signatures for 32-bit x86 binaries
#
# Go ABI0 passes ALL args and returns on the caller's stack.
# Ghidra types Go functions as void(void), causing the decompiler
# to eliminate branches consuming return values.
#
# This script applies custom variable storage so the decompiler
# sees the real argument/return stack layout.
#
#@category goscripts

from ghidra.program.model.data import ArrayDataType, Undefined4DataType
from ghidra.program.model.listing import Function, ParameterImpl, VariableStorage
from ghidra.program.model.symbol import SourceType
from java.util import ArrayList

CUSTOM = Function.FunctionUpdateType.CUSTOM_STORAGE
dwordType = Undefined4DataType.dataType
fixedCount = 0

def fixGoFunc(program, entry, numArgs, numReturns):
    global fixedCount
    print("  fixing " + str(entry) + "...")

    func = program.getFunctionManager().getFunctionAt(entry)
    if func is None:
        print("  ERROR: No function at " + str(entry))
        return

    txId = program.startTransaction("Fix ABI0: " + func.getName())
    try:
        func.setCustomVariableStorage(True)

        params = ArrayList()
        for i in range(numArgs):
            offset = 4 + i * 4
            storage = VariableStorage(program, offset, 4)
            params.add(ParameterImpl("arg" + str(i), dwordType, storage, program, SourceType.ANALYSIS))

        func.replaceParameters(params, CUSTOM, True, SourceType.ANALYSIS)

        if numReturns > 0:
            baseOffset = 4 + numArgs * 4
            totalSize = numReturns * 4
            retStorage = VariableStorage(program, baseOffset, totalSize)
            retType = ArrayDataType(dwordType, numReturns, 4)
            func.setReturn(retType, retStorage, SourceType.ANALYSIS)

        program.endTransaction(txId, True)
        fixedCount += 1
        print("  OK: " + func.getName() + " (" + str(numArgs) + "i, " + str(numReturns) + "r)")

    except Exception as e:
        program.endTransaction(txId, False)
        print("  FAIL: " + func.getName() + " @ " + str(entry) + ": " + str(e))
        import traceback
        traceback.print_exc()


program = currentProgram
print("FixGoABI0: Starting Go ABI0 function signature fixup...")

fixGoFunc(program, toAddr(0x08286660), 6, 4)  # services.ReadingMessages
fixGoFunc(program, toAddr(0x08285680), 2, 4)  # services.DecryptString
fixGoFunc(program, toAddr(0x082858a0), 2, 2)  # services.ExcuteCommand
fixGoFunc(program, toAddr(0x08285340), 2, 2)  # services.EncryptString
fixGoFunc(program, toAddr(0x082870e0), 8, 0)  # services.SendingMessages

fixGoFunc(program, toAddr(0x082862b0), 0, 2)  # services.GetClientName
fixGoFunc(program, toAddr(0x08285c00), 0, 3)  # services.Auth
fixGoFunc(program, toAddr(0x082841c0), 2, 4)  # services.GetCompleteAuth
fixGoFunc(program, toAddr(0x08284320), 4, 2)  # services.GetUser
fixGoFunc(program, toAddr(0x082848e0), 6, 2)  # services.CreateFolder
fixGoFunc(program, toAddr(0x08284ce0), 6, 2)  # services.GetFolderId
fixGoFunc(program, toAddr(0x08286300), 6, 0)  # services.DeleteingMessage

print("FixGoABI0: Applied fixups to " + str(fixedCount) + " functions.")
