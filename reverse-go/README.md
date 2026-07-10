Ghidra scripts to assist reversing Go.

- `GoFuncRename120.java` is entirely written by AI
- `FixGoABI0.py`: this script edits function signatures of each called function in the current one, to match Go ABI0 (reminder: in ABI0, all arguments and return values are passed on the caller's stack). The script sets `setCustomVariableStorage(true)` for each callee, then defines explicit stack offsets for each argument and return values. Doing this helps Ghidra decompiler work correctly: otherwise, it often eliminates things that it thinks is dead code...
- `SplitGoStrings.py`: finds the length of Go strings and renames label accordingly. This is not entirely perfect: if the length is provided an unknown way by the script, the string is not processed. Written by AI.
