Ghidra scripts to assist reversing Go.

- GoFuncRename120.java is entirely written by AI
- `FixGoABI0.py`: this script edits function signatures of each called function in the current one, to match Go ABI0 (reminder: in ABI0, all arguments and return values are passed on the caller's stack). The script sets `setCustomVariableStorage(true)` for each callee, then defines explicit stack offsets for each argument and return values. Doing this helps Ghidra decompiler work correctly: otherwise, it often eliminates things that it thinks is dead code...
- find_dynamic_strings.py comes from [CUJO](https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/find_dynamic_strings.py) + fixes by me + improvements to find more strings by AI.
