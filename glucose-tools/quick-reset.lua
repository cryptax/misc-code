local cmds = require('commands')
local getopt = require('getopt')
local utils =  require('utils')

author = '@cryptax'
version = 'v0.1'
desc = [[
This script tries to reset a glucose sensor
 ]]
example = [[

	 script run axelle

]]
usage = [[
script run axelle -h 

Arguments:
	-h             : this help
]]

local DEBUG = true
--- 
-- A debug printout-function
local function dbg(args)
    if not DEBUG then return end
    if type(args) == "table" then
		local i = 1
		while args[i] do
			dbg(args[i])
			i = i+1
		end
	else
		print("###", args)
	end	
end	
--- 
-- This is only meant to be used when errors occur
local function oops(err)
	print("ERROR: ",err)
	return nil, err
end
--- 
-- Usage help
local function help()
	print(author)	
	print(version)	
	print(desc)
	print('Example usage')
	print(example)
end
--
--- Reset 
local function reset()
	print('Unlock tag')
 	core.console("hf 15 cmd raw -c CENSORED")
	print('Blocks 1 and 2: zero')
	core.console("hf 15 cmd write u 1 00 00 00 00 00 00 00 00")
	core.console("hf 15 cmd write u 2 00 00 00 00 00 00 00 00")	
	print('Block 0: Reset Stage of life=1 and Activity=0 and CRC')
	core.console("hf 15 cmd write u 0 COMPUTE-IT-FOR-YOURS")
	print('Block 3: Trend Index=0, CRC')
	core.console("hf 15 cmd write u 3 62 C2 00 00 00 00 00 00")
	print('Block 0x27 included: zero')
	core.console("hf 15 cmd write u 0x27 00 00 00 00 00 00 00 00")	
	print('Lock tag')
	core.console("hf 15 cmd raw -c CENSORED")
	print('Read and check: ')
	core.console("hf 15 cmd read u 0")
	core.console("hf 15 cmd read u 1")
	core.console("hf 15 cmd read u 2")
	core.console("hf 15 cmd read u 3")
	core.console("hf 15 cmd read u 0x27")
	core.console("hf 15 cmd read u 0x28")
end
--

--- 
-- The main entry point
function main(args)

	print( string.rep('--',20) )
	print( string.rep('--',20) )	
	print()

	reset()	
end

main(args)
