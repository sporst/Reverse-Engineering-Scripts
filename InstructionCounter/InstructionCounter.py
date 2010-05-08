#
# InstructionCounter for IDAPython
#
# Copyright (c) 2006 Sebastian Porst (webmaster@the-interweb.com)
# All rights reserved.
#
# This software is licensed under the zlib/libpng License.
# For more details see http://www.opensource.org/licenses/zlib-license.php

from idautils import *

try:
	print "Starting..."

	opcodes = {}
	
	total = 0
	
	for fnr in range(0, get_func_qty()):
		func = getn_func(fnr)

		for addr in range(func.startEA, func.endEA):
			
			flags = getFlags(addr)
			
			if isHead(flags) and isCode(flags):
				line = GetDisasm(addr)
				index = line.find("  ")
				opcode = line[:index + 1000 * (index == -1)] # Kill me for this line
					
				if opcodes.has_key(opcode):
					opcodes[opcode] = opcodes[opcode] + 1
				else:
					opcodes[opcode] = 1
					
				total = total + 1

	c = opcodes.items()
	c.sort(lambda x,y: y[1] - x[1])
	
	print "Done."

	filename = AskFile(1, "*.*", "Save result to...")
	
	if filename != None:
		file = open(filename, "w")
		
		file.write("Opcode distribution of file: " + GetInputFilePath() + "\n")
		file.write("Total number of opcodes: " + str(total) + "\n\n")
		
		for i, v in enumerate(c):
			file.write("%04i. %06i %8.2f%%      %s\n" % ((i+1), v[1], 100.0 * v[1] / total, v[0]))
		
		file.close()
		
except:
	print "Unexpected error: ", sys.exc_info()[0]