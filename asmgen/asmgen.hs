-- Generates lots and lots of x86 instructions
--
-- Visit http://www.the-interweb.com :)

import Data.List

-- Defines the mnemonics and their possible operands
mnemonics = [
	("jcxz", jcc_targets),    -- Start with the jcxz and other instructions which only support relative jumps and can not be used later
	("jecxz", jcc_targets),
	("loop", [[["start"]]]),
	("loope", [[["start"]]]),
	("loopne", [[["start"]]]),
	("aaa", no_operands),
	("aad", no_operands),
	("aam", no_operands),
	("aas", no_operands),
	("adc", typical_binary),
	("add", typical_binary),
	("and", typical_binary),
	("bound", [[r16, "someDword" : mem32], [r32, "someDword" : mem64]]),
	("bsf", [[r16, r16], [r32, r32], [r16, mem16], [r32, mem32]]),
	("bsr", [[r16, r16], [r32, r32], [r16, mem16], [r32, mem32]]),
	("bsr", [[r16, r16], [r32, r32], [r16, mem16], [r32, mem32]]),
	("bswap", [[r32]]),
	("bt", [[mem16, imm8], [mem32, imm8], [r16, imm8], [r32, imm8], [mem16, r16], [mem32, r32]]),
	("btc", [[mem16, imm8], [mem32, imm8], [r16, imm8], [r32, imm8], [mem16, r16], [mem32, r32]]),
	("btr", [[mem16, imm8], [mem32, imm8], [r16, imm8], [r32, imm8], [mem16, r16], [mem32, r32]]),
	("bts", [[mem16, imm8], [mem32, imm8], [r16, imm8], [r32, imm8], [mem16, r16], [mem32, r32]]),
	("call", [[r32], [mem32], [["start"]]]),
	("cbw", no_operands),
	("cdq", no_operands),
	("clc", no_operands),
	("cld", no_operands),
	("cli", no_operands),
	("cmc", no_operands),
	("cmp", typical_binary),
	("cmpsb", no_operands),
	("cmpsw", no_operands),
	("cmpsd", no_operands),
	("cmpxchg", [[r32, r32], [mem32, r32]]),
	("cwd", no_operands),
	("cwde", no_operands),
	("daa", no_operands),
	("das", no_operands),
	("dec", rvalues),
	("div", rvalues),
	("enter", [[["2"], ["2"]]]),
	("hlt", no_operands),
	("idiv", rvalues),
	("imul", imul),
	("inc", rvalues),
	("int", [[["3"]]]),
	("ja", jcc_targets),
	("jae", jcc_targets),
	("jb", jcc_targets),
	("jbe", jcc_targets),
	("jc", jcc_targets),
	("je", jcc_targets),
	("jg", jcc_targets),
	("jge", jcc_targets),
	("jl", jcc_targets),
	("jle", jcc_targets),
	("jmp", jcc_targets),
	("jna", jcc_targets),
	("jnae", jcc_targets),
	("jnb", jcc_targets),
	("jnbe", jcc_targets),
	("jnc", jcc_targets),
	("jne", jcc_targets),
	("jng", jcc_targets),
	("jnge", jcc_targets),
	("jnl", jcc_targets),
	("jnle", jcc_targets),
	("jno", jcc_targets),
	("jnp", jcc_targets),
	("jns", jcc_targets),
	("jnz", jcc_targets),
	("jo", jcc_targets),
	("jp", jcc_targets),
	("jpe", jcc_targets),
	("jpo", jcc_targets),
	("js", jcc_targets),
	("jz", jcc_targets),
	("lahf", no_operands),
	("lds", [[r16, mem32]]),
	("lea", [[r16, mem16]]),
	("lea", [[r32, mem32]]),
	("leave", no_operands),
	("les", [[r16, mem32]]),
	("lfs", [[r16, mem32]]),
	("lgs", [[r16, mem32]]),
	("lodsb", no_operands),
	("lodsw", no_operands),
	("lodsd", no_operands),
	("lss", [[r16, mem32]]),
	("mov", typical_binary),
	("movsx", extend),
	("movzx", extend),
	("movsb", no_operands),
	("movsw", no_operands),
	("movsd", no_operands),
	("mul", rvalues),
	("neg", rvalues),
	("nop", no_operands),
	("not", rvalues),
	("or", typical_binary),
	("pop", [[segments_writable], [r16], [mem16], [r32], [mem32]]),
	("popa", no_operands),
	("popad", no_operands),
	("push", [segments] : [[r16], [mem16], [imm16]] ++ [[r32], [mem32], [imm32]]),
	("pusha", no_operands),
	("pushad", no_operands),
	("rcl", rotate),
	("rcr", rotate),
	("rep", [[["movsb"]], [["movsw"]], [["movsd"]], [["lodsb"]], [["lodsw"]], [["lodsd"]], [["stosb"]], [["stosw"]], [["stosd"]]]),
	("repe", [[["cmpsb"]], [["cmpsw"]], [["cmpsd"]], [["scasb"]], [["scasw"]], [["scasd"]]]),
	("repne", [[["cmpsb"]], [["cmpsw"]], [["cmpsd"]], [["scasb"]], [["scasw"]], [["scasd"]]]),
	("retn", [[[""]], [["4"]]]),
	("retf", [[[""]], [["4"]]]),
	("rol", rotate),
	("ror", rotate),
	("sahf", no_operands),
	("sal", rotate),
	("sar", rotate),
	("sbb", typical_binary),
	("scasb", no_operands),
	("scasw", no_operands),
	("scasd", no_operands),
	("seta", [[r8], [mem8]]),
	("setae", [[r8], [mem8]]),
	("setb", [[r8], [mem8]]),
	("setbe", [[r8], [mem8]]),
	("sete", [[r8], [mem8]]),
	("setne", [[r8], [mem8]]),
	("setl", [[r8], [mem8]]),
	("setge", [[r8], [mem8]]),
	("setle", [[r8], [mem8]]),
	("setg", [[r8], [mem8]]),
	("sets", [[r8], [mem8]]),
	("setns", [[r8], [mem8]]),
	("setc", [[r8], [mem8]]),
	("setnc", [[r8], [mem8]]),
	("seto", [[r8], [mem8]]),
	("setno", [[r8], [mem8]]),
	("setp", [[r8], [mem8]]),
	("setnp", [[r8], [mem8]]),
	("shl", rotate),
	("shr", rotate),
	("shld", shift_double),
	("shrd", shift_double),
	("stc", no_operands),
	("std", no_operands),
	("sti", no_operands),
	("stosb", no_operands),
	("stosw", no_operands),
	("stosd", no_operands),
	("sub", typical_binary),
	("test", typical_binary),
	("wait", no_operands),
	("fwait", no_operands),
	("xchg", [[r8, r8], [r16, r16], [r32, r32], [r8, mem8], [r16, mem16], [r32, mem32]]),
	("xlatb", [[mem8]]),
	("xlatb", no_operands),
	("xor", typical_binary)
	]

-- Register definitions
r8 = ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"]
r16 = ["ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]
r32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]
segments = "cs" : "ds" : segments_writable
segments_writable = ["es", "fs", "gs", "ss"]

-- Definitions of all possible memory access operand trees
mem8 = ["byte ptr [someDword]"] ++ simple_ptr "byte" r32 ++ ptr_offset "byte" r32 ++ mult_reg "byte" r32 ++ two_regs "byte" r32 ++ mult_two_regs "byte" r32
mem16 = ["word ptr [someDword]"] ++ (simple_ptr "word" r32) ++ (ptr_offset "word" r32) ++ mult_reg "word" r32 ++ two_regs "word" r32 ++ mult_two_regs "word" r32
mem32 = ["dword ptr [someDword]"] ++ (simple_ptr "dword" r32) ++ (ptr_offset "dword" r32) ++ mult_reg "dword" r32 ++ two_regs "dword" r32 ++ mult_two_regs "dword" r32
mem64 = ["qword ptr [someDword]"] ++ (simple_ptr "qword" r32) ++ (ptr_offset "qword" r32) ++ mult_reg "qword" r32 ++ two_regs "qword" r32 ++ mult_two_regs "qword" r32

-- Definitions of a few sample immediates
imm8 = ["12h"]
imm16 = ["512h"]
imm32 = ["6237512h"]

-- Variant for instructions that use no operands
no_operands = [[]]

-- All variants of typical instructions with two operands
-- like ADD, SUB, AND, OR, XOR, ...
typical_binary = [
	[r8, imm8], [r16, imm8], [r16, imm16], [r32, imm8], [r32, imm32],
	[mem8, imm8], [mem16, imm8], [mem16, imm16], [mem32, imm8], [mem32, imm32],
	[r8, r8], [r16, r16], [r32, r32],
	[mem8, r8], [mem16, r16], [mem32, r32],
	[r8, mem8], [r16, mem16], [r32, mem32]
	]

-- Operand variants for conditional jumps
jcc_targets = [[["start"]]]

-- Operand variants for single-operand instructions that write
-- back to the operand
rvalues = [[r8], [mem8], [r16], [mem16], [r32], [mem32]]

-- Operand variants for the IMUL instruction
imul = [
	[r8],
	[r16],
	[r32],
	[mem8],
	[mem16],
	[mem32],
	[r16, r16],
	[r32, r32],
	[r16, mem16],
	[r32, mem32],
	[r16, imm16],
	[r32, imm32],
	[r16, r16, imm16],
	[r32, r32, imm32],
	[r16, mem16, imm16],
	[r32, mem32, imm32]
	]

-- Operand variants for movsx and movzx
extend = [
	[r16, r8],
	[r16, mem8],
	[r32, r8],
	[r32, mem8],
	[r32, r16],
	[r32, mem16]
	]

-- Operand variants for shifts and rotates
rotate = [
	[r8, imm8],
	[mem8, imm8],
	[r16, imm8],
	[mem16, imm8],
	[r32, imm8],
	[mem32, imm8],
	[r8, ["cl"]],
	[mem8, ["cl"]],
	[r16, ["cl"]],
	[mem16, ["cl"]],
	[r32, ["cl"]],
	[mem32, ["cl"]]
	]

-- Operand variants for double precision rotates
shift_double = [
	[r16, r16, "cl" : imm8],
	[mem16, r16, "cl" : imm8],
	[r32, r32, "cl" : imm8],
	[mem32, r32, "cl" : imm8]
	]

-- Flattens a nested list
flatten = foldr (++) []

-- Only memory access operands with at most 1 use of ESP are valid
fmbr = filter (\(x:y:[]) -> x /= "esp" || y /= "esp")

-- Create operands of the form "byte/word/dword ptr [value]"
simple_ptr size = map (\x -> size ++ " ptr [" ++ x ++ "]")

-- Create operands of the form "byte/word/dword ptr [register + 123456h]"
ptr_offset size = map (\x -> size ++ " ptr [" ++ x ++ " + 123456h]")

-- Create operands of the form "byte/word/dword ptr [4 * register + 123456h]"
mult_reg size regs = map (\x -> size ++ " ptr [4 * " ++ x ++ " + 123456h]") (regs \\ ["esp"])

-- Create operands of the form "byte/word/dword ptr [register + register]"
two_regs size regs = map (\(x:y:[]) -> size ++ " ptr [" ++ x ++ " + " ++ y ++ "]") (fmbr $ zip_lists [regs, regs])

-- Create operands of the form "byte/word/dword ptr [4 * register + register]"
mult_two_regs size regs = map (\(x:y:[]) -> size ++ " ptr [4 * " ++ x ++ " + " ++ y ++ "]") (fmbr $ zip_lists [regs \\ ["esp"], regs])

-- Takes a list of the form [["eax", "ebx", ...], ["esi", "edi", ...]] and turns it into
-- [["eax", "esi"], ["eax, "edi"], ["eax", ...], ["ebx", "esi"], ["ebx", "edi"], ["ebx", "..."]]
zip_lists :: [[a]] -> [[a]]
zip_lists x | length x <= 1 = transpose x
zip_lists (x:xs) = [a : b | a <- x, b <- zip_lists(xs)]

-- Converts a list of operands an turns it into a comma-separated string
to_operand_string :: [String] -> String
to_operand_string = concat . intersperse ", "

-- Creates the operand strings for a list of given variants
create_operand_strings :: [[String]] -> [String]
create_operand_strings = map to_operand_string . zip_lists

-- Generates all instruction strings for one variant of an instruction
generate_variant :: String -> [[String]] -> [String]
generate_variant mnemonic =  map (\x -> concat [mnemonic, " ", x]) . create_operand_strings

-- Generates all instruction strings for one mnemonic
gen_instruction_strings :: (String, [[[String]]]) -> [[String]]
gen_instruction_strings (mnemonic, variants) = map (\x -> generate_variant mnemonic x) variants

-- Main function; used to print the generated results
main = putStrLn $ unlines $ flatten $ flatten $ map gen_instruction_strings mnemonics