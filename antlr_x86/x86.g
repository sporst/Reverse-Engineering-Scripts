// ANTLR grammer for parsing x86 assembly instructions in a slightly modified MASM syntax.
//
// Copyright 2009 by Sebastian Porst (sp@porst.tv); visit http://www.the-interweb.com for updates.
//
// This grammar is licensed under the GPL. If you contact me I can re-license the grammar to
// the zlib/libpng license depending on what you want to do with it.
//
// Unsupported:
//	- Many instructions
//	- All kinds of things that use memory segments/selectors
//
// Note: The main rule of this grammar is called "instruction"

grammar x86;

options {
	output = AST;
}

tokens {
	INSTRUCTION;
	PREFIX;
	MNEMONIC;
	OPERANDS;
	OPERAND;
	REGISTER_8;
	REGISTER_16;
	REGISTER_32;
	HEX_LITERAL_8;
	HEX_LITERAL_16;
	HEX_LITERAL_32;
	MEM_8;
	MEM_16;
	MEM_32;
	OPERATOR;
}

WS
	: (' '|'\n')+ {$channel=HIDDEN;} // Ignore whitespace
	;

HEX_DIGIT
	:	'0' .. '9' | 'a' .. 'f' | 'A' .. 'F'
	;
	
// All 8 bit x86 registers
reg8
	:	'al' -> REGISTER_8["al"]
	|	'ah' -> REGISTER_8["ah"]
	|	'bl' -> REGISTER_8["bl"]
	|	'bh' -> REGISTER_8["bh"]
	|	'cl' -> REGISTER_8["cl"]
	|	'ch' -> REGISTER_8["ch"]
	|	'dl' -> REGISTER_8["dl"]
	|	'dh' -> REGISTER_8["dh"]
	;

// All 16 bit x86 registers
reg16	
	:	'ax' -> REGISTER_16["ax"]
	|	'bx' -> REGISTER_16["bx"]
	|	'cx' -> REGISTER_16["cx"]
	|	'dx' -> REGISTER_16["dx"]
	|	'si' -> REGISTER_16["si"]
	|	'di' -> REGISTER_16["di"]
	|	'sp' -> REGISTER_16["sp"]
	|	'bp' -> REGISTER_16["bp"]
	;

// All 32 bit x86 registers
reg32	
	:	'eax' -> REGISTER_32["eax"]
	|	'ebx' -> REGISTER_32["ebx"]
	|	'ecx' -> REGISTER_32["ecx"]
	|	'edx' -> REGISTER_32["edx"]
	|	'esi' -> REGISTER_32["esi"]
	|	'edi' -> REGISTER_32["edi"]
	|	'esp' -> REGISTER_32["esp"]
	|	'ebp' -> REGISTER_32["ebp"]
	;

// All x86 accumulator registers
accumulator
	:	'al'	-> REGISTER_8["al"]
	|	'ax'	-> REGISTER_16["ax"]
	|	'eax' 	-> REGISTER_32["eax"]
	;

// 8 bits literals of the form XXh or 0xXX
literal_8
	:	literal_8_digits 'h' -> literal_8_digits
	|	'0x' literal_8_digits -> literal_8_digits
	;
	
literal_8_digits
	:	a=HEX_DIGIT -> HEX_LITERAL_8[$a.text]
	|	a=HEX_DIGIT b=HEX_DIGIT -> HEX_LITERAL_8[$a.text + $b.text]
	;

// 16 bits literals of the form XXXXh or 0xXXXX
literal_16
	:	literal_16_digits 'h' -> literal_16_digits
	|	'0x' literal_16_digits -> literal_16_digits
	;

literal_16_digits
	:	a=HEX_DIGIT -> HEX_LITERAL_16[$a.text]
	|	a=HEX_DIGIT b=HEX_DIGIT -> HEX_LITERAL_16[$a.text + $b.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT -> HEX_LITERAL_16[$a.text + $b.text + $c.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT d=HEX_DIGIT -> HEX_LITERAL_16[$a.text + $b.text + $c.text + $d.text]
	;

// 32 bits literals of the form XXXXXXXXh or 0xXXXXXXXX
literal_32
	:	literal_32_digits 'h' -> literal_32_digits
	|	'0x' literal_32_digits -> literal_32_digits
	;
	
literal_32_digits
	:	a=HEX_DIGIT -> HEX_LITERAL_32[$a.text]
	|	a=HEX_DIGIT b=HEX_DIGIT -> HEX_LITERAL_32[$a.text + $b.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT -> HEX_LITERAL_32[$a.text + $b.text + $c.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT d=HEX_DIGIT -> HEX_LITERAL_32[$a.text + $b.text + $c.text + $d.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT d=HEX_DIGIT e=HEX_DIGIT -> HEX_LITERAL_32[$a.text + $b.text + $c.text + $d.text + $e.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT d=HEX_DIGIT e=HEX_DIGIT f=HEX_DIGIT -> HEX_LITERAL_32[$a.text + $b.text + $c.text + $d.text + $e.text + $f.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT d=HEX_DIGIT e=HEX_DIGIT f=HEX_DIGIT g=HEX_DIGIT -> HEX_LITERAL_32[$a.text + $b.text + $c.text + $d.text + $e.text + $f.text + $g.text]
	|	a=HEX_DIGIT b=HEX_DIGIT c=HEX_DIGIT d=HEX_DIGIT e=HEX_DIGIT f=HEX_DIGIT g=HEX_DIGIT h=HEX_DIGIT-> HEX_LITERAL_32[$a.text + $b.text + $c.text + $d.text + $e.text + $f.text + $g.text + $h.text]
	;

// Register or memory access of size 8 bits
regmem_8
	:	reg8
	|	mem8
	;
	
// Register or memory access of size 16 bits
regmem_16
	:	reg16
	|	mem16
	;

// Register or memory access of size 32 bits
regmem_32
	:	reg32
	|	mem32
	;
	
// Register or memory access of any size
regmem
	:	regmem_8
	|	regmem_16
	|	regmem_32
	;
	
// Possible operand types for binary instruction source operands of size 8 bits but without memory access
simple_source_operand_8
	:	reg8		 -> ^(OPERAND reg8)
	|	literal_8	 -> ^(OPERAND literal_8)
	;
	
// Possible operand types of binary instruction source operands of size 16 bits but without memory access
simple_source_operand_16
	:	reg16		-> ^(OPERAND reg16)
	|	literal_16	-> ^(OPERAND literal_16)
	;
	
// Possible operand types of binary instruction source operands of size 32 bits but without memory access
simple_source_operand_32
	:	reg32		 -> ^(OPERAND reg32)
	|	literal_32	 -> ^(OPERAND literal_32)
	;

// Possible operand types for binary instruction source operands of size 8 bits
complex_source_operand_8
	:	complex_target_operand_8
	| 	literal_8 -> ^(OPERAND literal_8)
	;
	
// Possible operand types for binary instruction source operands of size 16 bits
complex_source_operand_16
	:	complex_target_operand_16
	|	literal_16 -> ^(OPERAND literal_16)
	;
	
// Possible operand types for binary instruction source operands of size 32 bits
complex_source_operand_32
	:	complex_target_operand_32
	|	literal_32 -> ^(OPERAND literal_32)
	;

// Possible operand types of binary instruction target operands
complex_target_operand
	:	complex_target_operand_8
	|	complex_target_operand_16
	|	complex_target_operand_32
	;
	
// Possible operand types of binary instruction target operands of size 8 bits
complex_target_operand_8
	:	reg8	-> ^(OPERAND reg8)
	|	mem8	-> ^(OPERAND mem8)
	;
	
// Possible operand types of binary instruction target operands of size 16 bits
complex_target_operand_16
	:	reg16	-> ^(OPERAND reg16)
	|	mem16	-> ^(OPERAND mem16)
	;

// Possible operand types of binary instruction target operands of size 32 bits
complex_target_operand_32
	:	reg32	-> ^(OPERAND reg32)
	|	mem32	-> ^(OPERAND mem32)
	;

// Accessing a byte from memory
mem8
	:	'byte' 'ptr' '[' memory_expression ']' -> ^(MEM_8 memory_expression)
	;

// Accessing a word from memory
mem16
	:	'word' 'ptr' '[' memory_expression ']' -> ^(MEM_16 memory_expression)
	;

// Accessing a dword from memory; the 'dword ptr' is optional here
mem32
	:	('dword' 'ptr')? '[' memory_expression ']' -> ^(MEM_32 memory_expression)
	;

// Used to build sub-expressions in memory access expressions
additive_operand
	:	'+'	-> OPERATOR["+"]
	| 	'-'	-> OPERATOR["-"]
	;

// The expression between the brackets when accessing memory
memory_expression
	:	simple_expression							// mov eax, [0x1234]
	|	mult_expression
	|	simple_expression additive_operand simple_expression			-> ^(additive_operand simple_expression simple_expression)					// mov eax, [0x1234 + eax]

	|	simple_expression additive_operand mult_expression			-> ^(additive_operand simple_expression mult_expression)			// mov eax, [0x1234 + x * y]
	|	mult_expression additive_operand simple_expression			-> ^(additive_operand mult_expression simple_expression) // mov eax, [x * y + 0x1234]
	
	|	reg32 additive_operand mult_expression additive_operand literal_32	-> ^(additive_operand ^(additive_operand reg32 mult_expression) literal_32)
	|	literal_32 additive_operand mult_expression additive_operand reg32	-> ^(additive_operand ^(additive_operand reg32 mult_expression) literal_32)
	
	|	mult_expression additive_operand reg32 additive_operand literal_32	-> ^(additive_operand ^(additive_operand reg32 mult_expression) literal_32)
	|	mult_expression additive_operand literal_32 additive_operand reg32	-> ^(additive_operand ^(additive_operand reg32 mult_expression) literal_32)
	|	mult_expression additive_operand literal_32 additive_operand literal_32	-> ^(additive_operand ^(additive_operand literal_32 mult_expression) literal_32)

	|	reg32 additive_operand literal_32 additive_operand mult_expression	-> ^(additive_operand ^(additive_operand reg32 mult_expression) literal_32)
	|	literal_32 additive_operand reg32 additive_operand mult_expression	-> ^(additive_operand ^(additive_operand reg32 mult_expression) literal_32)
	|	literal_32 additive_operand literal_32 additive_operand mult_expression	-> ^(additive_operand ^(additive_operand literal_32 mult_expression) literal_32)
	;

// Multiplicative part of memory access expressions
mult_expression
	:	literal_32 '*' reg32	-> ^(OPERATOR["*"] literal_32 reg32)
	|	reg32 '*' literal_32	-> ^(OPERATOR["*"] reg32 literal_32)
	;

simple_expression
	:	reg32
	|	literal_32
	;

// This is the main rule of the grammar. It can be used to parse a complete x86 instruction
instruction
	:	nullary_instruction	-> ^(INSTRUCTION nullary_instruction)		// Instructions without operands
	|	unary_instruction	-> ^(INSTRUCTION unary_instruction)	// Instructions with one operand
	|	binary_instruction	-> ^(INSTRUCTION binary_instruction)	// Instructions with two operands
	|	arpl
	|	bound
	|	bit_scan_instructions		// BSF, BSR
	|	bswap
	|	bit_test_instructions		// BT, BTC, BTR, BTS
	|	cmpxchg
	|	enter
	|	imul
	|	in
	|	int_instruction
	|	branch_instructions		// CALL, standard jumps
	|	jcxz
	|	lar
	|	lds
	|	lea
	|	les
	|	lfs
	|	loop_instructions		// LOOP, LOOPE, LOOPNE
	|	mov_ex_instructions		// MOVSX, MOVZX
	|	out
	|	push
	|	rotate_instructions	-> ^(INSTRUCTION rotate_instructions)		// RCL, RCR, ROL, ROR, SHL, SHR, SAL, SAR
	|	string_instructions	-> ^(INSTRUCTION string_instructions)		// REP X, REPE X, REPNE X
	|	return_instructions	-> ^(INSTRUCTION return_instructions)		// RET, RETN, RETF
	|	set_instructions	-> ^(INSTRUCTION set_instructions)		// SETCC
	|	double_shift_instructions	-> ^(INSTRUCTION double_shift_instructions)	// SHRD, SHLD
	;

// Instructions without any operands
nullary_instruction
	:	'aaa'		-> MNEMONIC["aaa"]
	| 	'aad'		-> MNEMONIC["aad"]
	| 	'aam'		-> MNEMONIC["aam"]
	| 	'aas'		-> MNEMONIC["aas"]
	| 	'cbw'		-> MNEMONIC["cbw"]
	| 	'cdq'		-> MNEMONIC["csq"]
	| 	'clc'		-> MNEMONIC["clc"]
	| 	'cld'		-> MNEMONIC["cld"]
	| 	'cli'		-> MNEMONIC["cli"]
	| 	'clts'		-> MNEMONIC["clts"]
	| 	'cmc'		-> MNEMONIC["cmc"]
	|	cmps_mnemonics
	|	'cwd'		-> MNEMONIC["cwd"]
	|	'cwde'		-> MNEMONIC["cwde"]
	|	'daa'		-> MNEMONIC["daa"]
	|	'das'		-> MNEMONIC["das"]
	|	'hlt'		-> MNEMONIC["hlt"]
	|	'insw'		-> MNEMONIC["insw"]
	|	'into'		-> MNEMONIC["into"]
	|	'invd'		-> MNEMONIC["invd"]
	|	'invlpg'	-> MNEMONIC["invlpg"]
	|	'iret'		-> MNEMONIC["iret"]
	|	'iretd'		-> MNEMONIC["iretd"]
	|	'lahf'		-> MNEMONIC["lahf"]
	|	'leave'		-> MNEMONIC["leave"]
	|	'lock'		-> MNEMONIC["lock"]
	|	lods_mnemonics
	|	movs_mnemonics
	|	'nop'		-> MNEMONIC["nop"]
	|	'popad'		-> MNEMONIC["popad"]
	|	'popaw'		-> MNEMONIC["popaw"]
	|	'popfd'		-> MNEMONIC["popfd"]
	|	'pushaw'	-> MNEMONIC["pushaw"]
	|	'pushad'	-> MNEMONIC["pushad"]
	|	'pushf'		-> MNEMONIC["pushf"]
	|	scas_mnemonics
	|	stos_mnemonics
	|	'sahf'		-> MNEMONIC["sahf"]
	|	'stc'		-> MNEMONIC["stc"]
	|	'std'		-> MNEMONIC["std"]
	|	'sti'		-> MNEMONIC["sti"]
	|	'xlat'		-> MNEMONIC["xlat"]
	;
	
// Instructions with a single operand and default operand options
unary_instruction
	:	unary_instruction_mnemonic complex_target_operand -> unary_instruction_mnemonic ^(OPERANDS complex_target_operand)
	;
	
unary_instruction_mnemonic
	:	'dec'		-> MNEMONIC["dec"]
	|	'div'		-> MNEMONIC["div"]
	|	'idiv'		-> MNEMONIC["idiv"]
	|	'inc'		-> MNEMONIC["inc"]
	|	'mul'		-> MNEMONIC["mul"]
	|	'neg'		-> MNEMONIC["neg"]
	|	'not'		-> MNEMONIC["not"]
	|	'pop'		-> MNEMONIC["pop"]
	;

// Instructions with two operands and default operand options
binary_instruction
	:	binary_instruction_mnemonic binary_operand -> binary_instruction_mnemonic binary_operand
	;

// Mnemonics of all binary instructions with default operand options
binary_instruction_mnemonic
	:	'adc'	-> MNEMONIC["adc"]
	|	'add'	-> MNEMONIC["add"]
	|	'and'	-> MNEMONIC["and"]
	|	'cmp'	-> MNEMONIC["cmp"]
	|	'mov'	-> MNEMONIC["mov"]
	|	'or'	-> MNEMONIC["or"]
	|	'sbb'	-> MNEMONIC["sbb"]
	|	'sub'	-> MNEMONIC["sub"]
	|	'test'	-> MNEMONIC["test"]
	|	'xchg'	-> MNEMONIC["xchg"]
	|	'xor'	-> MNEMONIC["xor"]
	;
	
// Defines the default behaviour of binary instruction operands.
// The target operand can be either a register or a memory address,
// the source operand can be a register, a memory address, or an
// integer literal.
// It is not possible to have both the source operand and the 
// target operand access memory.
binary_operand
	:
	|	reg8 ',' complex_source_operand_8	-> ^(OPERANDS ^(OPERAND reg8) complex_source_operand_8)
	|	mem8 ',' simple_source_operand_8	-> ^(OPERANDS ^(OPERAND mem8) simple_source_operand_8)
	|	reg16 ',' complex_source_operand_16	-> ^(OPERANDS ^(OPERAND reg16) complex_source_operand_16)
	|	mem16 ',' simple_source_operand_16	-> ^(OPERANDS ^(OPERAND mem16) simple_source_operand_16)
	|	reg32 ',' complex_source_operand_32	-> ^(OPERANDS ^(OPERAND reg32) complex_source_operand_32)
	|	mem32 ',' simple_source_operand_32	-> ^(OPERANDS ^(OPERAND mem32) simple_source_operand_32)
	;
	
arpl
	:	'arpl' reg16 ',' reg16 -> ^(INSTRUCTION MNEMONIC["arpl"] ^(OPERANDS ^(OPERAND reg16) ^(OPERAND reg16)))
	|	'arpl' mem16 ',' reg16 -> ^(INSTRUCTION MNEMONIC["arpl"] ^(OPERANDS ^(OPERAND mem16) ^(OPERAND reg16)))
	;

bound
	:	'bound' reg16 ',' mem32 -> ^(INSTRUCTION MNEMONIC["bound"] ^(OPERANDS ^(OPERAND reg16) ^(OPERAND mem32)))
	|	'bound' reg32 ',' mem32 -> ^(INSTRUCTION MNEMONIC["bound"] ^(OPERANDS ^(OPERAND reg32) ^(OPERAND mem32)))
	;
	
bit_scan_instructions
	:	bit_scan_mnemonic reg16 ',' reg16 -> ^(INSTRUCTION bit_scan_mnemonic ^(OPERANDS ^(OPERAND reg16) ^(OPERAND reg16)))
	|	bit_scan_mnemonic reg16 ',' mem16 -> ^(INSTRUCTION bit_scan_mnemonic ^(OPERANDS ^(OPERAND reg16) ^(OPERAND mem16)))
	|	bit_scan_mnemonic reg32 ',' reg32 -> ^(INSTRUCTION bit_scan_mnemonic ^(OPERANDS ^(OPERAND reg32) ^(OPERAND reg32)))
	|	bit_scan_mnemonic reg32 ',' mem32 -> ^(INSTRUCTION bit_scan_mnemonic ^(OPERANDS ^(OPERAND reg32) ^(OPERAND mem32)))
	;
	
bit_scan_mnemonic
	:	'bsf'	-> MNEMONIC["bsf"]
	|	'bsr'	-> MNEMONIC["bsr"]
	;
	
bswap
	:	'bswap' reg32 -> ^(INSTRUCTION MNEMONIC["bswap"] ^(OPERANDS ^(OPERAND reg32)))
	;
	
bit_test_instructions
	:	bit_test_mnemonic bit_test_operands -> ^(INSTRUCTION bit_test_mnemonic bit_test_operands)
	;
	
bit_test_mnemonic
	:	'bt'	-> MNEMONIC["bt"]
	|	'btc'	-> MNEMONIC["btc"]
	|	'btr'	-> MNEMONIC["btr"]
	|	'bts'	-> MNEMONIC["bts"]
	;
	
bit_test_operands
	:	reg16 ',' reg16		-> ^(OPERANDS ^(OPERAND reg16) ^(OPERAND reg16))
	|	mem16 ',' reg16		-> ^(OPERANDS ^(OPERAND mem16) ^(OPERAND reg16))
	|	reg16 ',' literal_8	-> ^(OPERANDS ^(OPERAND reg16) ^(OPERAND literal_8))
	|	mem16 ',' literal_8	-> ^(OPERANDS ^(OPERAND mem16) ^(OPERAND literal_8))
	|	reg32 ',' reg32		-> ^(OPERANDS ^(OPERAND reg32) ^(OPERAND reg32))
	|	mem32 ',' reg32		-> ^(OPERANDS ^(OPERAND mem32) ^(OPERAND reg32))
	|	reg32 ',' literal_8	-> ^(OPERANDS ^(OPERAND reg32) ^(OPERAND literal_8))
	|	mem32 ',' literal_8	-> ^(OPERANDS ^(OPERAND mem32) ^(OPERAND literal_8))
	;
	
cmpxchg
	:	'cmpxchg' regmem_8 ',' reg8	-> ^(INSTRUCTION MNEMONIC["cmpxchg"] ^(OPERANDS ^(OPERAND regmem_8) ^(OPERAND reg8)))
	|	'cmpxchg' regmem_16 ',' reg16	-> ^(INSTRUCTION MNEMONIC["cmpxchg"] ^(OPERANDS ^(OPERAND regmem_16) ^(OPERAND reg16)))
	|	'cmpxchg' regmem_32 ',' reg32	-> ^(INSTRUCTION MNEMONIC["cmpxchg"] ^(OPERANDS ^(OPERAND regmem_32) ^(OPERAND reg32)))
	;
	
enter
	:	'enter' literal_16 ',' literal_8	-> ^(INSTRUCTION MNEMONIC["enter"] ^(OPERANDS ^(OPERAND literal_16) ^(OPERAND literal_8)))
	;
	
imul
	:	'imul' mem32									-> ^(INSTRUCTION MNEMONIC["imul"] ^(OPERANDS ^(OPERAND mem32)))
	|	'imul' imul_first_value								-> ^(INSTRUCTION MNEMONIC["imul"] ^(OPERANDS imul_first_value))
	|	'imul' imul_first_value ',' imul_second_value					-> ^(INSTRUCTION MNEMONIC["imul"] ^(OPERANDS imul_first_value imul_second_value))
	|	'imul' imul_first_value ',' imul_second_value ',' imul_third_value		-> ^(INSTRUCTION MNEMONIC["imul"] ^(OPERANDS imul_first_value imul_second_value imul_third_value))
	;
	
	
imul_first_value
	:	reg16	-> ^(OPERAND reg16)
	|	reg32	-> ^(OPERAND reg32)
	;
	
imul_second_value
	:	regmem_16	-> ^(OPERAND regmem_16)
	|	regmem_32	-> ^(OPERAND regmem_32)
	|	literal_32	-> ^(OPERAND literal_32)
	;
	
imul_third_value
	:	literal_32	-> ^(OPERAND literal_32)
	;
	
in
	:	'in' accumulator ',' literal_8	-> ^(INSTRUCTION MNEMONIC["in"] ^(OPERANDS ^(OPERAND accumulator) ^(OPERAND literal_8)))
	|	'in' accumulator ',' 'dx'	-> ^(INSTRUCTION MNEMONIC["in"] ^(OPERANDS ^(OPERAND accumulator) ^(OPERAND REGISTER_16["dx"])))
	;
	
int_instruction
	:	'int' literal_8		-> ^(INSTRUCTION MNEMONIC["int"] ^(OPERANDS ^(OPERAND literal_8)))
	;
	
branch_instructions
	:	branch_mnemonic complex_source_operand_32
			-> ^(INSTRUCTION branch_mnemonic ^(OPERANDS complex_source_operand_32))
	;
	
branch_mnemonic
	:	'call'	-> MNEMONIC["call"]
	|	'ja'	-> MNEMONIC["ja"]
	|	'jae'	-> MNEMONIC["jae"]
	|	'jb'	-> MNEMONIC["jb"]
	|	'jbe'	-> MNEMONIC["jbe"]
	|	'jc'	-> MNEMONIC["jc"]
	|	'je'	-> MNEMONIC["je"]
	|	'jg'	-> MNEMONIC["jg"]
	|	'jge'	-> MNEMONIC["jge"]
	|	'jl'	-> MNEMONIC["jl"]
	|	'jle'	-> MNEMONIC["jle"]
	|	'jmp'	-> MNEMONIC["jmp"]
	|	'jna'	-> MNEMONIC["jna"]
	|	'jnae'	-> MNEMONIC["jnae"]
	|	'jnb'	-> MNEMONIC["jnb"]
	|	'jnbe'	-> MNEMONIC["jnbe"]
	|	'jnc'	-> MNEMONIC["jnc"]
	|	'jne'	-> MNEMONIC["jne"]
	|	'jng'	-> MNEMONIC["jng"]
	|	'jnge'	-> MNEMONIC["jnge"]
	|	'jnl'	-> MNEMONIC["jnl"]
	|	'jnle'	-> MNEMONIC["jnle"]
	|	'jno'	-> MNEMONIC["jno"]
	|	'jnp'	-> MNEMONIC["jnp"]
	|	'jns'	-> MNEMONIC["jns"]
	|	'jnz'	-> MNEMONIC["jnz"]
	|	'jo'	-> MNEMONIC["jo"]
	|	'jp'	-> MNEMONIC["jp"]
	|	'jpe'	-> MNEMONIC["jpe"]
	|	'jpo'	-> MNEMONIC["jpo"]
	|	'js'	-> MNEMONIC["js"]
	|	'jz'	-> MNEMONIC["jz"]
	;
	
jcxz	
	:	'jcxz' literal_32	-> ^(INSTRUCTION MNEMONIC["jcxz"] ^(OPERANDS ^(OPERAND literal_32)))
	|	'jecxz' literal_32	-> ^(INSTRUCTION MNEMONIC["jecxz"] ^(OPERANDS ^(OPERAND literal_32)))
	;
	
lar
	:	'lar' reg16 ',' regmem_16	-> ^(INSTRUCTION MNEMONIC["lar"] ^(OPERANDS ^(OPERAND reg16) ^(OPERAND regmem_16)))
	|	'lar' reg32 ',' regmem_32	-> ^(INSTRUCTION MNEMONIC["lar"] ^(OPERANDS ^(OPERAND reg32) ^(OPERAND regmem_32)))
	;
	
lds
	:	'lds' reg32 ',' mem32		-> ^(INSTRUCTION MNEMONIC["lds"] ^(OPERANDS ^(OPERAND reg32) ^(OPERAND mem32)))
	;
	
lea
	:	'lea' reg16 ',' mem32		-> ^(INSTRUCTION MNEMONIC["lea"] ^(OPERANDS ^(OPERAND reg16) ^(OPERAND mem32)))
	|	'lea' reg32 ',' mem32		-> ^(INSTRUCTION MNEMONIC["lea"] ^(OPERANDS ^(OPERAND reg32) ^(OPERAND mem32)))
	;
	
les
	:	'les' reg32 ',' mem32		-> ^(INSTRUCTION MNEMONIC["les"] ^(OPERANDS ^(OPERAND reg32) ^(OPERAND mem32)))
	;
	
lfs
	:	'lfs' reg32 ',' mem32		-> ^(INSTRUCTION MNEMONIC["lfs"] ^(OPERANDS ^(OPERAND reg32) ^(OPERAND mem32)))
	;
	
lgs
	:	'lgs' reg32 ',' mem32		-> ^(INSTRUCTION MNEMONIC["lgs"] ^(OPERANDS ^(OPERAND reg32) ^(OPERAND mem32)))
	;
	
loop_instructions
	:	loop_mnemonic literal_32	-> ^(INSTRUCTION loop_mnemonic ^(OPERANDS ^(OPERAND literal_32)))
	;

loop_mnemonic
	:	'loop'		-> MNEMONIC["loop"]
	|	'loope'		-> MNEMONIC["loope"]
	|	'loopz'		-> MNEMONIC["loopz"]
	|	'loopne'	-> MNEMONIC["loopne"]
	|	'loopnz'	-> MNEMONIC["loopnz"]
	;
	
mov_ex_instructions
	:	mov_ex_mnemonic reg16 ',' regmem_8	-> ^(INSTRUCTION mov_ex_mnemonic ^(OPERANDS ^(OPERAND reg16) ^(OPERANDS regmem_8)))
	|	mov_ex_mnemonic reg32 ',' regmem_8	-> ^(INSTRUCTION mov_ex_mnemonic ^(OPERANDS ^(OPERAND reg32) ^(OPERANDS regmem_8)))
	|	mov_ex_mnemonic reg32 ',' regmem_16	-> ^(INSTRUCTION mov_ex_mnemonic ^(OPERANDS ^(OPERAND reg32) ^(OPERANDS regmem_16)))
	;
	
mov_ex_mnemonic
	:	'movsx'	-> MNEMONIC["movsx"]
	|	'movzx'	-> MNEMONIC["movzx"]
	;
	
out
	:	'out' literal_8 ',' accumulator	-> ^(INSTRUCTION MNEMONIC["out"] ^(OPERANDS ^(OPERAND literal_8) ^(OPERAND accumulator)))
	|	'out' 'dx' ',' accumulator	-> ^(INSTRUCTION MNEMONIC["out"] ^(OPERANDS ^(OPERAND REGISTER_16["dx"]) ^(OPERAND accumulator)))
	;
	
push
	:	'push' complex_target_operand_16 -> ^(INSTRUCTION MNEMONIC["push"] ^(OPERANDS complex_target_operand_16))
	|	'push' complex_source_operand_32 -> ^(INSTRUCTION MNEMONIC["push"] ^(OPERANDS complex_source_operand_32))
	;
	
rotate_instructions
	:	rotate_mnemonic regmem ',' literal_8	-> rotate_mnemonic ^(OPERANDS ^(OPERAND regmem) ^(OPERAND literal_8))
	|	rotate_mnemonic regmem ',' 'cl'		-> rotate_mnemonic ^(OPERANDS ^(OPERAND regmem) ^(OPERAND REGISTER_8["cl"]))
	;
	
rotate_mnemonic
	:	'rcl'		-> MNEMONIC["rcl"]
	|	'rcr'		-> MNEMONIC["rcr"]
	|	'rol'		-> MNEMONIC["rol"]
	|	'ror'		-> MNEMONIC["ror"]
	|	'sal'		-> MNEMONIC["sal"]
	|	'sar'		-> MNEMONIC["sar"]
	|	'shl'		-> MNEMONIC["shl"]
	|	'shr'		-> MNEMONIC["shr"]
	;
	
string_instructions
	:	rep_instructions
	|	repe_instructions
	;
	
rep_instructions
	:	'rep' rep_instruction_mnemonics -> ^(PREFIX["rep"] rep_instruction_mnemonics)
	;
	
repe_instructions
	:	'repe' repe_instruction_mnemonics -> ^(PREFIX["repe"] repe_instruction_mnemonics)
	|	'repne' repe_instruction_mnemonics -> ^(PREFIX["repne"] repe_instruction_mnemonics)
	;
	
rep_instruction_mnemonics
	:	movs_mnemonics
	|	lods_mnemonics
	|	stos_mnemonics
	;
	
movs_mnemonics
	:	'movsb'		-> MNEMONIC["movsb"]
	|	'movsw'		-> MNEMONIC["movsw"]
	|	'movsd'		-> MNEMONIC["movsd"]
	;
	
lods_mnemonics
	:	'lodsb'		-> MNEMONIC["lodsb"]
	|	'lodsw'		-> MNEMONIC["lodsw"]
	|	'lodsd'		-> MNEMONIC["lodsd"]
	;
	
stos_mnemonics
	:	'stosb'
	|	'stosw'
	|	'stosd'
	;
	
repe_instruction_mnemonics
	:	cmps_mnemonics
	|	scas_mnemonics
	;
	
cmps_mnemonics
	:	'cmpsb'		-> MNEMONIC["cmpsb"]
	|	'cmpsw'		-> MNEMONIC["cmpsw"]
	|	'cmpsd'		-> MNEMONIC["cmpsd"]
	;
	
scas_mnemonics
	:	'scasb'		-> MNEMONIC["scasb"]
	|	'scasw'		-> MNEMONIC["scasb"]
	|	'scasd'		-> MNEMONIC["scasb"]
	;
	
return_instructions
	:	return_mnemonic literal_16?	-> return_mnemonic ^(OPERANDS ^(OPERAND literal_16))
	;
	
return_mnemonic
	:	'ret'		-> MNEMONIC["ret"]
	|	'retn'		-> MNEMONIC["retn"]
	|	'retf'		-> MNEMONIC["retf"]
	;
	
set_instructions
	:	set_mnemonic reg8		-> set_mnemonic ^(OPERANDS ^(OPERAND reg8))
	|	set_mnemonic mem8		-> set_mnemonic ^(OPERANDS ^(OPERAND mem8))
	;
	
set_mnemonic
	:	'setae'		-> MNEMONIC["setae"]
	|	'setnb'		-> MNEMONIC["setnb"]
	|	'setb'		-> MNEMONIC["setb"]
	|	'setnae'	-> MNEMONIC["setnae"]
	|	'setbe'		-> MNEMONIC["setbe"]
	|	'setna'		-> MNEMONIC["setna"]
	|	'sete'		-> MNEMONIC["sete"]
	|	'setz'		-> MNEMONIC["setz"]
	|	'setne'		-> MNEMONIC["setne"]
	|	'setnz'		-> MNEMONIC["setnz"]
	|	'setl'		-> MNEMONIC["setl"]
	|	'setnge'	-> MNEMONIC["setnge"]
	|	'setge'		-> MNEMONIC["setge"]
	|	'setnl'		-> MNEMONIC["setnl"]
	|	'setle'		-> MNEMONIC["setle"]
	|	'setng'		-> MNEMONIC["setng"]
	|	'setg'		-> MNEMONIC["setg"]
	|	'setnle'	-> MNEMONIC["setnle"]
	|	'sets'		-> MNEMONIC["sets"]
	|	'setns'		-> MNEMONIC["setns"]
	|	'setc'		-> MNEMONIC["setc"]
	|	'setnc'		-> MNEMONIC["setnc"]
	|	'seto'		-> MNEMONIC["seto"]
	|	'setno'		-> MNEMONIC["setno"]
	|	'setp'		-> MNEMONIC["setp"]
	|	'setpe'		-> MNEMONIC["setpe"]
	|	'setnp'		-> MNEMONIC["setnp"]
	|	'setpo'		-> MNEMONIC["setpo"]
	;
	
double_shift_instructions
	:	double_shift_mnemonic regmem_16 ',' reg16 ',' double_shift_third_operand
			-> double_shift_mnemonic ^(OPERANDS ^(OPERAND regmem_16) ^(OPERAND reg16) ^(OPERAND double_shift_third_operand))
	|	double_shift_mnemonic regmem_32 ',' reg32 ',' double_shift_third_operand
			-> double_shift_mnemonic ^(OPERANDS ^(OPERAND regmem_32) ^(OPERAND reg32) ^(OPERAND double_shift_third_operand))
	;
	
double_shift_mnemonic
	:	'shrd'
	|	'shld'
	;
	
double_shift_third_operand
	:	literal_8
	|	'cl'
	;
