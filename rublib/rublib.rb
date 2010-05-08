# RubLib 0.04
#
# Copyright (c) 2006 - 2007 Sebastian Porst (webmaster@the-interweb.com)
# All rights reserved.
#
# This software is licensed under the zlib/libpng License.
# For more details see http://www.opensource.org/licenses/zlib-license.php
# or the readme file in the root directory.

require 'idarub'

# Helps to create x86 specific instruction information
class Helper_X86
	
	# Creates a new Helper_X86 object
	#
	#  The parameter ida is an IdaRub object.
	#
	#  An exception is raised if ida is nil
	def initialize(ida)
	
		raise "Invalid IdaRub object" if ida == nil
		
		@ida = ida
		
	end

	# Returns the mnemonic belonging to a instruction
	def mnemonic(instruction)
		if @ida.ua_mnem(instruction.offset) != nil:
			mnem = @ida.cmd.get_canon_mnem

			byte = instruction.byte
			
			if byte == 0xF3
				if mnem == "scas"
					return "repe " + mnem
				else
					return "rep " + mnem
				end
			elsif byte == 0xF2
					return "repne " + mnem
			elsif byte == 0xF0
					return "lock " + mnem
			else
				return mnem
			end
		else
			return nil
		end
	end
	
end

# Creates helper objects
module CreateHelper

	# Creates a helper object
	#	
	#  The parameter ida is a valid IdaRub object.
	#
	#  Return type: Helper
	def create_helper(ida)
		if ida.inf.procName == "metapc\000I":
			return Helper_X86.new(ida)
		else
			return nil
		end
	end
	
	private :create_helper
end

# This module can be used to read strings from arbitrary offsets
module ReadString
	
	# Reads a string
	#
	#  The parameter ida is a IdaRub object
	#
	#  The parameter offset is the offset where the string should be read from. This parameter
	#  expects a numeric value, not an Offset object.
	#
	#  The parameter type determines the type of the string to read
	#
	#  Return type: String
	def read_string(ida, offset, type)
		@ida.get_ascii_contents(offset, @ida.get_max_ascii_length(offset, type), type)
	end
	
	# Reads an ASCII string from the specified offset
	#
	#  The parameter ida is a IdaRub object
	#
	#  The parameter offset is the offset where the string should be read from. This parameter
	#  expects a numeric value, not an Offset object.
	#
	#  Return type: String
	def read_ascii(ida, offset)
		read_string(ida, offset, 0)
	end
	
	# Reads an Unicode string from the specified offset
	#
	#  The parameter ida is a IdaRub object
	#
	#  The parameter offset is the offset where the string should be read from. This parameter
	#  expects a numeric value, not an Offset object.
	#
	#  Return type: String
	def read_unicode(ida, offset)
		read_string(ida, offset, 3)
	end
	
	private :read_string, :read_ascii, :read_unicode
end

# Contains functions that make sense for offsets and instructions
module Shared
	# Returns the offset flags of the offset
	#
	#  Return type: Bignum
	def flags
		@ida.getFlags(address)
	end
	
	# Determines whether or not the byte has additional anterior or posterior lines?
	#
	#  Return type: Bool
	def extra_lines?
		@ida.hasExtra(flags)
	end
	
	# Determines whether or not there's a comment at the offset
	#
	#  Return type: Bool
	def comment?
		@ida.has_cmt(flags)
	end
	
	# Determines whether or not the offset has references leading to it
	#
	#  Return type: Bool
	def references?
		@ida.hasRef(flags)
	end
	
	# Returns the name of the offset
	#
	#  Return type: String
	def name
		@ida.get_name(@ida.BADADDR, address)
	end
	
	# Changes the name of the offset
	#
	#  The parameter is a string that contains the new name of the offset
	def name=(name)
		@ida.set_name(address, name)
		@ida.refresh_idaview_anyway
	end
	
	# Determines whether or not the offset has a name
	#
	#  Return type: Bool
	def name?
		@ida.has_name(flags)
	end
	
	# Determines whether or not the offset has a dummy name
	#
	#  Return type: Bool
	def dummy_name?
		@ida.has_dummy_name(flags)
	end
	
	# Determines whether or not the offset has an automatically generated name
	#
	#  Return type: Bool
	def auto_name?
		@ida.has_auto_name(flags)
	end
	
	# Determines whether or not the offset has a user defined name
	#
	#  Return type: Bool
	def user_name?
		@ida.has_user_name(flags)
	end
	
	# Determines whether or not the offset has any name at all
	#
	#  Return type: Bool
	def any_name?
		@ida.has_any_name(flags)
	end
	# Determines whether or not a function begins at that offset
	#
	#  Return type: Bool
	def function_start?
		@ida.isFunc(flags)
	end
	
	# Returns the comment found at the offset
	#
	#  Return type: String
	def comment
		@ida.get_cmt(address, false)
	end
	
	# Returns the repeatable comment found at the offset
	#
	#  Return type: String
	def repeatable_comment
		@ida.get_cmt(address, true)
	end
	
	# Returns a list of the anterior or posterior lines that belong to the offset
	#
	#  The parameter type must be either E_PREV (anterior lines) or E_NEXT (posterior lines)
	#
	#  Return type: [String]
	def extra_lines(type)
		lines = []
		cline = 0
		
		while (x = @ida.ExtraGet(address, type + cline)) != nil
			lines << x
			cline += 1
		end
		
		lines
	end
	
	private :extra_lines
	
	# Returns a list of the anterior lines that belong to the offset
	#
	#  Return type: [String]
	def anterior_lines
		extra_lines(@ida.E_PREV)
	end
	
	# Returns a list of the posterior lines that belong to the offset
	#
	#  Return type: [String]
	def posterior_lines
		extra_lines(@ida.E_NEXT)
	end
	
	# Returns a list of all code references to the offset
	#
	#  Return type: [Instruction]
	def crefs_to
		refs = []
		
		curr = @ida.get_first_cref_to(address)
		
		while curr != @ida.BADADDR
			refs << Instruction.new(@ida, curr)
			curr = @ida.get_next_cref_to(address, curr)
		end
		
		refs
	end
	
	# Returns a list of all code references from the offset
	#
	#  Return type: [Instruction]
	def crefs_from
		refs = []
		
		curr = @ida.get_first_cref_from(address)
		
		while curr != @ida.BADADDR
			refs << Instruction.new(@ida, curr)
			curr = @ida.get_next_cref_from(address, curr)
		end
		
		refs
	end
	
	# Returns a list of all data references to the offset
	#
	#  Return type: [Offset]
	def drefs_to
		refs = []
		
		curr = @ida.get_first_dref_to(address)
		
		while curr != @ida.BADADDR
			refs << Offset.new(@ida, curr)
			curr = @ida.get_next_dref_to(address, curr)
		end
		
		refs
	end
	
	# Returns a list of all data references from the offset
	#
	#  Return type: [Offset]
	def drefs_from
		refs = []
		
		curr = @ida.get_first_dref_from(address)
		
		while curr != @ida.BADADDR
			refs << Offset.new(@ida, curr)
			curr = @ida.get_next_dref_from(address, curr)
		end
		
		refs
	end
	
end

# Represents an offset and everything you can do with it
class Offset
	include ReadString
	include CreateHelper
	include Shared
	
	# Numeric value of the offset
	def address
		@offset
	end
	
	# Creates a new Offset object
	#
	#  The parameter ida is an IdaRub object
	#
	#  The parameter offset is a numeric offset
	def initialize(ida, offset)
		@ida = ida
		@offset = offset
		@helper = create_helper(ida)
	end

	# Compares two Offset objects. Two Offset objects are considered equal if they
	# have the same numerical offset.
	#
	#  The parameter rhs is the right-hand side object of the comparison.
	def <=>(rhs)
		@offset <=> rhs.offset
	end
	
	# Returns the next offset. This is primarily used to support offset ranges.
	# I wouldn't use the function explicitly if I were you.
	def succ
		Offset.new(@ida, @offset + 1)
	end
	
	# Determines whether or not the offset is actually visible in IDA
	#
	#  Return type: Bool
	def enabled?
		@ida.isEnabled(@offset)
	end
	
	# Reads an ASCII string from the offset position
	#
	#  Return type: String
	def ascii
		read_ascii(@ida, @offset)
	end
	
	# Reads an Unicode string from the offset position
	#
	#  Return type: String
	def unicode
		read_unicode(@ida, @offset)
	end
	
	# Reads a byte from the offset position
	#
	#  Return type: Fixnum
	def byte
		@ida.get_byte(@offset)
	end
	
	# Sets the byte value at the offset position
	#
	#  The parameter value is the new value of the byte value
	def byte=(value)
		@ida.patch_byte(@offset, value)
		@ida.refresh_idaview_anyway
	end
	
	# Reads a word from the offset position
	#
	#  Return type: String
	def word
		@ida.get_word(@offset)
	end
	
	# Sets the word value at the offset position
	#
	#  The parameter value is the new value of the word value
	def word=(value)
		@ida.patch_word(@offset, value)
		@ida.refresh_idaview_anyway
	end
	
	# Reads a three-byte value from the offset position
	#
	#  Return type: String
	def three_bytes
		@ida.get_3byte(@offset)
	end
	
	# Sets the three-byte value at the offset position
	#
	#  The parameter value is the new value of the three-byte value 
	def word=(value)
		@ida.patch_word(@offset, value)
		@ida.refresh_idaview_anyway
	end
	
	# Reads a dword from the offset position
	#
	#  Return type: Bignum
	def dword
		@ida.get_long(@offset)
	end
	
	# Sets the dword value at the offset position
	#
	#  The parameter value is the new value of the dword value
	def dword=(value)
		@ida.patch_long(@offset, value)
		@ida.refresh_idaview_anyway
	end
	
	# Reads a dword from the offset position
	def qword
		@ida.get_qword(@offset)
	end
	
	# Sets the qword value at the offset position
	#
	#  The parameter value is the new value of the qword value
	def dword=(value)
		@ida.patch_long(@offset, value)
		@ida.refresh_idaview_anyway
	end
	
	# Returns the original byte at the offset position
	#
	#  Return type: Fixnum
	def original_byte
		@ida.get_original_byte(@offset)
	end
	
	# Returns the original word at the offset position
	#
	#  Return type: Fixnum
	def original_word
		@ida.get_original_word(@offset)
	end
	
	# Returns the original dword at the offset position
	#
	#  Return type: Bignum
	def original_dword
		@ida.get_original_long(@offset)
	end
	
	# Determines whether or not the byte at the offset is a head byte
	#
	#  Return type: Bool
	def head?
		@ida.isHead(flags)
	end
	
	# Determines whether or not the byte at the offset is a tail byte
	#
	#  Return type: Bool
	def tail?
		@ida.isTail(flags)
	end
	
	# Determines whether or not the byte at the offset is not a tail byte
	#
	#  Return type: Bool
	def not_tail?
		@ida.isNotTail(flags)
	end
	
	# Determines whether or not the byte at the offset is a code byte
	#
	#  Return type: Bool
	def code?
		@ida.isCode(flags)
	end
	
	# Determines whether or not the byte at the offset is a data byte
	#
	#  Return type: Bool
	def data?
		@ida.isData(flags)
	end
	
	# Determines whether or not the byte at the offset is a unknown byte
	#
	#  Return type: Bool
	def unknown?
		@ida.isUnknown(flags)
	end
	
	# Determines whether or not the byte has a previous instruction that leads to the offset
	#
	#  Return type: Bool
	def flow?
		@ida.isFlow(flags)
	end

	# Converts length bytes from the offset into bytes
	#
	# Note: The data must be undefined before.
	def do_byte(length)
		@ida.doByte(@offset, length)
	end
	
	# Converts length bytes from the offset into words
	#
	# Note: The data must be undefined before.
	def do_word(length)
		@ida.doWord(@offset, length)
	end
	
	# Converts length bytes from the offset into dwords
	#
	# Note: The data must be undefined before.
	def do_dword(length)
		@ida.doDwrd(@offset, length)
	end
	
	# Converts length bytes from the offset into qwords
	#
	# Note: The data must be undefined before.
	def do_qword(length)
		@ida.doQwrd(@offset, length)
	end
	
	# Converts length bytes from the offset into octawords
	#
	# Note: The data must be undefined before.
	def do_oword(length)
		@ida.doOwrd(@offset, length)
	end
	
	# Converts length bytes from the offset into TBytes
	#
	# Note: The data must be undefined before.
	def do_tbyte(length)
		@ida.doTbyt(@offset, length)
	end
	
	# Converts length bytes from the offset into floats
	#
	# Note: The data must be undefined before.
	def do_float(length)
		@ida.doFloat(@offset, length)
	end
	
	# Converts length bytes from the offset into doubles
	#
	# Note: The data must be undefined before.
	def do_double(length)
		@ida.doDouble(@offset, length)
	end
	
	# Converts length bytes from the offset into packed reals
	#
	# Note: The data must be undefined before.
	def do_packed_real(length)
		@ida.doPackReal(@offset, length)
	end
	
	def do_ascii(length)
		@ida.doASCI(@offset, length)
	end
	
	# Converts length bytes from the offset into 3bytes
	#
	# Note: The data must be undefined before.
	def do_three_byte(length)
		@ida.do3byte(@offset, length)
	end
	
	# Determines whether or not the data at the offset is a byte variable
	#
	#  Return type: Bool
	def byte?
		@ida.isByte(flags)
	end
	
	# Determines whether or not the data at the offset is a word variable
	#
	#  Return type: Bool
	def word?
		@ida.isWord(flags)
	end
	
	# Determines whether or not the data at the offset is a dword variable
	#
	#  Return type: Bool
	def dword?
		@ida.isDwrd(flags)
	end
	
	# Determines whether or not the data at the offset is a dword variable
	#
	#  Return type: Bool
	def qword?
		@ida.isQwrd(flags)
	end
	
	# Determines whether or not the data at the offset is an octaword variable
	#
	#  Return type: Bool
	def oword?
		@ida.isOwrd(flags)
	end
	
	# Determines whether or not the data at the offset is a TByte variable
	#
	#  Return type: Bool
	def tbyte?
		@ida.isTbyt(flags)
	end
	
	# Determines whether or not the data at the offset is a float variable
	#
	#  Return type: Bool
	def float?
		@ida.isFloat(flags)
	end
	
	# Determines whether or not the data at the offset is a double variable
	#
	#  Return type: Bool
	def double?
		@ida.isDouble(flags)
	end
	
	# Determines whether or not the data at the offset is a packed real variable
	#
	#  Return type: Bool
	def packed_real?
		@ida.isPackReal(flags)
	end
	
	def ascii?
		@ida.isASCII(flags)
	end
	
	# Determines whether or not the data at the offset is a 3Byte variable
	#
	#  Return type: Bool
	def three_byte?
		@ida.is3byte(flags)
	end
	
	# TODO: get_typeinfo

end

# Represents a disassembled instruction and everything you can do with it
class Instruction
	include Shared
	
#	def <=>(rhs)
#		return @offset <=> rhs.offset
#	end
	
#	def succ
#		return crefs_from[0]
#	end
	
	# Numeric value of the address of the instruction
	def address
		@ea
	end
	
	# Creates a new Instruction offset
	#
	#  The parameter ida is an IdaRub remote object
	#  The parameter ea is the address of the instruction
	def initialize(ida, ea)
		@ida = ida
		@ea = ea
	end

	# Two Instruction objects are equal if they have the same offset
	#
	#  The parameter rhs is the right-hand side Offset object used in the comparison.
	def ==(rhs)
		@ea == rhs[0].address
	end
	
	# Returns the mnemonic (mov, jz, ...)
	#
	#  Return type: String
	def mnemonic
		if @helper == nil
			@ida.ua_mnem(@ea)
			@ida.cmd.get_canon_mnem
		else
			@helper.mnemonic(self)
		end
	end
	
	# Returns the instruction type
	def instruction_type
		@ida.ua_mnem(@ea)
		@ida.cmd.itype
	end
	
	# Returns the size of the instruction
	#
	#  Return type: int
	def instruction_size
		@ida.ua_mnem(@ea)
		@ida.cmd.size
	end
	
	# TODO: This
	def operand(index)
		@ida.ua_mnem(@ea)
		@ida.cmd.Operands.remote_methods
#		@ida.cmd.Operands.type
#		@ida.cmd.Operands.ea
#		@ida.cmd.ir_get_operand(0).to_s
	end
	
	# Returns the disassembled line
	#
	#  Return type: String
	def line
		@ida.tag_remove(unstripped_line)
	end
	
	# Returns the disassembled line including all format information
	#
	#  Return type: String
	def unstripped_line
		@ida.generate_disasm_line(@ea)
	end
	
	# Determines whether or not the instruction is a manual instruction
	#
	#  Return type: Bool
	def manual?
		@ida.is_manual_insn(@ea)
	end
	
	# Returns the manual disassembled line
	#
	#  Return type: String
	def manual_line
		@ida.get_manual_insn(@ea)
	end
	
	# Changes the disassembled to a string value
	#
	#  The parameter line is a string that contains the new value for the line.
	def manual_line=(line)
		@ida.set_manual_insn(@ea, line)
		@ida.refresh_idaview_anyway
	end
	
	# Splits the line into various components
	def split_instruction
		tline = line
		
		tline, comm = tline.split(/; /, 2)

		while (tline.include?("   "))
			tline.gsub!(/   /, "  ")
		end
		
		tline.split(/  /) << comm
	end
	
	# Returns all bytes belonging to the instruction
	#
	#  Return type: [ unsigned int ]
	def bytes
		@ida.get_many_bytes(self[0].address, instruction_size).unpack("C*")
	end
	
	# Returns objects that represent all bytes of the instruction
	#
	#  Return type: [ Object ]
	def byte_objects
		offsets = [ ]
		
		for i in ( 0 ... instruction_size)
			offsets << Offset.new(@ida, self[0].address + i)
		end
		
		return offsets
	end
	
	# Returns one or more bytes from the instruction
	#
	#  The parameter index can be an integer or a range. The type of
	#  this parameter determines the return type of the function.
	#
	#  Return type: Object or [ Object ]
	def [](index)
		if index.kind_of? Range
			return index.map{|i| at(i)}
		end
		
		at(index)
	end
	
	# Returns one byte from the instruction
	#
	#  Return type: Object
	def at(index)
		isize = instruction_size
	
		if index < - isize or index >= isize
			return nil
		end
		
		Offset.new(@ida, address + index % isize)
	end
	
	private :at
	
end

# Represents a function
class Function
	include Enumerable
	
	# Index of the function
	attr_accessor :index
	
	# Resets buffered values
	#
	# Buffered values are: 
	#   - Number of instructions in the function
	def reset
		@inst_num = -1
	end
	
	# Creates a new function object from an IdaRub object and the function id
	#
	#  The parameter ida is an IdaRub remote object
	#
	#  The parameter index is a valid parameter of the function. It must not be negative
	#  and it must be smaller than the number of functions in the file.
	#
	#  An exception is thrown if the constraints of parameter index are broken
	def initialize(ida, index)
		raise "Invalid index" if index < 0 || index >= ida.get_func_qty
	
		@ida = ida
		@index = index
		@func = @ida.getn_func(index)
		@inst_num = -1
	end	
	
	# Returns the disassembled instruction at the given index
	#
	#  The parameter index is the number of the instruction that should be returned.
	#  
	#  This function operates on instructions, not offsets. It is important to remember
	#  that a instruction can be more than one offset large.
	#
	#  Return type: Instruction
	def at(index)
	
		if index != 0
			nrinst = number_of_instructions
	
			if index < - nrinst or index >= nrinst
				return nil
			end
	
			index = index % nrinst
		end
			
		iter = @ida.Func_tail_iterator_t.new(@func)
		ctr = 0
		
		begin 
			start_offset = iter.chunk().startEA
			end_offset = iter.chunk().endEA
			
			for addr in (start_offset ... end_offset)
				
				flags = @ida.getFlags(addr)
				
				if @ida.isHead(flags) and @ida.isCode(flags)
					if ctr == index
						return Instruction.new(@ida, addr)
					else
						ctr = ctr + 1
					end
				end
				
			end
		end while iter.next()
	
		return nil
	end
	
	private :at
	
	# Returns the disassembled instruction at the given index or range
	#
	#  If the parameter index is a number the instruction with the given index
	#  is returned.
	#
	#  If the parameter index is a range a list of instructions that fill into
	#  that range is returned.
	#
	#  Return type: Instruction or [Instruction]
	def [](index)
	
		if index.kind_of? Range
			return index.map{|i| at(i)}
		end
		
		at(index)
	end
		
	# Name of the function
	#
	#  Return type: String
	def name
		@ida.get_func_name(address)
	end
	
	# Sets the name of the function
	# 
	# The parameter value is a string that contains the new name of the function
	def name=(value)
		start.name = value
	end
	
	# Function comment of the function
	#
	#  Return type: String
	def comment
		@ida.get_func_cmt(@func, false)
	end
	
	# Set the function comment of the function
	#
	#  The parameter value is a string that contains the new function comment value.
	def comment=(value)
		@ida.set_func_cmt(@func, value, false)
		@ida.refresh_idaview_anyway
	end
	
	# Determines whether the function contains a given offset
	#
	#  The parameter is the numeric value of the offset to test. It is
	#  possible to pass an Offset object.
	#
	#  Return type: Bool
	def contains_offset?(offset)
		@ida.func_contains(@func, offset)
#		start.offset <= offset && self.end.offset >= offset
	end
	
	# Returns the number of instructions in the function
	def number_of_instructions
	
		if @inst_num != -1
			return @inst_num
		end
	
		iter = @ida.Func_tail_iterator_t.new(@func)
		ctr = 0
		
		begin 
			start_offset = iter.chunk().startEA
			end_offset = iter.chunk().endEA
			
			for addr in (start_offset ... end_offset)
				
				flags = @ida.getFlags(addr)
				
				if @ida.isHead(flags) and @ida.isCode(flags)
					ctr = ctr + 1
				end
				
			end
		end while iter.next()
		
		@inst_num = ctr
		
		return ctr
	end
	
	# Used to iterate over the instructions in the function
	#
	#  Return type: Instruction
	def each
		iter = @ida.Func_tail_iterator_t.new(@func)
		
		begin 
			start_offset = iter.chunk().startEA
			end_offset = iter.chunk().endEA
			
			for addr in (start_offset ... end_offset)
				
				flags = @ida.getFlags(addr)
				
				if @ida.isHead(flags) and @ida.isCode(flags)
					yield Instruction.new(@ida, addr)
				end
				
			end
		end while iter.next()

#		for addr in (start .. self.end)
#			if addr.head? and addr.code?
#				yield Line.new(@ida, addr.offset)
#			end
#		end
	end
	
	# Returns a list of all function chunks that belong to the function
	#
	#   Return type: [ FunctionChunk ]
	def chunks
		iter = @ida.Func_tail_iterator_t.new(@func)
		
		c = [ ]
		
		iter.main()
		
		c << FunctionChunk.new(@ida, iter.chunk())
		
		while iter.next()
			c << FunctionChunk.new(@ida, iter.chunk())
		end
		
		return c
	end
	
	# Returns a list of all instructions in the function.
	#
	#   Return type: [ Instruction ]
	def instructions
	
		inst = [ ]
		
		self.each{|i| inst << i }
		
		return inst
	
	end
	
	# Numeric value of the address of the instruction
	def address
		@func.startEA
	end
	
end

# Represents a function chunk
class FunctionChunk
	include Enumerable
	
	# Resets buffered values
	#
	# Buffered values are: 
	#   - Number of instructions in the chunk
	def reset
		@inst_num = -1
	end
	
	# Creates a new function chunk object.
	#
	#  The parameter ida is an IdaRub remote object
	#  The parameter chunk is an area_t object.
	def initialize(ida, chunk)
		@ida = ida
		@chunk = chunk
		@inst_num = -1
	end
	
	# Returns the first offset of the function chunk
	#
	#  Return type: ea
	def first_offset
		Offset.new(@ida, @chunk.startEA)
	end
	
	# Returns the last offset that belongs to the function chunk
	#
	#  Return type: ea
	def last_offset
		Offset.new(@ida, @chunk.endEA - 1)
	end

	# Returns the number of instructions in the function chunk
	def number_of_instructions
	
		if @inst_num != -1
			return @inst_num
		end
	
		start_offset = address
		end_offset = last_offset.address
		ctr = 0
		
		for addr in (start_offset ... end_offset)
			
			flags = @ida.getFlags(addr)
			
			if @ida.isHead(flags) and @ida.isCode(flags)
				ctr = ctr + 1
			end
			
		end
		
		@inst_num = ctr
		
		return ctr
	end
	
	# Can be used to iterate over all instructions in the chunk
	#
	#  Return type: Instruction
	def each
		for addr in (first_offset.address .. last_offset.address)
		
			flags = @ida.getFlags(addr)
			
			if @ida.isHead(flags) and @ida.isCode(flags)
				yield Instruction.new(@ida, addr)
			end
		end
	end
	
	# Returns the disassembled instruction at the given index
	#
	#  The parameter index is the number of the instruction that should be returned.
	#  
	#  This function operates on instructions, not offsets. It is important to remember
	#  that a instruction can be more than one offset large.
	#
	#  Return type: Instruction
	def at(index)
	
		if index != 0
			nrinst = number_of_instructions
		
			if index < - nrinst or index >= nrinst
				return nil
			end
			
			index = index % nrinst
		end
		
		ctr = 0
		
		start_offset = @chunk.startEA
		end_offset = @chunk.endEA
		
		for addr in (start_offset ... end_offset)
			
			flags = @ida.getFlags(addr)
			
			if @ida.isHead(flags) and @ida.isCode(flags)
				if ctr == index
					return Instruction.new(@ida, addr)
				else
					ctr = ctr + 1
				end
			end
			
		end

		return nil
	end
	
	private :at
	
	# Returns the disassembled instruction at the given index or range
	#
	#  If the parameter index is a number the instruction with the given index
	#  is returned.
	#
	#  If the parameter index is a range a list of instructions that fill into
	#  that range is returned.
	#
	#  If the index parameter is either too small or too large an exception
	#  is thrown.
	#
	#  Return type: Instruction or [Instruction]
	def [](index)
		if index.kind_of? Range
			return index.map{|i| at(i)}
		end
		
		at(index)
	end
	
	# Numeric value of the address of the instruction
	def address
		@chunk.startEA
	end
end

# Represents a segment
class Segment

	# Creates a new Segment object
	#
	#  The parameter ida is an IdaRub remote object
	#  The parameter segment is a segment_t object.
	#
	#  An exception is any of the parameters are nil
	def initialize(ida, segment)
	
		raise "Invalid IdaRub object" if ida == nil
		raise "Invalid segment" if segment == nil
	
		@ida = ida
		@segment = segment
	end
	
	# Returns the address of the segment start
	#
	#  Return type: Offset
	def first_offset
		Offset.new(@ida, @segment.startEA)
	end
	
	# Returns the address of the segment end
	#
	#  Return type: Offset
	def last_offset
		Offset.new(@ida, @segment.endEA - 1)
	end
	
	# Returns the name of the segment
	#
	#  Return type: String
	def name
		# True name or untrue name here?
		@ida.get_true_segm_name(@segment)
	end
	
	# Returns the class of the segment
	#
	#  Return type: String
	def class
		@ida.get_segm_class(@segment)
	end
	
	# Returns the base of the segment
	#
	#  Return type: int
	def base
		@ida.get_segm_base(@segment)
	end
	
	# Returns the segment comment
	#
	#  Return type: String
	def comment
		@ida.get_segment_cmt(@segment, false)
	end
	
	# Changes the segment comment
	#
	#  The parameter cmt is a String containing the new segment comment.
	def comment=(cmt)
		@ida.set_segment_cmt(@segment, cmt, false)
		@ida.refresh_idaview_anyway
	end
	
	# Returns the repeatable segment comment
	#
	#  Return type: String
	def repeatable_comment
		@ida.get_segment_cmt(@segment, true)
	end
	
	# Changes the repeatable segment comment
	#
	#  The parameter cmt is a String containing the new repeatable segment comment.
	def repeatable_comment=(cmt)
		@ida.set_segment_cmt(@segment, cmt, true)
		@ida.refresh_idaview_anyway
	end
	
	# Removes the segment
	#
	#  The parameter flags is a combination of SEGDEL_PERM, SEGDEL_KEEP and SEGDEL_SILENT. SEGDEL_PERM and SEGDEL_SILENT
	#  are used by default.
	def remove(flags = 5)
		@ida.del_segm(start, flags)
		@ida.refresh_idaview_anyway
	end
	
end

# Represents a list of all segments in the current file
class SegmentList

	include Enumerable
	
	# Creates a new segment
	#
	#  The parameter ida is a valid IdaRub object.
	#
	#  An exception is thrown if ida is nil
	def initialize(ida)
		
		raise "Invalid IdaRub object" if ida == nil
	
		@ida = ida
	end
	
	# Returns the number of segments in the file
	#
	#  Return type: int
	def number_of_segments
		@ida.get_segm_qty()
	end
	
	# Returns a Segment object identified by an ID
	#
	#  The parameter index is the index of the segment
	#
	#  Return type: Segment
	def [](index)
		Segment.new(@ida, @ida.getnseg(index))
	end
	
	# Returns a Segment object identified by an offset
	#
	#  The parameter offset is the offset of the segment
	#
	#  Return type: Segment
	def segment_by_offset(offset)
		Segment.new(@ida, @ida.getseg(offset))
	end
	
	# Adds a new segment to the file
	#
	#  The parameter para is the segment base paragraph
	#  The parameter startea is the start address of the segment
	#  The parameter endea is the end address of the segment
	#  The parameter name is the name of the segment
	#  The parameter sclass is the class of the segment.
	def add(para, startea, endea, name, sclass)
		@ida.add_segm(para, startea, endea, name, sclass)
		@ida.refresh_idaview_anyway
	end
	
	# Used to iterate over all segments in the file.
	def each
		number_of_segments.times{|i| yield self[i]}
	end
	
end

# Represents an IDA file
class IdaFile

	include Enumerable
	
	# Creates a new IdaFile
	#
	#  The parameter ida is a valid IdaRub remote object
	def initialize(ida)
	
		raise "Error: Invalid IdaRub object" if ida == nil
	
		@ida = ida
	end
	
	# Returns the function at the given index or the functions at the given range
	#
	#  The parameter index can be a number or a range.
	#  
	#  If the parameter is a number it is the index of the function. If this index is negative or larger
	#  than the number of functions in the file it'll be taken modulo the number of functions
	#  in the file. That way you can easily access the last function of a file using file[-1]
	#
	#  If the parameter is a range, function objects for the functions in this range are returned. The modulo
	#  operation still holds true.
	#
	#  Return type: Function or [Function]
	def [](index)
		if index.kind_of? Range
			index.map{|i| at(i)}
		else
			at(index)
		end
	end
	
	# Helper function for the [] operator
	def at(index)
	
		num_func = number_of_functions
		
		if index < -number_of_functions or index >= number_of_functions
			return nil
		end
		
		Function.new(@ida, index % number_of_functions)
	end
	
	private :at
	
	# Returns the file name of the disassembled file
	#
	#  Return type: String
	def name
		@ida.get_root_filename
	end
	
	# Returns the path of the disassembled file
	#
	#  Return type: String
	def path
		@ida.get_input_file_path
	end
	
	# Offset of the currently selected instruction
	#
	#  Return type: Offset
	def screen_ea
		Offset.new(@ida, @ida.get_screen_ea)
	end

	# Number of functions in the file
	#
	#  Return type: Fixnum
	def number_of_functions
		@ida.get_func_qty
	end
	
	# Returns a function identified by name
	#
	#  The parameter function_name is a string that contains a function name.
	#
	#  Return type: Function or nil
	def function_by_name(function_name)
	
		self.each { |function| return function if function.name == function_name }
		
		return nil
	end
	
	# Calculates the CRC32 of the input file
	#
	#  Return type: Bignum
	def crc32
		@ida.retrieve_input_file_crc32
	end
	
	# TODO: this
#	def md5
#		@ida.retrieve_input_file_md5
#	end

	# Returns the processor name used in the current file
	#
	#  Return type: String
	def processor_name
		@ida.inf.procName
	end
	
	# Returns the filetype of the file
	#
	#  Return type: filetype_t
	def filetype
		@ida.inf.filetype
	end
	
	# Returns the start offset of the file
	#
	#  Return type: Offset
	def start_offset
		Offset.new(@ida, @ida.inf.beginEA)
	end

	# Returns the first offset of the file
	#
	#  Return type: Offset
	def first_offset
		Offset.new(@ida, @ida.inf.minEA)
	end

	# Returns the last offset of the file
	#
	#  Return type: Offset
	def last_offset
		Offset.new(@ida, @ida.inf.maxEA - 1)
	end

	# Returns a list of all segments of the file
	#
	#  Return type: SegmentList
	def segments
		SegmentList.new(@ida)
	end
	
	# Returns the number of entry points in the file
	#
	#  Return type: Fixnum
	def number_of_entry_points
		@ida.get_entry_qty()
	end

	# Returns a list of entrypoints
	#
	#  Return type: [Offset]
	def entry_points
		(0 ... number_of_entry_points).map{|i| Offset.new(@ida, @ida.get_entry(@ida.get_entry_ordinal(i)))}
	end
	
	# Iterates through all functions in the file
	#
	#  Return type: Function
	def each
		number_of_functions.times {|i| yield Function.new(@ida, i)}
	end
	
	# String list of the file
	#
	#  Return type: StringList
	def string_list
		StringList.new(@ida)
	end
	
	# Returns the helper object that provides processor-specific information about instructions
	def helper
		@helper
	end
end

# Represents strings in the string list
class IdaString
	include ReadString

	# Creates a new StringList object from an IdaRub object and the string index
	#
	#  The parameter ida is an IdaRub object
	#
	#  The parameter index is the index of the string in the string list
	def initialize(ida, index)
		@ida = ida
		@index = index
		
		@str = @ida.String_info_t.new
		@ida.get_strlist_item(@index, @str)
	end
	
	# Numeric value of the address of the instruction
	def address
		@str.ea
	end
	
	# Offset of the string
	#
	#  Return type: Offset
	def offset
		Offset.new(@ida, @str.ea)
	end
	
	# Type of the string
	#
	#  Return type: Fixnum
	def type
		@str.type
	end
	
	# The value of the string
	#
	#  Return type: String
	def value
		return read_ascii(@ida, offset.address) if type == 0
		return read_unicode(@ida, offset.address) if type == 3

		raise "Invalid string type"
	end
	
end

# Represents the string list of a disassembled file
class StringList

	include Enumerable

	# Creates a new StringList object from an IdaRub object
	#
	#  The parameter ida is a IdaRub remote object
	def initialize(ida)
		@ida = ida
	end
	
	def at(index)
		len = number_of_strings
		
		if index < - len or index >= len
			return nil
		end
		
		IdaString.new(@ida, index % len)
	end
	
	private :at
	
	# Returns the string with the given index. 
	#
	#  The parameter index is the index of the string to read.
	#
	#  Return type: IdaString
	def[](index)
		if index.kind_of? Range
			return index.map{|i| at(i)}
		end
		
		at(index)
	end
	
	# Returns the number of strings in the list
	#
	#  Return type: Fixnum
	def number_of_strings
		@ida.get_strlist_qty()
	end
	
	# Iterates over all strings in the list
	#
	#  Return type: IdaString
	def each
		number_of_strings.times{|i| yield IdaString.new(@ida, i) }
	end
end