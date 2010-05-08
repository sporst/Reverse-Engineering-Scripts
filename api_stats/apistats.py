import os
import sys
import pefile

from os.path import join, getsize

# Directories where the PE files that provide the exported functions are located.
dll_dirs = ['C:/windows', 'C:/windows/system32']

# Valid extensions of PE files with export directories
dll_extensions = [ 'dll' ]

# Directories where the PE files that import functions are located.
# If the second tuple-member is True, this directory is traversed recursively.
input_dirs = [('C:\program files', True), ('C:\windows', False), ('C:\windows\system32', False)]

# Valid extensions of PE files which import functions
input_extensions = [ 'exe', 'dll' ]

verbose_mode = True

def get_name(symbol):
	"""
	Takes an entry of an import or export directory and creates a standardized
	name for that entry.
	"""
	if symbol.name is None:
		return "ord_%d" % symbol.ordinal
	else:
		return symbol.name

def file_qualifies(filename, valid_extensions):
	"""
	Checks whether a file ends with one of the file extensions
	from the valid_extensions argument.
	"""
	for extension in valid_extensions:
		if filename.endswith(extension):
			return True
	
	return False

def load_export_dir(pe):
	"""
	Loads the export directory of a PE file.
	"""
	export_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
	return pe.parse_export_directory(export_directory.VirtualAddress, export_directory.Size)

def load_import_dir(pe):
	"""
	Loads the import directory of a PE file.
	"""
	import_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
	return pe.parse_import_directory(import_directory.VirtualAddress, import_directory.Size)

def process_export_dir(filename, exported, ordinals):
	"""
	Loads the export directory of a given file and stores the information
	from the export directory in the exported and ordinals arguments.
	"""
	if verbose_mode:
		print "Loading export directory of %s" % filename
	
	try:
		exp_dir = load_export_dir(pefile.PE(filename, fast_load=True))
		
		if exp_dir is not None:
			# Initially each exported function is called 0 times
			exported[file.lower()] = dict([(get_name(symbol), 0) for symbol in exp_dir.symbols])
			
			# Create a function ordinal => standardized function name mapping
			ordinals[file.lower()] = dict([(symbol.ordinal, get_name(symbol)) for symbol in exp_dir.symbols])
		else:
			if verbose_mode:
				print "Skipping: File has no export directory"
		
	except pefile.PEFormatError:
		if verbose_mode:
			print "Skipping: File could not be read (probably a 16bit file)"
	
def process_import_dir(filename, exported, ordinals):
	"""
	Loads the import directory of a given file and stores the information
	from the import directory in the exported argument.
	"""
	if verbose_mode:
		print "Loading import directory of %s" % filename
			
	try:
		imp_dir = load_import_dir(pefile.PE(filename, fast_load=True))
		
		for entry in imp_dir:
			lower_dll = entry.dll.lower()
		
			if exported.has_key(lower_dll):
			
				export_map = exported[lower_dll]
				ordinals_map = ordinals[lower_dll]
				
				for imp in entry.imports:
					std_name = get_name(imp)
				
					if export_map.has_key(std_name):
						# The function was exported and imported by name
						export_map[std_name] = export_map[std_name] + 1
					elif ordinals_map.has_key(imp.ordinal) and export_map.has_key(ordinals_map[imp.ordinal]):
						# The function was exported by name but imported by ordinal
						export_map[ordinals_map[imp.ordinal]] = export_map[ordinals_map[imp.ordinal]] + 1
					else:
						# We do not know the imported function, because something went wrong.
						if verbose_mode:
							print "Warning: File tries to import unknown DLL function %s from DLL file %s" % (get_name(imp), entry.dll)
			else:
				if verbose_mode:
					print "Warning: File tries to load from unknown library file %s" % entry.dll
	except pefile.PEFormatError:
		if verbose_mode:
			print "Skipping: File could not be read (probably a 16bit file)"
	
exported = { }
ordinals = { }

# Load the export directories of all DLL files in the DLL firectories
for dll_dir in dll_dirs:
	for file in [file for file in os.listdir(dll_dir) if file_qualifies(file.lower(), dll_extensions)]:
		process_export_dir(join(dll_dir, file), exported, ordinals)
		
input_counter = 0

# Load the import directories of all PE files in the input directories
for input_dir, do_walk in input_dirs:

	if do_walk:
		for root, dirs, files in os.walk(input_dir):
			for file in [file for file in files if file_qualifies(file.lower(), input_extensions)]:
				process_import_dir(join(root, file), exported, ordinals)
				input_counter = input_counter + 1
	else:
		for file in [file for file in os.listdir(input_dir) if file_qualifies(file.lower(), input_extensions)]:
			process_import_dir(join(input_dir, file), exported, ordinals)
			input_counter = input_counter + 1

stats_list = []
				
for dll, stats_map in exported.items():
	for function, hits in stats_map.items():
		stats_list.append(("%s/%s" % (dll, function), hits))

stats_list.sort(lambda x, y : y[1] - x[1])

print "Number of library files: %d" % len(exported)
print "Number of input files: %d" % input_counter
print

counter = 1

for name, hits in stats_list:
	print "% 6d. % 6d %s" % (counter, hits, name)
	counter = counter + 1
