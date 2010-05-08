import os
import sys
import pefile
import shutil

from os.path import join, getsize

# Directories where the PE files are located.
# If the second tuple-member is True, this directory is traversed recursively.
input_dirs = [('C:\program files', True), ('C:\windows', False), ('C:\windows\system32', False)]

output_dir = None

# Valid extensions of PE files which import functions
input_extensions = [ 'exe', 'dll' ]

verbose_mode = True

def file_qualifies(filename, valid_extensions):
	"""
	Checks whether a file ends with one of the file extensions
	from the valid_extensions argument.
	"""
	for extension in valid_extensions:
		if filename.endswith(extension):
			return True
	
	return False

def process_file(filename):
	"""
	Copies the file to the output directory if it is a valid PE file.
	"""
	if verbose_mode:
		print "Processing file %s" % filename
			
	try:
		pe = pefile.PE(filename, fast_load=True)
		
		parts = filename.split("\\")
		
		shutil.copyfile(filename, join(output_dir, parts[-1]))
		
	except pefile.PEFormatError:
		if verbose_mode:
			print "Skipping: File could not be read (probably a 16bit file)"
	
if not output_dir:
	print "Error: Please configure the output directory"
	sys.exit(0)
			
for input_dir, do_walk in input_dirs:

	if do_walk:
		for root, dirs, files in os.walk(input_dir):
			for file in [file for file in files if file_qualifies(file.lower(), input_extensions)]:
				process_file(join(root, file))
	else:
		for file in [file for file in os.listdir(input_dir) if file_qualifies(file.lower(), input_extensions)]:
			process_file(join(input_dir, file))
