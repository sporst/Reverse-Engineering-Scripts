This script collects exported functions from Windows DLL files and matches
them with imported functions from various directories.

I used this script to figure out what Windows API functions are pretty much
never used and can therefore be abused for anti-emulation trickery. Turns
out a whole lot of API functions are never used.