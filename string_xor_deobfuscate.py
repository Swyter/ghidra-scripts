# Quickly uncloak or reveal C style-strings XORed against the same (single) byte. For strings where it also affects the NULL terminator, [0^key = key] revealing the trick.
# To use, select the whole block from the known end and press Shift+D. Done.
# If you aren't sure, or it looks wrong, you can easily try and undo, then narrow down the start position by trying again selecting a bigger block until you find the
# actual beginning. As long as you nail down the actual end part (with the encoded NULL terminator) the script should still work fine and the text should appear.
#@author Swyter <swyterzone+ghidra@gmail.com>
#@category Data
#@keybinding Shift D
#@menupath Edit.Deobfuscate XORed string data
#@toolbar 

from ghidra.program.model.data import MutabilitySettingsDefinition

# https://github.com/NationalSecurityAgency/ghidra/issues/1969#issuecomment-1221655969
def getUByte(address):  return getByte(address)  & 0xFF
def getUShort(address): return getShort(address) & 0xFFFF
def getUInt(address):   return getInt(address)   & 0xFFFFFFFF
def getULong(address):  return getLong(address)  & 0xFFFFFFFFFFFFFFFF

# swy: make it work when there's just a single line highlighted,
#      as well as when we've selected multiple of them.
range = {"first": currentAddress, "last": currentAddress}

# swy: when currentSelection is None, currentAddress is filled out, and vice versa.
if currentSelection:
	range = {"first": currentSelection.minAddress, "last": currentSelection.maxAddress}

# swy: get the key, in our case it's the last selected byte
cur_addr = range["last"]; xored_null_byte = getUByte(cur_addr)
print(cur_addr, "xor byte/key: %x" % xored_null_byte)

# swy: go backwards and decode the ASCII data by XORing against the key/NULL terminator, write it replacing memory
while cur_addr >= range["first"]:
	obfuscated_byte = getUByte(cur_addr)
	setByte(cur_addr, obfuscated_byte ^ xored_null_byte)

	print(cur_addr, range["last"], "%x" % obfuscated_byte, "%c" % (obfuscated_byte ^ xored_null_byte))
	cur_addr = cur_addr.subtract(1); 

# swy: clear any previous data types and define the whole thing as a C string
clearListing(range["first"], range["last"].add(0))
dt = getDataTypes("TerminatedCString")[0]
createData(range["first"], dt)