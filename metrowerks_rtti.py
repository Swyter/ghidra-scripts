#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


'''
>>> currentProgram.getMemory().getBlock(currentProgram.getAddressFactory().getAddress("0x8080b600")).isExecute()
False
>>> currentProgram.getMemory().getBlock(currentProgram.getAddressFactory().getAddress("0x80799500")).isExecute()
True
'''

# https://github.com/ghidraninja/ghidra_scripts/blob/master/golang_renamer.py
addressFactory = currentProgram.getAddressFactory()

def addressToInt(ghidra_addr):
    return int(ghidra_addr.toString(), 16)

def intToAddress(addr):
    return addressFactory.getAddress("%x" % addr)

blocks = currentProgram.getMemory().getBlocks()
#for block in blocks:
#	print("Name: {}, Size: {}".format(block.getName(), block.getSize()))

# https://github.com/NationalSecurityAgency/ghidra/issues/1969#issuecomment-1221655969
def getUByte(address):  return getByte(address)  & 0xFF
def getUShort(address): return getShort(address) & 0xFFFF
def getUInt(address):   return getInt(address)   & 0xFFFFFFFF
def getULong(address):  return getLong(address)  & 0xFFFFFFFFFFFFFFFF

#TODO Add User Code Here

dt = getDataTypes("pointer")[0]
addr = currentAddress;
i = 0
while getUInt(addr) != 0 or addr <= currentAddress.add(4 + 4):
	p_addr_int = getUInt(addr)
	p_addr = currentProgram.getAddressFactory().getAddress("%x" % (p_addr_int))
	p_addr_block = currentProgram.getMemory().getBlock(p_addr)
	print(i, hex(p_addr_int), p_addr, p_addr_block, p_addr_block and p_addr_block.getPermissions())

	# swy: the first entry of the vtable is the RTTI pointer (or NULL when none)
	#      the second one seems to be NULL, and the third one is the third one the destructor
	#      any functions after that are optional
 	if i == 0 and p_addr:
		rtti_str_addr = intToAddress(getUInt(p_addr))
		clearListing(p_addr, p_addr.add(4))
		createData(p_addr,        dt);
		createData(p_addr.add(4), dt);

		#createAsciiString(rtti_str_addr)
		print("Found RTTI name: ", getDataAt(rtti_str_addr).getValue())
	if i >= 2 and (p_addr_int == 0 or not p_addr_block):
		break;
	if i >= 2 and not p_addr_block.isExecute():
		break;

	clearListing(addr, addr.add(4))
	createData(addr, dt);
	addr = addr.add(4); i+=1
	print(addr, i)
