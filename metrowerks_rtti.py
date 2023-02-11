#TODO write a description for this script
#@author Swyter <swyterzone+ghidra@gmail.com>
#@category Games
#@keybinding Ctrl + Alt + 1
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
while True:
	p_addr_int = getUInt(addr)
	p_addr = currentProgram.getAddressFactory().getAddress("%x" % (p_addr_int))
	p_addr_block = currentProgram.getMemory().getBlock(p_addr)
	print(i, "%x" % (p_addr_int), p_addr, p_addr_block, p_addr_block and p_addr_block.getPermissions())

	# swy: the first entry of the vtable is the RTTI pointer (or NULL when none)
	#      the second one seems to be NULL, and the third one is the third one the destructor
	#      any functions after that are optional
	if i == 0 and p_addr and p_addr_int != 0:
		def fill_out_rtti_at(p_rtti_addr, level = 0):
			def print_indent(args):
				args = ("--" * level) + args
				print(args)
			print_indent("[i] Scanning RTTI at %x" % addressToInt(p_rtti_addr))

			rtti_str_addr = intToAddress(getUInt(p_rtti_addr))
			rtti_hie_addr = intToAddress(getUInt(p_rtti_addr.add(4)))
			clearListing(p_rtti_addr, p_rtti_addr.add(4 + 4))
			createData(p_rtti_addr,        dt);
			createData(p_rtti_addr.add(4), dt);

			if addressToInt(rtti_str_addr) != 0:
				rtti_str_addr_tmp = rtti_str_addr; j = 32
				while getUInt(rtti_str_addr_tmp) != 0 or j > 0:
					clearListing(rtti_str_addr_tmp)
					rtti_str_addr_tmp = rtti_str_addr_tmp.add(1); j -= 1

				createAsciiString(rtti_str_addr)
				print_indent("[i] Found RTTI name: %s" % getDataAt(rtti_str_addr).getValue())
			else:
				print_indent("[i] Empty RTTI name")

			if addressToInt(rtti_hie_addr) != 0:
				print_indent("[i] Found RTTI hierarchy at %x" % addressToInt(rtti_hie_addr))

				rtti_hie_addr_tmp = rtti_hie_addr
				while getUInt(rtti_hie_addr_tmp) != 0:
					clearListing(rtti_hie_addr_tmp, rtti_hie_addr_tmp.add(4 + 4))
					createData(rtti_hie_addr_tmp,        dt);
					createData(rtti_hie_addr_tmp.add(4), dt);

					fill_out_rtti_at(intToAddress(getUInt(rtti_hie_addr_tmp)), level + 1)
					rtti_hie_addr_tmp = rtti_hie_addr_tmp.add(4 + 4)
			else:
				print_indent("[i] Empty RTTI hierarchy")

		fill_out_rtti_at(p_addr)
			
	if i >= 2 and not p_addr_block and not p_addr_int == 0:
		print("[!] pointer points somewhere outside the valid memory range, not a pointer, bailing out...")
		break;
	if i >= 2 and p_addr_block and not p_addr_block.isExecute() and not p_addr_int == 0:
		print("[!] pointer points to non-executable memory; not a function, bailing out...")
		break;

	clearListing(addr)
	createData(addr, dt)
	addr = addr.add(4); i+=1

	if i >= 2 and getUInt(addr) == 0 and getUInt(addr.add(4)) == 0:
		print("[!] too many upcoming NULL fields, bailing out...")
		break