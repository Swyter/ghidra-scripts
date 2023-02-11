#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

dt = getDataTypes("pointer")[0]
addr = currentAddress;
i = 0
while getInt(addr) != 0 or addr <= currentAddress.add(4 + 4):
	clearListing(addr, addr.add(4))
	createData(addr, dt);
	addr = addr.add(4); i+=1
	print(addr, i)
