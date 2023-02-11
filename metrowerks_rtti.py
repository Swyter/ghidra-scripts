#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

dt = getDataTypes("pointer")[0]
addr = currentAddress;

clearListing(addr, addr.add(4 + 4))
createData(addr, dt);
createData(addr.add(4), dt);
