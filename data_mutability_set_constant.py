#Allows you to quickly set the data/string at the selected address as constant, to show the string value in the decompilation.
#@author Swyter <swyterzone+ghidra@gmail.com>
#@category Data
#@keybinding Ctrl K
#@menupath 
#@toolbar 

from ghidra.program.model.data import MutabilitySettingsDefinition

# swy: thanks to kotcrab for ghidra-allegrex and this example, otherwise I'd still be lost in the rat's nest of Java uglyness:
#      https://programtalk.com/java-more-examples/ghidra.program.model.data.MutabilitySettingsDefinition.CONSTANT/

# mutab = getDataAt(currentAddress).getLong(MutabilitySettingsDefinition.MUTABILITY)
# 
# if mutab:
# 	print("[i] Current mutability setting is %u; setting %#x to constant " % (mutab, int(currentAddress.toString(), 16)))

# swy: make it work when there's just a single line highlighted,
#      as well as when we've selected multiple of them.
range = [currentAddress, currentAddress.add(1)]

if currentSelection:
	range = [currentSelection.minAddress, currentSelection.maxAddress]

prev_set_data = None; cur_addr = range[0]
while cur_addr < range[1]:
	# print(cur_addr, range[1])
	cur_data = getDataAt(cur_addr)
	cur_addr = cur_addr.add(1)

	if not cur_data:
		continue

	# swy: avoid setting the same object multiple times
	#      as we swim through contiguous ranges
	if prev_set_data == cur_data:
		continue

	cur_data.setLong(
		MutabilitySettingsDefinition.MUTABILITY, MutabilitySettingsDefinition.CONSTANT
	)
	prev_set_data = cur_data
	