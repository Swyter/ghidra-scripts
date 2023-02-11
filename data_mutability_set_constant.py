#Allows you to quickly set the data/string at the selected address as constant, to show the string value in the decompilation.
#@author Swyter <swyterzone+ghidra@gmail.com>
#@category Data
#@keybinding Ctrl K
#@menupath 
#@toolbar 

from ghidra.program.model.data import MutabilitySettingsDefinition

# swy: thanks to kotcrab for ghidra-allegrex and this example, otherwise I'd still be lost in the rat's nest of Java uglyness:
#      https://programtalk.com/java-more-examples/ghidra.program.model.data.MutabilitySettingsDefinition.CONSTANT/

mutab = getDataAt(currentAddress).getLong(MutabilitySettingsDefinition.MUTABILITY)

if mutab:
	print("[i] Current mutability setting is %u; setting %#x to constant " % (mutab, int(currentAddress.toString(), 16)))

getDataAt(currentAddress).setLong(
	MutabilitySettingsDefinition.MUTABILITY, MutabilitySettingsDefinition.CONSTANT
)