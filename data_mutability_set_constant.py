#Allows you to quickly set the data/string at the selected address as constant, to show the string value in the decompilation.
#@author Swyter <swyterzone+ghidra>
#@category Data
#@keybinding Ctrl K
#@menupath 
#@toolbar 

from ghidra.program.model.data import MutabilitySettingsDefinition

# swy: thanks to kotcrab for ghidra-allegrex and this example:
#      https://programtalk.com/java-more-examples/ghidra.program.model.data.MutabilitySettingsDefinition.CONSTANT/
getDataAt(currentAddress).getLong(MutabilitySettingsDefinition.MUTABILITY);
getDataAt(currentAddress).setLong(MutabilitySettingsDefinition.MUTABILITY, MutabilitySettingsDefinition.CONSTANT);