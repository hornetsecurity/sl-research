#Run with currentAddress == emotet_get_func function.
#@author Hornetsecurity Security Lab
#@category Emotet
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.data import DataType
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.data import Enum
from ghidra.program.model.data import EnumDataType
from ghidra.program.model.symbol import SourceType

func_names = open(askFile('Function List','OK').getPath(),'r').read().split()

funcs = {}

def init_funcs(addr):
	inst = getInstructionAt(addr)
	# TODO: use pcode and reaching definition
	while not inst.toString().startswith('XOR EAX,0x'):
		inst = inst.getNext()
	xor_value = inst.getScalar(1).getValue()

	for func_name in func_names:
		accu = 0
		for c in func_name:
			tmp = ord(c)
			accu = (tmp + accu * 0x1003f)%2**32;
		hash = accu ^ xor_value
		funcs.update({hash:func_name})


def get_func(hash):
	func_name = funcs.get(hash)
	if func_name is None:
		print "ERROR: Could not find function name for hash " + hex(hash)
		return "Unknown"
	return func_name

init_funcs(currentAddress)

enum = EnumDataType('emotet_func_hash',4)
for func in funcs:
	enum.add(funcs[func], func)
dtm = currentProgram.getDataTypeManager()
dtm.addDataType(enum,None)

refs = getReferencesTo(currentAddress)

for r in refs:
	callee = r.getFromAddress()
	inst = inst_ = getInstructionAt(callee)
	i = 0
	# TODO: use pcode and reaching definition
	while not inst.toString().startswith('MOV EDX,0x'):
		inst = getInstructionBefore(inst)
		i += 1
		if i > 10:
			break
	if inst.toString().startswith('MOV EDX,0x'):
		try:
			func_name = get_func(inst.getScalar(1).getValue())
		except Exception as e:
			print(str(callee) + " FAIL 1")
		else:
			inst_.setComment(CodeUnit.EOL_COMMENT,func_name)
			createBookmark(callee, "emotet func", func_name)
			print str(callee)+" "+str(func_name)
			# fixup the function name with the imported functions
			f = getFunctionContaining(callee)
			s = f.getSymbol()
			name = s.getName().replace('FUN_','emo_')
			if len(name) + 1 + len(func_name) <= 2000:
				n = name.split('_')
				n.append(func_name)
				name = '_'.join(n[:2]) + '_' + '_'.join(list(set(n[2:])))
			s.setName(name,SourceType.USER_DEFINED)
	else:
		print(str(callee) + " FAIL 2")


