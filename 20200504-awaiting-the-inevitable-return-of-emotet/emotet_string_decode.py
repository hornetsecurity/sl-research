#Run with currentAddress == emotet_string_decode() function (or any other function
#that gets an Emotet XOR encoded string in ECX parameter).
#@author Hornetsecurity Security Lab
#@category Emotet
#@keybinding 
#@menupath
#@toolbar

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

def decrypt(string_start):
	for b in getBookmarks(string_start.add(8)):
		if b.getCategory() == 'emotet string':
			return b.getComment()
	xor_key = getBytes(string_start,4)
	len_bytes = getBytes(string_start.add(4),4)
	
	str_len = 0
	for i in range(4):
		str_len |= ((xor_key[i]) ^ (len_bytes[i]))<<(i*8)
	
	string = ""
	for i in range(str_len+1):
		p = string_start.add(8).add(i)
		if i == str_len:
			setByte(p,0)
			break
		b = getBytes(p,1)[0] ^ xor_key[i%4]
		#don't edit the binary
		#setByte(p,b)
		if b >= 0 and b < 256:
			string += chr(b)
		else:
			string += '.'
	
	cu = currentProgram.getListing().getCodeUnitAt(string_start)
	cu.setComment(CodeUnit.PLATE_COMMENT,"emotet string: "+string)
	createBookmark(string_start.add(8), "emotet string", string)
	label = "emostr_" + hex(hash(string)&(2**32-1)) + "_"
	for c in string:
		if c.isalnum():
			label += c
		else:
			label += "_"
	getSymbolAt(string_start).setName(label,SourceType.USER_DEFINED)
	return string

refs = list(set(getReferencesTo(currentAddress)))

for r in refs:
	callee = r.getFromAddress()
	inst = getInstructionAt(callee)
	i = 0
	# TODO: use pcode and reaching definition
	while not inst.toString().startswith('MOV ECX'):
		inst = getInstructionBefore(inst)
		i += 1
		if i > 10:
			break
	if inst.toString().startswith('MOV ECX'):
		string_start = toAddr(inst.getScalar(1).getValue())
		string = decrypt(string_start)
		print(str(string_start)+" "+string)
		inst.setComment(CodeUnit.PRE_COMMENT,string)
	else:
		print("FAIL")


