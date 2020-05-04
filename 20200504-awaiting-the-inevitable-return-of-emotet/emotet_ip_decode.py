#Run with currentAddress == emotet_ip_data
#@author Hornetsecurity Security Lab 
#@category Emotet
#@keybinding 
#@menupath 
#@toolbar 


from ghidra.program.model.listing import CodeUnit

xor_key = getBytes(currentAddress,4)
len_bytes = getBytes(currentAddress.add(4),4)

data_len = 0
for i in range(4):
	data_len |= ((xor_key[i]) ^ (len_bytes[i]))<<(i*8)

type(data_len)

p = currentAddress

c2s = ""

b = getBytes(p,8)
while b[4] != 0:
	c2s += str(b[3] & (2**8-1)) + "."
	c2s += str(b[2] & (2**8-1)) + "."
	c2s += str(b[1] & (2**8-1)) + "."
	c2s += str(b[0] & (2**8-1)) + ":"
	port = 0
	port |= b[4] & (2**8-1)
	port |= (b[5] & (2**8-1)) << 8
	c2s += str(port) + "\n"
	p = p.add(8)
	b = getBytes(p,8)

cu = currentProgram.getListing().getCodeUnitAt(currentAddress)
cu.setComment(CodeUnit.PLATE_COMMENT,"emotet c2s:\n" + c2s)

