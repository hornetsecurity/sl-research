#Run with currentAddress = emotet_rsa_xor_encoded data.
#Decodes XOR encoded RSA key (and potentially other data) of Emotet.
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

for i in range(data_len):
	p = currentAddress.add(8).add(i)
	b = getBytes(p,1)[0] ^ xor_key[i%4]
	setByte(p,b)

cu = currentProgram.getListing().getCodeUnitAt(currentAddress.add(8))
cu.setComment(CodeUnit.PLATE_COMMENT,"emotet data DECODED!")
