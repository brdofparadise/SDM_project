import os
from Crypto.Cipher import DES
import hashlib
m = hashlib.md5()

# 16 
a = os.urandom(16)									# Generated 16 byte Plain Text Block
b = a.encode('hex')									# Conversions
c = int(a.encode('hex'), 16)						# Conversions
d = bin(int(a.encode('hex'), 16))					# Conversions

#Step 2
k_2 = os.urandom(8)									#Getting the hash working
k_1 = os.urandom(8)
s_i = os.urandom(4)

print b
for plain_fragment in ([b[i:i+8] for i in range(0, len(b), 8)]):
	print plain_fragment
	des = DES.new(k_2, DES.MODE_ECB)
	cipher_fragment = des.encrypt(plain_fragment)
	print len(cipher_fragment)
	L_i = cipher_fragment[0:len(b)/2]
	k_i = m.update(L_i) 
	decrypt_fragment = des.decrypt(cipher_fragment)

	print decrypt_fragment