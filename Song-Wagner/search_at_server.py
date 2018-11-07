
#search at server

# -*- coding: utf-8 -*-
"""
Created on Wed Nov  7 10:45:54 2018

@author: sande
"""
from Crypto.Cipher import DES
import binascii

def padhexa(s):
    return '0x' + s[2:].zfill(32)

X_j =  b"Z\xe0\xde\xb9\xb1\xfeE\xcf\xb4\x12\x99\x10.\xa6'F".hex()
kj =  b'\xa7p\xb9\x0bg\xabE\xa1'
#C_p = "0x4d627e16482a3506549f218b5dd5a61d"
C_p = "1722d1236006fbef0369b4ff4220aff670d4fb5f0cc14c3912eb0f4bf24fc862"
#C_p = binascii.unhexlify(int(C_p, 16))
#hex_str = "0xAD4"
#hex_int = int(C_p, 16)
#new_int = hex_int + 0x200
#C_p = hex(new_int)
for cipher_fragment in ([C_p[i:i+32] for i in range(0, len(C_p), 32)]):
    #X_j = X_j.hex()	
    #thiscf = bytes.fromhex(cipher_fragment)
    #cipher_fragment = bytes.fromhex(cipher_fragment)
    #print (cipher_fragment)
    T_p = hex(int(cipher_fragment, 16) ^ int(X_j, 16))
#    T_p = hex(int(cipher_fragment.hex(), 16) ^ int(X_j, 16))
#    print (cipher_fragment.hex())
#    print (X_j)
    print (T_p)
    T_p = padhexa(T_p)
#    print (T_p)
    
    #print (cipher_fragment.hex())
    #T_p = hex(cipher_fragment.hex() ^ int(X_j, 16))
#
    #print (len(T_p)/2)
    S_p = T_p[2:18]
    print (S_p)
#    
   S_p_1 = T_p[18:]
 
#    print (S_p_1)
#    print (kj)
#    print (len(kj))
   
    iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'
    F_k = DES.new(kj, DES.MODE_CBC,iv)
    S_p = bytes.fromhex(S_p)
    F_kj_s_p = F_k.encrypt(S_p)
    print ("sp1", S_p_1)
    print ("fkjsp", F_kj_s_p.hex())
    if (S_p_1 == F_kj_s_p):
        print ("yay")