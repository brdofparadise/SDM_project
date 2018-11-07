# p desired location
# Cp = hCp,l, Cp,ri stored block
# Sp random value
# Xp,l = Cp,l ⊕ Sp left part of encrypted block
# kp = fk0 (Xp,l) key for F
# Tp = hSp, Fkp
# (Sp)i check tuple
# Xp = Cp ⊕ Tp encrypted block
# Wp = Dk00 (Xp) plain text block
# where D is the decryption function D : key × {0, 1} n → {0, 1}  n such that Dk00 (Ek00 (Wi)) = Wi

import csv
from Crypto.Cipher import DES
from Crypto import Random
import binascii
import os

#get k1 and k2 generated during encryption phase from csv file
k_1,k_2 = None, None
with open('example2.csv', newline='') as File:  
    reader = csv.reader(File,delimiter=',')
    for row in reader:
        #print(row)
        k_1 = row[0]
        k_2 = row[1]
        print (k_1)
        print (k_2)
 
#stored block (Cp = hCp, l,  Cp, ri)
#C_p = 

#Wj plain text block
W_j= b'I\x90\xe2_\x94\xc4]\x81\xb0\xd4l\x14\xc0\x00\t\x03'

#Sp random value (generated using seed)
#Sp = 
 
