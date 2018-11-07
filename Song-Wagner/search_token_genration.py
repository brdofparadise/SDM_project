# -*- coding: utf-8 -*-
"""
Created on Wed Nov  7 09:46:25 2018

@author: sande
"""
#new_path = 'guru999.txt'
#new_days = open(new_path,'r')
#contents =new_days.read()
#print (contents)
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
#with open('example2.csv', newline='') as File:  
#    reader = csv.reader(File,delimiter=',')
#    for row in reader:
#        print(row)
#        
#
k_2 = binascii.unhexlify(k_2)
k_1 = binascii.unhexlify(k_1)

#Wj is the plaintext we need to search

W_j= b'I\x90\xe2_\x94\xc4]\x81\xb0\xd4l\x14\xc0\x00\t\x03'
k_2 = os.urandom(4).hex()
des = DES.new(k_2, DES.MODE_ECB)
X_j = des.encrypt(W_j)
print ("X_j is ", X_j)
L_j = X_j[0:int(len(W_j)/2)]

iv = Random.new().read(DES.block_size)
#print ("iv", binascii.hexlify(iv))
f_k = DES.new(k_1, DES.MODE_CBC,iv)
k_j = f_k.encrypt(L_j)

print ("kj is ",k_j)