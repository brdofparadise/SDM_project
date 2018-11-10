# Storage_Computation.py

import os
import sys
import csv
import time
import hmac
import struct
import socket
import binascii
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import DES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

def sign_message(private_key, message):
    h = SHA256.new(message)
    signer = PKCS1_PSS.new(private_key)
    signature = signer.sign(h)

    return signature

print ("This portion of the code handles the Storage Functionality of the system.")
print ("The user is allowed to input his data in plain text.")
print ("This is then fragmented into equal portions and the corresponding cipher blocks are created.")
print ("This is then signed and sent to the server for storage.")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.connect(server_address)

C_ID = "1"

a_bc = os.urandom(32)                           
a_bc = b'tJ\x100\nI\xa9\x96P\x10\x88\xfe-q\xa8\xbf\x92\x7f\xd3\xc0\xb0y}\x9c\xc1{+\x84\n\xd6Q\x94'
a_hex=a_bc.hex()

#Step 2
k_2 = os.urandom(8)                                 
k_1 = os.urandom(8)

#store k1 and k2 in a csv file
keys = [k_1.hex(),k_2.hex()]
myFile = open('keysandsi.csv', 'w', newline='')
with myFile:
    writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(keys)

C_T = ""
iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'

#STEP 1, Partition to find W_I    
for plain_fragment in ([a_hex[i:i+32] for i in range(0, len(a_hex), 32)]):

#STEP 2, Got Plaintext fragment and key now. Start finding X_i
    des = DES.new(k_2, DES.MODE_ECB)
    X_i = des.encrypt(bytes.fromhex(plain_fragment))

#STEP 3, Found L_I    
    L_i = X_i.hex()[0:16]

#STEP 4, Encrypt L_i with k_1
    des = DES.new(k_1, DES.MODE_CBC,iv)
    k_i = des.encrypt(bytes.fromhex(L_i))

#STEP 5, Find S_i
    s_i = os.urandom(8)    
    s_i_entry = [s_i.hex()]
    myFile = open('keysandsi.csv', 'a', newline='')
    with myFile:
        writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(s_i_entry)

#Step 6, Find FKISI
    F_k = DES.new(k_i, DES.MODE_CBC,iv)
    F_k_i_s_i = F_k.encrypt(s_i)
    T_i = s_i.hex() + F_k_i_s_i.hex()    
    X_i = X_i.hex() 
    C_i = hex(int(X_i, 16) ^ int(T_i, 16))[2:]
    C_T = C_T + C_i

sk_consultant = RSA.importKey(open('private_key_CID0.pem', 'r').read())
pk_consultant = RSA.importKey(open('public_key_CID0.pem', 'r').read())

sign_CT = sign_message(sk_consultant,C_T.encode("utf-8"))
# verify_signature(pk_consultant,sign_CT,SHA256.new(C_T.encode("utf-8")))
# print("CT HERE", C_T.encode("utf-8"),type(C_T.encode("utf-8")))
# print("PK wokring", pk_consultant,type(pk_consultant))
# print("Sign",sign_CT,type(sign_CT))

C_ID = "0"
C_T = C_T + "," + C_ID
Str_sign_CT = str(sign_CT.hex())
C_T = C_T + "," + Str_sign_CT

print ("Plaintext Fragments are taken and the correponding cipher block is sent ")
print ("\n")
print ("SENDING",C_T)

try:    
    message = C_T
    server_address = 'localhost'
    sock.sendto(message.encode('utf-8'), (server_address, 10000))

finally:
    sock.close()


