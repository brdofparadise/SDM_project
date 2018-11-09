# Storage_Computation.py

#encryption
import os
from Crypto.Cipher import DES
import binascii
import hmac
import csv
from Crypto import Random
import socket
import sys
import time
import socket
import sys
import struct
import csv
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def sign_message(private_key, message):
    h = SHA256.new(message)
    signer = PKCS1_PSS.new(private_key)
    signature = signer.sign(h)

    return signature

# Verify signature with public key
def verify_signature(public_key, signature, h):
    verifier = PKCS1_PSS.new(public_key)
    if verifier.verify(h, signature):
        print("Signature valid :)")
        return True
    else:
        print("Signature invalid :(")
        return False



sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.connect(server_address)

C_ID = "1"

a_bc = os.urandom(32)                           
a_bc = b'tJ\x100\nI\xa9\x96P\x10\x88\xfe-q\xa8\xbf\x92\x7f\xd3\xc0\xb0y}\x9c\xc1{+\x84\n\xd6Q\x94'
# print ("full PT",a_bc)
a_hex=a_bc.hex()

#Step 2
k_2 = os.urandom(8)                                 
k_1 = os.urandom(8)


##store k1 and k2 in a csv file
keys = [k_1.hex(),k_2.hex()]
myFile = open('keysandsi.csv', 'w', newline='')
with myFile:
    writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
    writer.writerow(keys)

C_T = ""
iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'



#STEP 1, Partition to find W_I    
# print ("\n")
for plain_fragment in ([a_hex[i:i+32] for i in range(0, len(a_hex), 32)]):
    # print("W_I",plain_fragment)

#STEP 2, Got Plaintext fragment and key now. Start finding X_i

    des = DES.new(k_2, DES.MODE_ECB)
    X_i = des.encrypt(bytes.fromhex(plain_fragment))
    # print("X_I",X_i)
    # print("X_I_HEX", X_i.hex())

#STEP 3, Found L_I    
    L_i = X_i.hex()[0:16]
    # print("L_I_HEX",L_i)

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

    # print("F_k_i_s_i", F_k_i_s_i.hex())


    T_i = s_i.hex() + F_k_i_s_i.hex()
    # print ("T_I", T_i)
    
    X_i = X_i.hex() 
    C_i = hex(int(X_i, 16) ^ int(T_i, 16))[2:]
    # print ("C_i",C_i)
    C_T = C_T + C_i

#Signature_Begins_Here
sk_consultant = RSA.importKey(open('private_key_CID0.pem', 'r').read())
pk_consultant = RSA.importKey(open('public_key_CID0.pem', 'r').read())

sign_CT = sign_message(sk_consultant,C_T.encode("utf-8"))
verify_signature(pk_consultant,sign_CT,SHA256.new(C_T.encode("utf-8")))
print("CT HERE", C_T.encode("utf-8"),type(C_T.encode("utf-8")))
print("PK wokring", pk_consultant,type(pk_consultant))
print("Sign",sign_CT,type(sign_CT))

# print("SIGNATURE_HERE", sign_CT)
# Sign message with private key


C_ID = "0"
C_T = C_T + "," + C_ID
Str_sign_CT = str(sign_CT.hex())
C_T = C_T + "," + Str_sign_CT

print ("SENDING",C_T)

try:    
    # Send data
    message = C_T
    # print (sys.stderr, 'sending "%s"' % message)
    #sock.sendall(message)
    server_address = 'localhost'
    sock.sendto(message.encode('utf-8'), (server_address, 10000))

finally:
    # print (sys.stderr, 'closing socket')
    sock.close()


