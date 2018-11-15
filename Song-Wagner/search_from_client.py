import sys
import csv
import time
import socket
import os
import hmac
import struct
import binascii
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import DES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10001)

sock.connect(server_address)

def sign_message(private_key, message):
    h = SHA256.new(message)
    signer = PKCS1_PSS.new(private_key)
    signature = signer.sign(h)

    return signature

sk_consultant = RSA.importKey(open('private_key_CID0.pem', 'r').read())
pk_consultant = RSA.importKey(open('public_key_CID0.pem', 'r').read())

print("This portion of the code allows search functionality.")
print("The user is allowed to search the plaintext which had been previously uploaded to the server")
print("For demonstration purposes, we have hard-coded the value to be searched for")

message_queried = input("Enter date to be searched in DDMMYYYY ")
message_queried = "{:1^32s}".format(message_queried)
plain_fragment = hex(int(message_queried,16))
#11111111111111122018111111111111
#744a10300a49a996501088fe2d71a8bf
plain_fragment = plain_fragment[2:]

k_1,k_2 = None, None
with open('keysandsi.csv', newline='') as File:  
    reader = csv.reader(File,delimiter=',')
    data = [row for row in reader]
    k_1 = data[0][0]
    k_2 = data[0][1]

    k_1 = bytes.fromhex(k_1)
    k_2 = bytes.fromhex(k_2)

des = DES.new(k_2, DES.MODE_ECB)
X_j = des.encrypt(bytes.fromhex(plain_fragment))
L_j = X_j.hex()[0:16]


iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'
des = DES.new(k_1, DES.MODE_CBC,iv)
k_j = (des.encrypt(bytes.fromhex(L_j))).hex()
X_j = X_j.hex()

sign_XJ = str(sign_message(sk_consultant,X_j.encode("utf-8")).hex())
print("\n")
#print ("Signature Sent",sign_XJ,type(sign_XJ))
#print ("Signature Sent",sign_XJ,type(sign_XJ))
#print("Digest",X_j.encode("utf-8"),type(X_j.encode("utf-8")))

try:    
    message = X_j + "," + k_j + "," + sign_XJ
    server_address = 'localhost'
    sock.sendto(message.encode('utf-8'), (server_address, 10001))

    data = sock.recv(2000)
    data = data.decode("utf-8")
    position = data.split(",")[0]
    C_p = data.split(',')[1]
    print ("Position of Query Keyword ", position)
    print ("Returned Cipher Block ", C_p)

    print("\n")
    print("This portion of the code implements the Retrieval Functionality. ")
    print("It takes the position and cipher fragment returned and attempts to compute the correspoding plaintext")


    position = int(position)
    with open('keysandsi.csv', newline='') as File:  
        reader = csv.reader(File,delimiter=',')
        data = [row for row in reader]
        S_p = data[position][0]

    C_pl = C_p[0:16]
    X_pl = hex(int(C_pl, 16) ^ int(S_p, 16))[2:]

    X_pl = X_pl.zfill(16)
    des = DES.new(k_1, DES.MODE_CBC,iv)
    k_p = des.encrypt(bytes.fromhex(X_pl))

    F_k = DES.new(k_p, DES.MODE_CBC,iv)
    F_k_p_s_p = F_k.encrypt(bytes.fromhex(S_p))   

    T_p = S_p + F_k_p_s_p.hex()
    #print ("T_p in retrieval is", T_p)


    X_p = hex(int(C_p, 16) ^ int(T_p, 16))[2:]
    #print ("X_p in retrieval is", X_p)
    X_p = X_p.zfill(32)
    des = DES.new(k_2, DES.MODE_ECB)
    W_p = des.decrypt(bytes.fromhex(X_p))
    print("Retireved Plaintext Fragment",W_p.hex())
    print("\n")
    print("\n")

finally:
    print (sys.stderr, 'closing socket')
    sock.close()