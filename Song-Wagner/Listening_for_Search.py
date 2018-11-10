# ListeningServer.py

import socket
import sys
import time
import csv
import binascii
import os
import binascii
import hmac
import csv
from Crypto import Random
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS

iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10001)
sock.bind(server_address)
sock.listen(1)


def sign_message(private_key, message):
    h = SHA256.new(message)
    signer = PKCS1_PSS.new(private_key)
    signature = signer.sign(h)

    return signature

def verify_signature(public_key, signature, h):
    verifier = PKCS1_PSS.new(public_key)
    if verifier.verify(h, signature):
        print("Signature valid. Authenticity Verified.")
        return True
    else:
        print("Signature invalid :(")
        return False


while True:
    # print (sys.stderr, 'waiting for a connection')
    connection, client_address = sock.accept()
    
    try:
        # print (sys.stderr, 'connection from', client_address)
        data = connection.recv(1000)
        print (sys.stderr, 'received "%s"' % data)

        data = data.decode("utf-8")
        k_j=data.split(',')[1]
        X_j=data.split(',')[0]
        sign_CT=data.split(',')[2]
        c_id = 0
        with open('clients_id_pk.csv', 'r') as f:
            reader = csv.reader(f, delimiter=',')
            data = list(reader)
            public_key_n = int(data[int(c_id)][1])
            public_key_e = int(data[int(c_id)][2])

        data_key = [public_key_n, public_key_e]
        public_key = RSA.construct(data_key)

        print("\n")
        print ("Signature Rxed",sign_CT,type(sign_CT))
        print("Digest",X_j.encode("utf-8"),type(X_j.encode("utf-8")))

        with open('cipher_text.csv', newline='') as File:  
            reader = csv.reader(File,delimiter=',')
            data = [row for row in reader]
            C_T = data[0][0]
        
        # print("C_T",C_T)
        # print("X_j",X_j)
        # print("k_j",k_j)

        counter_position = 0
        for C_p in ([C_T[i:i+32] for i in range(0, len(C_T), 32)]):
                counter_position  = counter_position + 1
                T_p = ((hex(int(X_j, 16) ^ int(C_p, 16)))[2:]).zfill(32)
                print ("T_p",T_p)
                S_p = T_p[0:16]
                S_p_bar = T_p[16:32]
                F_k = DES.new(bytes.fromhex(k_j), DES.MODE_CBC,iv)
                F_k_j_s_p = F_k.encrypt(bytes.fromhex(S_p))
                print ("S_p_bar calculated from T_p",S_p_bar)
                print ("S_p_bar calucated from S_p",F_k_j_s_p.hex())

                if(S_p_bar==F_k_j_s_p.hex()):
                    print(" Valid Match has been found.")
                    print (" Sending cipher block and it's corresponding position")
                    message = str(counter_position) + "," + C_p
                    # print (sys.stderr, 'sending "%s"' % message)
                    server_address = 'localhost'
                    connection.sendall(message.encode('utf-8'))
                else:
                    print("No match has been found. Try again")

                print("\n Trying Next Block")
            
    finally:
        # Clean up the connection
        connection.close()