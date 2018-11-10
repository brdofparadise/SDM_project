import csv
import sys
import time
import socket
import struct
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

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

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    connection, client_address = sock.accept()
    
    try:

        data = connection.recv(2000)
        data_hex = data.decode("utf-8")
        c_t = data_hex.split(",")[0]
        c_id = data_hex.split(",")[1]
        sign_CT = bytes.fromhex(data_hex.split(",")[2])

        with open('clients_id_pk.csv', 'r') as f:
            reader = csv.reader(f, delimiter=',')
            data = list(reader)
            public_key_n = int(data[int(c_id)][1])
            public_key_e = int(data[int(c_id)][2])

        data_key = [public_key_n, public_key_e]
        public_key = RSA.construct(data_key)
        verify_signature(public_key,sign_CT,SHA256.new(c_t.encode("utf-8")))

        print ("C_T obtained",c_t)
        print ("Written to Server")
        c_i_entry = [c_t]
        myFile = open('cipher_text.csv', 'w', newline='')
        with myFile:
            writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(c_i_entry)
        
    finally:
        # Clean up the connection
        connection.close()