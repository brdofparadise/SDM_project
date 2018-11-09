import socket
import sys
import time
import csv
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

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
#server_address = 'localhost'
print (sys.stderr, 'starting up on %s port %s' % server_address)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print (sys.stderr, 'waiting for a connection')
    connection, client_address = sock.accept()
    
    try:

        data = connection.recv(2000)
        data_hex = data.decode("utf-8")
        c_t = data_hex.split(",")[0]
        c_id = data_hex.split(",")[1]
        sign_CT = bytes.fromhex(data_hex.split(",")[2])
        # sign_CT = bytes((data_hex.split(",b")[1]), 'utf-8')
        print("c_id",int(c_id))

        with open('clients_id_pk.csv', 'r') as f:
            reader = csv.reader(f, delimiter=',')
            data = list(reader)
            public_key_n = int(data[int(c_id)][1])
            public_key_e = int(data[int(c_id)][2])

            print("PublicKey n",public_key_n)
            print("PUBLIC e",public_key_e)            

        data_key = [public_key_n, public_key_e]
        public_key = RSA.construct(data_key)

        print("CT HERE", c_t.encode("utf-8"),type(c_t.encode("utf-8")))
        print("PK non wokring", public_key,type(public_key))
        print("Sign",sign_CT,type(sign_CT))


        verify_signature(public_key,sign_CT,SHA256.new(c_t.encode("utf-8")))
        # print ("data_hex",data.decode("utf-8"))
        # c_i_entry = [data.decode("utf-8")]
        # myFile = open('cipher_text.csv', 'w', newline='')
        # with myFile:
        #     writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
        #     writer.writerow(c_i_entry)
        
        # time.sleep(.300)
        # data2 = connection.recv(32)
        # print (sys.stderr, 'received  "%s"' % data)
        


        #receive Xj and Kj which is a search token 
        #X_J = data.split("~")[0]
        #k_j = data.split("~")[1]
        
        # C_T = None
        # with open('cipher_text.csv', newline='') as File:  
        #     reader = csv.reader(File,delimiter=',')
        #     data = [row for row in reader]
        #     C_T = data[0][0]
        #     print (C_T)
        # if data2:
        #     message = "Hello 2 from server"
        #     print (sys.stderr, 'sending %s' % message)
        #     connection.sendall(message.encode('utf-8'))
#        while True:
#            data = connection.recv(16)
#            print (sys.stderr, 'received "%s"' % data)
#            if data:
#                print (sys.stderr, 'sending data back to the client')
#                connection.sendall(data)
#            else:
#                print (sys.stderr, 'no more data from', client_address)
#                break
            
    finally:
        # Clean up the connection
        connection.close()