# -*- coding: utf-8 -*-
"""
Created on Thu Nov  8 13:07:38 2018

@author: sande
"""

#client
import socket
import sys
import time
from Crypto.Cipher import DES
import csv
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10001)

#print (sys.stderr, 'connecting to %s port %s' % server_address)
sock.connect(server_address)
plain_fragment = hex(int("744a10300a49a996501088fe2d71a8bf",16))
plain_fragment = plain_fragment[2:]

k_1,k_2 = None, None
with open('keysandsi.csv', newline='') as File:  
    reader = csv.reader(File,delimiter=',')
    data = [row for row in reader]
    k_1 = data[0][0]
    k_2 = data[0][1]

    k_1 = bytes.fromhex(k_1)
    k_2 = bytes.fromhex(k_2)
    print (k_1)
    print (k_2)
des = DES.new(k_2, DES.MODE_ECB)
X_j = des.encrypt(bytes.fromhex(plain_fragment))
    
L_j = X_j.hex()[0:16]
print("L_J_HEX",L_j)
iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'
des = DES.new(k_1, DES.MODE_CBC,iv)
k_j = (des.encrypt(bytes.fromhex(L_j))).hex()
X_j = X_j.hex()

print (X_j)
print("Alice sends X_j and K_J to bob")

try:    
    # Send X_j and k_j
    message = X_j + "," + k_j
    print (sys.stderr, 'sending "%s"' % message)
    #sock.sendall(message)
    server_address = 'localhost'
    sock.sendto(message.encode('utf-8'), (server_address, 10001))

    # Look for the response
    data = sock.recv(64)
    print (sys.stderr, 'received matching cipher text back "%s"' % data)
    data = data.decode("utf-8")
    position = data.split(",")[0]
    C_p = data.split(',')[1]
    print ("position ", position)
    print ("C_p ", C_p)

    #Retrieval
    position = int(position)
    with open('keysandsi.csv', newline='') as File:  
        reader = csv.reader(File,delimiter=',')
        data = [row for row in reader]
        S_p = data[position][0]

    #S_p = bytes.fromhex(S_p)
    C_pl = C_p[0:16]
    X_pl = hex(int(C_pl, 16) ^ int(S_p, 16))[2:]

    print ("ErrorMarker", X_pl)
    X_pl = X_pl.zfill(16)
    des = DES.new(k_1, DES.MODE_CBC,iv)
    k_p = des.encrypt(bytes.fromhex(X_pl))

    F_k = DES.new(k_p, DES.MODE_CBC,iv)
    F_k_p_s_p = F_k.encrypt(bytes.fromhex(S_p))   

    T_p = S_p + F_k_p_s_p.hex()
    print ("T_p in retrieval is", T_p)


    X_p = hex(int(C_p, 16) ^ int(T_p, 16))[2:]
    print ("X_p in retrieval is", X_p)
    X_p = X_p.zfill(32)
    des = DES.new(k_2, DES.MODE_ECB)
    W_p = des.decrypt(bytes.fromhex(X_p))
    print("Retireved Frag",W_p.hex())
    print("\n")
    print("\n")
#    #sleep for few milliseconds before sending the next message
#    time.sleep(.500)
#    message2 = "Hello 2 from client 46c6bcc81a962693497b0ac79762cdfe"
#    print (sys.stderr, 'sending "%s"' % message2)
#    #sock.sendall(message.encode('utf-8'))
#    sock.sendto(message2.encode('utf-8'), (server_address, 10001))
#
#    data = sock.recv(64)
#    print (sys.stderr, 'received "%s"' % data)
#    while amount_received < amount_expected:print ("position ", position)
#        data = sock.recv(16)
#        amount_received += len(data)
#        print (sys.stderr, 'received "%s"' % data)

finally:
    print (sys.stderr, 'closing socket')
    sock.close()