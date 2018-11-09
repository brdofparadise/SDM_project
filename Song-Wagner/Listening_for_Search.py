# ListeningServer.py

import socket
import sys
import time
import csv
import binascii
import os
from Crypto.Cipher import DES
import binascii
import hmac
import csv
from Crypto import Random
iv = b'\xbb\xa8\xff\x02{\xa7\xd9\xbf'
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10001)
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
        print (sys.stderr, 'connection from', client_address)
        # Receive the data
        data = connection.recv(100)
        print (sys.stderr, 'received "%s"' % data)

        data = data.decode("utf-8")
        k_j=data.split(',')[1]
        X_j=data.split(',')[0]

        with open('cipher_text.csv', newline='') as File:  
            reader = csv.reader(File,delimiter=',')
            data = [row for row in reader]
            C_T = data[0][0]
        
        # C_T = C_T.decode('utf-8')
        # Stopped herecaden
        print("C_T",C_T)
        print("X_j",X_j)
        print("k_j",k_j)

        counter_position = 0
        for C_p in ([C_T[i:i+32] for i in range(0, len(C_T), 32)]):
                counter_position  = counter_position + 1
                T_p = (hex(int(X_j, 16) ^ int(C_p, 16))).zfill(32)[2:]
                print ("T_p",T_p)
                S_p = T_p[0:16]
                S_p_bar = T_p[16:32]
                F_k = DES.new(bytes.fromhex(k_j), DES.MODE_CBC,iv)
                F_k_j_s_p = F_k.encrypt(bytes.fromhex(S_p))
                print ("S_p_bar from calc",S_p_bar)
                print ("S_p_bar from func",F_k_j_s_p.hex())

                if(S_p_bar==F_k_j_s_p.hex()):
                    print("Match")
                    message = str(counter_position) + "," + C_p
                    print (sys.stderr, 'sending "%s"' % message)
                    server_address = 'localhost'
                    connection.sendall(message.encode('utf-8'))
                else:
                    print("No match")
# #         # if data:
#         #     message = "Hello from server"
#         #     print (sys.stderr, 'sending %s' % message)
            
#         #     connection.sendall(message.encode('utf-8'))
        
        
#         time.sleep(.300)
#         #receive Xj and Kj which is a search token 
#         data2 = connection.recv(32)
#         print (sys.stderr, 'received  "%s"' % data)
#         #X_J = data.split("~")[0]
#         #k_j = data.split("~")[1]
        
#         C_T = None
#         with open('cipher_text.csv', newline='') as File:  
#             reader = csv.reader(File,delimiter=',')
#             data = [row for row in reader]
#             C_T = data[0][0]
#             print (C_T)
#         # if data2:
#         #     message = "Hello 2 from server"
#         #     print (sys.stderr, 'sending %s' % message)
#         #     connection.sendall(message.encode('utf-8'))
# #        while True:
# #            data = connection.recv(16)
# #            print (sys.stderr, 'received "%s"' % data)
# #            if data:
# #                print (sys.stderr, 'sending data back to the client')
# #                connection.sendall(data)
# #            else:
# #                print (sys.stderr, 'no more data from', client_address)
# #                break
            
    finally:
        # Clean up the connection
        connection.close()