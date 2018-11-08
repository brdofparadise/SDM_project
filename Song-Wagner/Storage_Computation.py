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
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)

#print (sys.stderr, 'connecting to %s port %s' % server_address)
sock.connect(server_address)




a_bc = os.urandom(32)                           # Generated 16 byte Plain Text Block
print ("full PT",a_bc)
a_hex=a_bc.hex()
# w_i = a_bc.hex()[0:32]                          # w_i of length n 
# print ("first 16 bytes ", w_i)
# w_i_bytecode = bytes.fromhex(w_i)
# print ("first 16 bytes ", w_i_bytecode)

#Step 2
k_2 = os.urandom(8)                                 #Getting the hash working
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
print ("\n")
for plain_fragment in ([a_hex[i:i+32] for i in range(0, len(a_hex), 32)]):
    print("W_I",plain_fragment)

#STEP 2, Got Plaintext fragment and key now. Start finding X_i

    des = DES.new(k_2, DES.MODE_ECB)
    X_i = des.encrypt(bytes.fromhex(plain_fragment))
    print("X_I",X_i)
    print("X_I_HEX", X_i.hex())

#STEP 3, Found L_I    
    L_i = X_i.hex()[0:16]
    print("L_I_HEX",L_i)

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

    print("F_k_i_s_i", F_k_i_s_i.hex())


    T_i = s_i.hex() + F_k_i_s_i.hex()
    print ("T_I", T_i)
    
    X_i = X_i.hex() 
    C_i = hex(int(X_i, 16) ^ int(T_i, 16))[2:]
    print ("C_i",C_i)






try:    
    # Send data
    message = C_i
    print (sys.stderr, 'sending "%s"' % message)
    #sock.sendall(message)
    server_address = 'localhost'
    sock.sendto(message.encode('utf-8'), (server_address, 10000))


#     # Look for the response
#     data = sock.recv(32)
#     print (sys.stderr, 'received "%s"' % data)
    
#     #sleep for few milliseconds before sending the next message
#     time.sleep(.500)
#     message2 = "Hello 2 from client"
#     print (sys.stderr, 'sending "%s"' % message2)
#     #sock.sendall(message.encode('utf-8'))
#     sock.sendto(message2.encode('utf-8'), (server_address, 10000))
# #    
#     data = sock.recv(32)
#     print (sys.stderr, 'received "%s"' % data)
# #    while amount_received < amount_expected:
# #        data = sock.recv(16)
# #        amount_received += len(data)
# #        print (sys.stderr, 'received "%s"' % data)

finally:
    print (sys.stderr, 'closing socket')
    sock.close()


