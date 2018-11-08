# ListeningServer.py

#server
# -*- coding: utf-8 -*-
"""
Created on Tue Oct 23 12:49:12 2018

@author: sande
"""
#Source https://pymotw.com/2/socket/tcp.html
import socket
import sys
import time
import csv

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
        print (sys.stderr, 'connection from', client_address)

        # Receive the data
        data = connection.recv(100)
        print (sys.stderr, 'received "%s"' % data)
        #Received Cipher Text
        #store in a csv file
        c_i_entry = [data]
        myFile = open('cipher_text.csv', 'w', newline='')
        with myFile:
            writer = csv.writer(myFile,delimiter=',',quotechar='|', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(c_i_entry)
        # if data:
        #     message = "Hello from server"
        #     print (sys.stderr, 'sending %s' % message)
            
        #     connection.sendall(message.encode('utf-8'))
        
        
        time.sleep(.300)
        #receive Xj and Kj which is a search token 
        data2 = connection.recv(32)
        print (sys.stderr, 'received  "%s"' % data)
        #X_J = data.split("~")[0]
        #k_j = data.split("~")[1]
        
        C_T = None
        with open('cipher_text.csv', newline='') as File:  
            reader = csv.reader(File,delimiter=',')
            data = [row for row in reader]
            C_T = data[0][0]
            print (C_T)
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