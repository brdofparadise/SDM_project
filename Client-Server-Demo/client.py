#client
# -*- coding: utf-8 -*-
"""
Created on Tue Oct 23 12:43:57 2018

@author: sande
"""

import socket
import sys
import time
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)

#print (sys.stderr, 'connecting to %s port %s' % server_address)
sock.connect(server_address)


try:    
    # Send data
    message = 'Hello from client'
    print (sys.stderr, 'sending "%s"' % message)
    #sock.sendall(message)
    server_address = 'localhost'
    sock.sendto(message.encode('utf-8'), (server_address, 10000))

    # Look for the response
    data = sock.recv(32)
    print (sys.stderr, 'received "%s"' % data)
    
    #sleep for few milliseconds before sending the next message
    time.sleep(.500)
    message2 = "Hello 2 from client"
    print (sys.stderr, 'sending "%s"' % message2)
    #sock.sendall(message.encode('utf-8'))
    sock.sendto(message2.encode('utf-8'), (server_address, 10000))
#    
    data = sock.recv(32)
    print (sys.stderr, 'received "%s"' % data)
#    while amount_received < amount_expected:
#        data = sock.recv(16)
#        amount_received += len(data)
#        print (sys.stderr, 'received "%s"' % data)

finally:
    print (sys.stderr, 'closing socket')
    sock.close()