import struct
import socket
import sys
import csv
import time

def send_msg(s, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    s.sendall(msg)


def recv_msg(s):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(s, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(s, msglen)


def recvall(s, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = s.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


host = '127.0.0.1'
port = 50001

s = socket.socket()
s.connect((host, port))

try:
    with open('clients_keys-sk.csv', newline='') as File:
        reader = csv.reader(File,delimiter=',')
        for row in reader:
            print("sending first column")
            send_msg(s, row[0].encode("utf-8"))
            #s.sendall(row[0].encode("utf-8"))
            print("sending second column")
            send_msg(s, row[1].encode("utf-8"))
            #s.sendall(row[1].encode("utf-8"))
            print("finished sending one row")
except socket.error:
    print("An error has occurred.")
    s.close()
finally:
    print(sys.stderr, 'closing socket')
    s.close()