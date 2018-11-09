import struct
import socket
import sys
import csv


# Prefix each message with a 4-byte length (network byte order)
def send_msg(s, msg):
    msg = struct.pack('>I', len(msg)) + msg
    s.sendall(msg)

# Read message length and unpack it into an integer
def recv_msg(s):
    raw_msglen = recvall(s, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(s, msglen)

# Helper function to recv n bytes or return None if EOF is hit
def recvall(s, n):
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

# Send all client IDs with the corresponding public keys
try:
    with open('clients_keys-sk.csv', newline='') as File:
        reader = csv.reader(File,delimiter=',')
        for row in reader:
            print("sending cID")
            send_msg(s, row[0].encode("utf-8"))
            print("sending public_key_n")
            send_msg(s, row[1].encode("utf-8"))
            print("sending public_key_e")
            send_msg(s, row[2].encode("utf-8"))
            print("finished sending one row")
except socket.error:
    print("An error has occurred.")
    s.close()
finally:
    print(sys.stderr, 'closing socket')
    s.close()