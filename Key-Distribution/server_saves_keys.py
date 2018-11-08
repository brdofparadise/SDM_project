#!/usr/bin/env python3
import socket
import struct
import sys
import csv


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
s.bind((host,port))
print("server Started")
s.listen()

while True:
    print(sys.stderr, 'waiting for a connection')
    conn, addr = s.accept()

    try:
        print(sys.stderr, 'connection from', addr)
        data = recv_msg(conn)
        print(sys.stderr, 'received "%s"' % data)
        data_received = 0
        write = 0

        if data:
            print("Im in the if data.")
            if data_received % 2 == 0:
                client_id = data
                data_received = data_received + 1
                write = 0
                print("Received one piece of data.")
            else:
                client_pk = data
                data_received = data_received + 1
                write = 1
                print("Received 2 pieces of data.")

            if write == 1:
                print("Writing to file.")
                # write cID and keys to csv file
                clients_id_pk_file = open('clients_id_pk.csv', 'w', newline='')
                with clients_id_pk_file :
                    writer = csv.writer(clients_id_pk_file, delimiter=',', quotechar='|',
                                        quoting=csv.QUOTE_MINIMAL)
                    writer.writerow([client_id, client_pk])
        else:
            print(sys.stderr, 'no more data from', addr)
            break
    except socket.error:
        print("An error occurred.")
    finally:
        # Clean up the connection
        conn.close()
