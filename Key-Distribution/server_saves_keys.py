import socket
import struct
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
s.bind((host,port))
print("server Started")
s.listen()

while True:
    print(sys.stderr, 'waiting for a connection')
    conn, addr = s.accept()

    try:
        print(sys.stderr, 'connection from', addr)
        data_received = 0
        write = 0
        client_id = 0
        public_key_n = 0
        public_key_e = 0

        while True:
            data = recv_msg(conn)
            print(sys.stderr, 'received "%s"' % data)

            if data:
                print("Im in the if data.")
                data_received = data_received + 1
                if data_received % 3 == 1:
                    client_id = data
                    write = 0
                    print("Received cID.")
                elif data_received % 3 == 2:
                    client_pk_n = data
                    write = 0
                    print("Received keydata n.")
                else:
                    client_pk_e = data
                    write = 1
                    print("Received keydata e.")

                if write == 1:
                    print("Writing to file.")
                    # write cID and keys to csv file
                    try:
                        with open('clients_id_pk.csv', 'a', newline='') as f:
                            writer = csv.writer(f, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                            writer.writerow([client_id.decode("utf-8"), client_pk_n.decode("utf-8"), client_pk_e.decode("utf-8")])
                    except FileNotFoundError:
                        print("File doesn't exist.")
                        print("Creating new file")
                        clients_keys_without_sk_file = open('clients_id_pk.csv', 'w', newline='')
                        with clients_keys_without_sk_file:
                            writer = csv.writer(clients_keys_without_sk_file, delimiter=',', quotechar='|',
                                                quoting=csv.QUOTE_MINIMAL)
                            writer.writerow([client_id.decode("utf-8"), client_pk_n.decode("utf-8"), client_pk_e.decode("utf-8")])
            else:
                print(sys.stderr, 'no more data from', addr)
                break
    except socket.error:
        print("An error occurred.")
        conn.close()
    finally:
        # Clean up the connection
        conn.close()
