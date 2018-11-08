import socket
import sys
import struct
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class Consultant:
    clients_dict = {}
    number_of_clients = 0

    # Generate key pairs which can be used for signing and verifying (for the Client),
    # plus generate client id for new client
    def generate_keypair(self):
        new_client_id = "CID" + str(self.number_of_clients)
        self.number_of_clients = self.number_of_clients + 1

        new_key = RSA.generate(2048, e=65537)
        private_key = new_key
        public_key = new_key.publickey()

        # In case we want to save the keys to files:
        private_key = new_key.exportKey("PEM")
        public_key = new_key.publickey().exportKey("PEM")
        private_key_filename = "private_key_" + str(new_client_id) + ".pem"
        private_key_file = open(private_key_filename, "wb")
        private_key_file.write(private_key)
        private_key_file.close()

        public_key_filename = "public_key_" + str(new_client_id) + ".pem"
        public_key_file = open(public_key_filename, "wb")
        public_key_file.write(public_key)
        public_key_file.close()

        self.clients_dict[new_client_id] = (private_key, public_key)

        # returns the client ID and the keydata
        # private key: n, e, d, p, q, u
        # public key: n, e
        return new_client_id, [new_key.n, new_key.e, new_key.d, new_key.p, new_key.q, new_key.u]

    # Generate n keypairs and put them in a list
    def generate_keys(self, n):
        keys_list = []

        for x in range(n):
            client_id, private_key, public_key = self.generate_keypair()
            keys_list.append((client_id, private_key, public_key))

        return keys_list

    # Generate public/private keypair used for key distribution
    # Will be called by the Consultant and Client only once.
    def generate_keypair_pke(self):
        new_key = RSA.generate(2048, e=65537)
        private_key = new_key
        public_key = new_key.publickey()

        # In case we want to save the keys to files:
        private_key = new_key.exportKey("PEM")
        public_key = new_key.publickey().exportKey("PEM")
        private_key_file = open("private_key_consultant.pem", "wb")
        private_key_file.write(private_key)
        private_key_file.close()

        public_key_file = open("public_key_consultant.pem", "wb")
        public_key_file.write(public_key)
        public_key_file.close()

        return private_key, public_key

    def build_private_key(self, data_key):
        private_key = data_key.construct
        public_key = private_key.publickey()

        return private_key, public_key

    # Sign message with private key
    def sign_message(self, private_key, message):
        h = SHA256.new(message)
        signer = PKCS1_PSS.new(private_key)
        signature = signer.sign(h)

        return signature

    # Verify signature with public key
    def verify_signature(self, public_key, signature, h):
        verifier = PKCS1_PSS.new(public_key)
        if verifier.verify(h, signature):
            print("Signature valid :)")
            return True
        else:
            print("Signature invalid :(")
            return False

    # Encrypt message with public key
    def encrypt_message(self, public_key, message):
        cipher = PKCS1_OAEP.new(public_key, SHA256)
        ciphertext = cipher.encrypt(message)

        return ciphertext

    # Decrypt message with private key
    def decrypt_message(self, private_key, ciphertext):
        cipher = PKCS1_OAEP.new(private_key, SHA256)
        plaintext = cipher.decrypt(ciphertext)

        return plaintext

    def send_msg(self, conn, msg):
        # Prefix each message with a 4-byte length (network byte order)
        msg = struct.pack('>I', len(msg)) + msg
        conn.sendall(msg)

    def recv_msg(self, conn):
        # Read message length and unpack it into an integer
        raw_msglen = self.recvall(conn, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return self.recvall(conn, msglen)

    def recvall(self, conn, n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = b''
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def distribute_keys_client(self, host, port, private_key_consultant):
        # create an INET, STREAMing socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # connect to web server on port port
        s.bind((host, port))
        s.listen()

        while True:
            # Wait for a connection
            print(sys.stderr, 'waiting for a connection')
            conn, addr = s.accept()

            try:
                print(sys.stderr, 'connection from', addr)
                # Receive the public key from the client
                data = RSA.importKey(conn.recv(1024))
                print(sys.stderr, 'received "%s"' % data)
                if data:
                    public_key_client = data
                    client_id, data_key = self.generate_keypair()
                    my_tuple = client_id, data_key
                    my_tuple = [str(x) for x in my_tuple]
                    my_tuple = [x.encode("utf-8") for x in my_tuple]
                    print("my_tuple[0] bytes = ", len(my_tuple[0]))
                    print("my_tuple[1] bytes = ", len(my_tuple[1]))
                    print(sys.stderr, 'sending new keypair to the client')
                    for x in my_tuple:
                        # if the plaintext to be encrypted is too long, split it in smaller chunks
                        # 256 - 2 - 2 * 32 = 190
                        if len(x) > 190:
                            print("plaintext too long for encryption, so split")
                            self.send_msg(conn, "ABC-BEGIN".encode("utf-8"))
                            self.send_msg(conn, "ABC-BEGIN-h".encode("utf-8"))
                            data_chunks = [x[start:start + 190] for start in range(0, len(x), 190)]
                            for chunk in data_chunks:
                                encrypted_chunk = self.encrypt_message(public_key_client, chunk)
                                signature_chunk = self.sign_message(private_key_consultant, encrypted_chunk)
                                self.send_msg(conn, encrypted_chunk)
                                self.send_msg(conn, signature_chunk)
                            self.send_msg(conn, "END-XYZ".encode("utf-8"))
                            self.send_msg(conn, "END-XYZ-h".encode("utf-8"))
                        else:
                            encrypted_message = self.encrypt_message(public_key_client, x)
                            signature = self.sign_message(private_key_consultant, encrypted_message)
                            self.send_msg(conn, encrypted_message)
                            self.send_msg(conn, signature)
                    print(sys.stderr, 'keypair sent')
                else:
                    print(sys.stderr, 'no more data from', addr)
                    break
            except socket.error:
                print("An error occurred.")
            finally:
                # Clean up the connection
                conn.close()


if __name__ == "__main__":
    a = Consultant()
    #a.generate_keypair_pke()

    sk_consultant = RSA.importKey(open('private_key_consultant.pem', 'r').read())
    pk_consultant = RSA.importKey(open('public_key_consultant.pem', 'r').read())

    a.distribute_keys_client("127.0.0.1", 10000, sk_consultant)
