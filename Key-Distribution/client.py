import socket
import sys
import struct
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class Client:
    # Generate public/private keypair used for encrypting and decrypting messages (used for key distribution)
    # Will be called by the Consultant and Client only once.
    def generate_keypair_pke(self):
        new_key = RSA.generate(2048, e=65537)
        private_key = new_key
        public_key = new_key.publickey()

        # In case we want to save the keys to files:
        private_key = new_key.exportKey("PEM")
        public_key = new_key.publickey().exportKey("PEM")
        private_key_file = open("private_key_client.pem", "wb")
        private_key_file.write(private_key)
        private_key_file.close()

        public_key_file = open("public_key_client.pem", "wb")
        public_key_file.write(public_key)
        public_key_file.close()

        return private_key, public_key

    # Sign message with private key
    def sign_message(self, private_key, message):
        h = SHA256.new(message)
        signer = PKCS1_PSS.new(private_key)
        signature = signer.sign(h)

        return h, signature

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

    # Prefix each message with a 4-byte length (network byte order)
    def send_msg(self, s, msg):
        msg = struct.pack('>I', len(msg)) + msg
        s.sendall(msg)

    # Read message length and unpack it into an integer
    def recv_msg(self, s):
        raw_msglen = self.recvall(s, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Read the message data
        return self.recvall(s, msglen)

    # Helper function to recv n bytes or return None if EOF is hit
    def recvall(self, s, n):
        data = b''
        while len(data) < n:
            packet = s.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def connect_to_server(self, host, port, message, public_key_consultant, private_key_client):
        # create an INET, STREAMing socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # connect to web server on port port
        s.connect((host, port))

        # send message
        try:
            print("start sending message")
            s.sendall(message)
            messages_all = []
            messages_mixed = []
            while True:
                reply = self.recv_msg(s)
                if reply:
                    print("Received", repr(reply))
                    messages_mixed.append(reply)
                    if reply == b'ABC-BEGIN' or reply == b'END-XYZ':
                        messages_all.append(reply.decode("utf-8"))
                    if len(messages_mixed) % 2 == 0 and messages_mixed[len(messages_mixed)-2] != b'ABC-BEGIN' and \
                            messages_mixed[len(messages_mixed)-2] != b'END-XYZ':
                        h = SHA256.new(messages_mixed[len(messages_mixed)-2])
                        if self.verify_signature(public_key_consultant, messages_mixed[len(messages_mixed)-1], h):
                            message_to_be_decrypted = messages_mixed[len(messages_mixed)-2]
                            messages_all.append(self.decrypt_message(private_key_client, message_to_be_decrypted))
                else:
                    print("Stopped receiving")
                    the_tuple = []
                    whole_message = ''
                    chunks = 0
                    for message in messages_all:
                        try:
                            message = message.decode("utf-8")
                        except AttributeError:
                            pass
                        if "ABC-BEGIN" in message:
                            chunks = 1
                        elif "ABC-BEGIN-h" in message:
                            pass
                        elif "END-XYZ" in message:
                            chunks = 0
                            the_tuple.append(whole_message)
                        elif "END-XYZ-h" in message:
                            pass
                        elif chunks == 1:
                            whole_message = whole_message + message
                        else:
                            the_tuple.append(message)
                    client_id = the_tuple[0]
                    data_key = the_tuple[1]
                    data_key = data_key.strip("[]")
                    data_key = data_key.split(",")
                    data_key = [int(x) for x in data_key]
                    private_key = RSA.construct(data_key)
                    public_key = private_key.publickey()

                    print("client_id = ", client_id)
                    print("private_key = ", private_key)
                    print("public_key = ", public_key)

                    return client_id, private_key, public_key
        except socket.error:
            print("An error has occurred.")
            s.close()
        finally:
            print(sys.stderr, 'closing socket')
            s.close()


if __name__ == "__main__":
    a = Client()
    private_key_client, public_key_client = a.generate_keypair_pke()
    private_key_client = RSA.importKey(open('private_key_client.pem', 'r').read())
    pk_consultant = RSA.importKey(open('public_key_consultant.pem', 'r').read())

    client_id, private_key, public_key = a.connect_to_server("127.0.0.1", 10000, public_key_client, pk_consultant, private_key_client)

    print("cID = ", client_id)
    print("private_key = ", private_key)
    print("public_key = ", public_key)
