from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

clients_dict = {}
number_of_clients = 0

# Generate key pairs which can be used for signing and verifying (for the Client),
# plus generate client id for new client
def generate_keypair():
    global clients_dict
    global number_of_clients

    new_client_id = "CID" + str(number_of_clients)
    number_of_clients = number_of_clients + 1

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

    clients_dict[new_client_id] = (private_key, public_key)

    return new_client_id, private_key, public_key

# Generate n keypairs and put them in a list
def generate_keys(n):
    keys_list = []

    for x in range(n):
        client_id, private_key, public_key = generate_keypair()
        keys_list.append((client_id, private_key, public_key))

    return keys_list

# Generate public/private keypair used for encrypting and decrypting messages (used for key distribution)
# Will be called by the Consultant and Client only once.
def generate_keypair_pke():
    new_key = RSA.generate(2048, e=65537)
    private_key = new_key
    public_key = new_key.publickey()

    # In case we want to save the keys to files:
    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")
    private_key_file = open("private_key.pem", "wb")
    private_key_file.write(private_key)
    private_key_file.close()

    public_key_file = open("public_key.pem", "wb")
    public_key_file.write(public_key)
    public_key_file.close()

    return private_key, public_key

# Sign message with private key
def sign_message(private_key, message):
    h = SHA256.new(message.encode("utf8"))
    signer = PKCS1_PSS.new(private_key)
    signature = signer.sign(h)

    return signature

# Verify signature with public key
def verify_signature(public_key, signature, h):
    verifier = PKCS1_PSS.new(public_key)
    if verifier.verify(h, signature):
        print("Signature valid :)")
        return True
    else:
        print("Signature invalid :(")
        return False

# Encrypt message with public key
def encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key, SHA256)
    ciphertext = cipher.encrypt(message)

    return ciphertext

# Decrypt message with private key
def decrypt_message(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key, SHA256)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext

# The idea is to let the client generate his own public/private key-pair.
# Client will send his public key to the Consultant so that
# the Consultant can encrypt the generated public/private key-pair for the Client,
# (which will be used for signing (private key), and verifying (public key) the signature)
# and send it to the Client.
def distribute(keys_tuple, client_pk, consultant_private_key):
    for keys in keys_tuple:
        message = encrypt_message(client_pk, keys)
        signature = sign_message(consultant_private_key, message)
        # send the client s keypair with client_id (signature) to client
        # send (client_id, public_key) to server


# # Testing the generated keys for signing and verifying
# private_key, public_key = generate_keypair()
# # _, _= generate_keypair()
# # private_key = RSA.importKey(open('private_key.pem', 'r').read())
# # public_key = RSA.importKey(open('public_key.pem', 'r').read())
#
# message = 'I need to sign this.'
# h = SHA256.new(message.encode("utf8"))
# signer = PKCS1_PSS.new(private_key)
# signature = signer.sign(h)
#
# verifier = PKCS1_PSS.new(public_key)
# if verifier.verify(h, signature):
#     print("Signature valid :)")
# else:
#     print("Signature invalid :(")
