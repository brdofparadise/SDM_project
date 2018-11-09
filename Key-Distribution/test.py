import socket
import sys
import struct
import csv
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# Sign message with private key
def sign_message(private_key, message):
    h = SHA256.new(message)
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

try:
    with open('clients_keys.csv', 'r') as f:
        reader = csv.reader(f, delimiter=',')
        data = list(reader)
        public_key_n = int(data[0][1])
        public_key_e = int(data[0][2])

        # Reconstruct the public key from the keydata
        data_key = [public_key_n, public_key_e]
        public_key = RSA.construct(data_key)

        # print("public_key hex = ", public_key_n)
        # public_key_n = bytes.fromhex(public_key_n)
        # print("public_key comverted back = ", public_key_n)
        # public_key_n = public_key_n.decode("utf-8")
        # print("public_key decoded = ", public_key_n)
except FileNotFoundError:
    print("File doesn't exist.")

sk_client = RSA.importKey(open('private_key_CID0.pem', 'r').read())

message = 'hoi'
print("message = ", message)
signature = sign_message(sk_client, message.encode("utf-8"))
print("signature = ", signature)
h = SHA256.new(message.encode("utf-8"))
verify_signature(public_key, signature, h)
