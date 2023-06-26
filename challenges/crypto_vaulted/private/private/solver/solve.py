#!/usr/bin/env python3
import socket
from sys import argv
from coincurve import PrivateKey, utils
from json import dumps

"""
Explaination:

    The "Vault" recieves serialized public keys.
    To prevent re-using the same public key as if it were multiple, the vault
    uses a map to keep only one signature from each distinct public key.

    However, the coincurve library uses libsecp256k1 under the hood and thus
    accepts three distinct valid encodings of each public key
        * Compressed form is 33 bytes and starts with 0x02 or 0x03,
            depending on the Y-coordinate of the elliptic curve point
        * Uncompressed form is 65 bytes and starts with 0x04
        * Hybrid form is 65 bytes and starts with 0x06 or 0x07,
             depending on the Y-coordinate sign.

    By sending each of these serializations we can use our single authorized
    key three times, unlocking the vault.
"""


assert len(argv) == 3, "solve.py HOST PORT (vs %r)" % argv
HOST = argv[1]
PORT = int(argv[2])

privkey = PrivateKey(utils.urandom(32))

compressed = privkey.public_key.format(True)
uncompressed = privkey.public_key.format(False)
hybrid = bytes([uncompressed[0] | compressed[0]]) + uncompressed[1:]

pubkeys = [pk.hex() for pk in [compressed, uncompressed, hybrid]]

sigs = [privkey.sign(b'get_flag').hex()] * 3

# Open a connection to the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# Receive the banner
print(s.recv(1024).decode())

# Send the public key
msg = {'method': 'enroll', 'pubkey': pubkeys[0]}
s.sendall(dumps(msg).encode() + b'\n')

# Receive the response
print(s.recv(1024).decode())

# Send the signature
msg = {'method': 'get_flag', 'pubkeys':  pubkeys, 'signatures': sigs}
s.sendall(dumps(msg).encode() + b'\n')

# Receive the response
print(s.recv(1024).decode())
