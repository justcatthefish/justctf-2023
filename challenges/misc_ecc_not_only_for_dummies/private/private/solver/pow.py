#!/usr/bin/env python3
import secrets
import hashlib
from time import time

class NcPowser:
    def __init__(self, difficulty=22, prefix_length=16):
        self.difficulty = difficulty
        self.prefix_length = prefix_length

    def get_challenge(self):
        return secrets.token_urlsafe(self.prefix_length)[:self.prefix_length].replace('-', 'b').replace('_', 'a')

    def verify_hash(self, prefix, answer):
        h = hashlib.sha256()
        h.update((prefix + answer).encode())
        bits = ''.join(bin(i)[2:].zfill(8) for i in h.digest())
        return bits.startswith('0' * self.difficulty)

if __name__ == '__main__':
    powser = NcPowser()
    prefix = powser.get_challenge()
    print(f'''
sha256({prefix} + ???) == {'0'*powser.difficulty}({powser.difficulty})...
''')
    last = int(time())
    i = 0
    while not powser.verify_hash(prefix, str(i)):
        i += 1
    print(int(time()) - last, 'seconds')
    print(f"sha256({prefix} + {i}) == {'0'*powser.difficulty}({powser.difficulty})")