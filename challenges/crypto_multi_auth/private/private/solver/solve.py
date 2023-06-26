#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
~Gros
"""

from pwn import *
import subprocess
from binascii import *
from sys import argv
from base64 import b64decode, b64encode
import json
import os
from hashlib import sha256


TARGET = b"We the people, in order to get points, are kindly asking for flag"
NOPE = b"nope"
OK = b"ok"


def b64e(x):
    return b64encode(x).decode()


def test_simple_working(s):
    msg = b64encode(os.urandom(22)).decode()
    s.sendline(json.dumps({"method": "auth", "message": msg}).encode())
    sigs = json.loads(s.recvline(keepends=False))

    s.sendline(json.dumps({"method": "verify", "message": msg, "signatures": sigs}).encode())
    resp = s.recvline(keepends=False)
    assert resp == OK, resp


def test_easy_forgery_not_allowed(s):
    s.sendline(json.dumps({"method": "auth", "message": b64e(TARGET)}).encode())
    resp = s.recvline(keepends=False)
    assert resp == NOPE, resp


def test_forgery_via_whitespaces_not_allowed(s):
    s.sendline(json.dumps({"method": "auth", "message": b64e(TARGET + b" ")}).encode())
    sigs = json.loads(s.recvline(keepends=False))

    s.sendline(json.dumps({"method": "verify", "message": b64e(TARGET), "signatures": sigs}).encode())
    resp = s.recvline(keepends=False)
    assert resp == NOPE, resp


def test_all_signatures_must_be_correct(s):
    msg = b64e(b"slowackiego balladyna")
    s.sendline(json.dumps({"method": "auth", "message": msg}).encode())
    sigs = json.loads(s.recvline(keepends=False))

    s.sendline(json.dumps({"method": "verify", "message": msg, "signatures": sigs}).encode())
    resp = s.recvline(keepends=False)
    assert resp == OK, resp

    for sig_to_replace in ['hmac', 'ecdsa']:
        sigs2 = sigs.copy()
        x = b64decode(sigs2[sig_to_replace])
        sigs2[sig_to_replace] = b64e(x[:2] + bytes([x[2] ^ 0xff]) + x[3:])
        s.sendline(json.dumps({"method": "verify", "message": msg, "signatures": sigs2}).encode())
        resp = s.recvline(keepends=False)
        assert resp == NOPE, resp


def solve(s):
    # get correct hmac value
    s.sendline(json.dumps({"method": "auth", "message": b64e(sha256(TARGET).digest())}).encode())
    hmac_signature = b64decode(json.loads(s.recvline(keepends=False))['hmac'])

    # get correct ecdsa signature
    s.sendline(json.dumps({"method": "auth", "message": b64e(TARGET + bytes([hmac_signature[0]]))}).encode())
    ecdsa_signature = b64decode(json.loads(s.recvline(keepends=False))['ecdsa'])

    # get 3 bytes of aes tag
    s.sendline(json.dumps({"method": "backdoor", "message": b64e(TARGET + hmac_signature + ecdsa_signature)}).encode())
    aes_signature = s.recv(15)
    assert len(aes_signature) == 15

    # bruteforce 4th byte of aes tag
    flag = None
    for tag_4_byte in range(256):
        aes_sig_forged = b64e(aes_signature + bytes([tag_4_byte]))

        sigs = {"aes": aes_sig_forged, "hmac": b64e(hmac_signature), "ecdsa": b64e(ecdsa_signature)}
        s.sendline(json.dumps({"method": "verify", "message": b64e(TARGET), "signatures": sigs}).encode())
        maybe_flag = s.recvline(keepends=False)
        if maybe_flag != NOPE:
            print(f"Found correct signatures: {sigs}")
            flag = maybe_flag
            break

    if flag is None:
        return False
    
    print(flag)
    assert flag.startswith(b'justCTF{') and flag.endswith(b'}'), flag
    return True


if __name__ == '__main__':
    assert len(argv) == 3, "solve.py HOST PORT (vs %r)" % argv
    HOST = argv[1]
    PORT = int(argv[2])

    s = remote(HOST, PORT)
    header = s.recvuntil(b'\n')[:-1]
    assert header == b"Multi authenticator started"

    test_simple_working(s)
    test_easy_forgery_not_allowed(s)
    test_forgery_via_whitespaces_not_allowed(s)
    test_all_signatures_must_be_correct(s)
    assert solve(s)

    # s.interactive()
    s.close()
