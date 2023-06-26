from pwn import *
import string

class Conn:
    def connect(self):
        self.io = remote(args.get('HOST', "localhost"), int(args.get('PORT', '2137')))
        self.r = lambda x: self.io.recv(x)
        self.rl = lambda: self.io.recvline(keepends=False)
        self.ru = lambda x: self.io.recvuntil(x, drop=True)
        self.cl = lambda: self.io.clean(timeout=1)
        self.s = lambda x: self.io.send(x)
        self.sa = lambda x, y: self.io.sendafter(x, y)
        self.sl = lambda x: self.io.sendline(x)
        self.sla = lambda x, y: self.io.sendlineafter(x, y)
        self.ia = lambda: self.io.interactive()
        self.li = lambda s: log.info(s)
        self.ls = lambda s: log.success(s)

    def send_bit(self, b):
        # conn.li(f'send_bit: {b}')
        if b: sleep(0.4)
        # if b: sleep(0.2)
        self.s(random.choice(string.hexdigits).encode())

    def send_half(self, b):
        for i in range(4):
            self.send_bit((b >> (4 - 1 - i)) & 1)

        self.ru(b"OK")
        # conn.li('recved confirm')

    def send_byte(self, b):
        # self.li(f'send_byte {b:#x}')
        self.send_half((b >> 4) & 0xF)
        self.send_half(b & 0xF)

    def send1(self, b):
        self.send_byte(b)

    def send2(self, w):
        self.send_byte((w >> 8) & 0xFF)
        self.send_byte(w & 0xFF)

    def send_instruction(self, offset, type, opcode_type, data):
        # self.li(f'send_instruction (ip:{offset:#x} type:{type:#x} op_type:{opcode_type:#x} data:{data:#x})')

        self.send2(offset)
        self.send1(type)
        self.send2(opcode_type)
        self.send2(data)


conn = Conn()
