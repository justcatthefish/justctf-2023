# VM based flag-checker

# VM design:

- stack for ret addrs
- code mem (max 256 instructions)
- mem (max 128 entries)
- 3 GP registers + ip
- program args are stored on [0x0; 0x32]

# VM start procedure

- worker sends RDY packet to client
- client responds with 0x32 bytes of data that will be stored in mem[0x0; 0x32]
- worker confirms receiving the input
- worker is ready to decode/execute instructions

# Instruction set

[0x0-0x6)
- mov
- add
- sub
- mul
- mod
- xor
- and

[0x12-0x15)
- call
- ret
- jz (jump if reg0 == 0)
- jnz (jump if reg0 != 0)

[0x21, 0x22)
- dbg (dump regs)
- stop


# Instruction encoding/decoding

- client sends one instruction at the time (2B offset, 1B instr_type, 2B opcode_type, 2B imm)
- one packet = 4 bits
- packet value is determined based on delay in messages received from client (delay means bit 1, 0s delay means bit 0)
- worker confirms receiving one instruction, till that client does not send any data
- worker hangs and waits for instructions if `ip` value was never seen before, once opcode is loaded it is stored in cache
