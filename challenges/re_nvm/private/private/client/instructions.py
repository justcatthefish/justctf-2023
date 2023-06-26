from consts import *
from connection import conn


class ArithInstr:
    def __init__(self, instr_type):
        self.instr_type = instr_type

    def reg_to_reg(self, ip, reg1, reg2):
        conn.send_instruction(ip, self.instr_type, 0 << 4 | reg1, reg2)

    def imm_to_reg(self, ip, reg1, imm):
        conn.send_instruction(ip, self.instr_type, 1 << 4 | reg1, imm)

    def mem_to_reg(self, ip, reg1, reg2):
        conn.send_instruction(ip, self.instr_type, 2 << 4 | reg1, reg2)

    def reg_to_mem(self, ip, reg1, reg2):
        conn.send_instruction(ip, self.instr_type, 3 << 4 | reg1, reg2)


Mov = ArithInstr(MOV)
Add = ArithInstr(ADD)
Sub = ArithInstr(SUB)
Mul = ArithInstr(MUL)
Mod = ArithInstr(MOD)
Xor = ArithInstr(XOR)
And = ArithInstr(AND)


class Jumpable:
    def __init__(self, instr_type):
        self.instr_type = instr_type

    def imm(self, ip, cond, imm):
        conn.send_instruction(ip, self.instr_type, 0 << 4 | cond, imm)

    def reg(self, ip, cond, reg1):
        conn.send_instruction(ip, self.instr_type, 1 << 4 | cond, reg1)

    def mem(self, ip, cond, reg1):
        conn.send_instruction(ip, self.instr_type, 2 << 4 | cond, reg1)


class Simple:
    def __init__(self, instr_type):
        self.instr_type = instr_type

    def imm(self, ip, imm):
        conn.send_instruction(ip, self.instr_type, 0 << 4 | 0, imm)

    def reg(self, ip, reg1):
        conn.send_instruction(ip, self.instr_type, 1 << 4 | reg1, 0)

    def mem(self, ip, reg1):
        conn.send_instruction(ip, self.instr_type, 2 << 4 | reg1, 0)


Call = Simple(CALL)
Ret = lambda ip: conn.send_instruction(ip, RET, 0 << 4 | 0, 0)
Jz = Jumpable(JZ)
Jnz = Jumpable(JNZ)

Stop = Simple(STOP)


class Dbg:
    @staticmethod
    def vm(ip):
        conn.send_instruction(ip, DEBUG, 0 << 4 | 0, 0)


Debug = Dbg()
