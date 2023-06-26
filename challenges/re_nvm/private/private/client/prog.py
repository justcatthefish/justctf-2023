from instructions import *
import random
from pwn import p8

class Base:
    @staticmethod
    def start(input):
        conn.ru(b'RDY')
        conn.s(input.encode()[:0x20].ljust(0x20, p8(0)))
        conn.ru(b'OK')

    @staticmethod
    def finish():
        print(conn.cl())


class Label(str):
    def __repr__(self):
        return f'>{self}'


class Instr:
    def __init__(self, func, *args):
        self.func = func
        self.args = list(args)
        self.ip = None

    def execute(self):
        return self.func(self.ip, *self.args)

    def __repr__(self):
        return f'{self.ip:#x}: {self.func.__qualname__} {self.args}'


class Program:
    def __init__(self, instr, arg):
        self.ip = 0
        self.instr = instr
        self.arg = arg[:32]

    def execute(self):
        self.transpile()
        conn.connect()
        Base.start(self.arg)

        print(f'{len(self.instr)} instructions to send...')

        random.shuffle(self.instr)
        for inst in self.instr:
            print(inst)
            inst.execute()

        Base.finish()

    def transpile(self):
        # collect labels first
        labels = {}
        seen_instr = 0
        for i, l in enumerate(self.instr):
            if type(l) == Label:
                labels[l] = seen_instr
            else:
                seen_instr += 1

        # remove labels from instr
        self.instr = list(filter(lambda inst: type(inst) != Label, self.instr))

        # replace labels in args with offsets
        for i, inst in enumerate(self.instr):
            inst.ip = i
            for aid, a in enumerate(inst.args):
                if a in labels.keys():
                    inst.args[aid] = labels[a]
