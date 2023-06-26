from pwn import args

from instructions import *

from prog import Instr, Label, Program


def gen_verifier():
    ret = []
    for v in map(lambda v: int(v, 16), open("./enc.txt", "rt").read().strip().split()):
        ret.append(Instr(Mov.imm_to_reg, REG2, v))
        ret.append(Instr(Sub.reg_to_mem, REG1, REG2))
        ret.append(Instr(Add.imm_to_reg, REG1, 1))

    assert len(ret) > 0
    return ret


instr = [
    # initialize
    Instr(Mov.imm_to_reg, REG1, 0),
    Instr(Mov.imm_to_reg, REG2, 0),
    Instr(Mov.imm_to_reg, REG3, 0),

    Instr(Call.imm, Label('stage1')),
    Instr(Call.imm, Label('stage2')),
    Instr(Call.imm, Label('stage3')),
    Instr(Call.imm, Label('exit')),

    Label('stage1'),
        # for (size_t i = 0; i < FLAG_LEN; i++)
        # {
        #     a[i] = ((flag[i] + flag[(i+1) % FLAG_LEN] + flag[(i+2) % FLAG_LEN]) + 0x1337);
        # }

        Instr(Mov.imm_to_reg, REG1, 0),
        Instr(Call.imm, Label('stage1_loop')),
    Instr(Ret),

    Label('stage2'),
        # for (size_t i = 0; i < FLAG_LEN; i++)
        # {
        #     b[i] = (flag[i] + flag[(i+1) % FLAG_LEN]) / 0x3;
        # }

        Instr(Mov.imm_to_reg, REG1, 0),
        Instr(Call.imm, Label('stage2_loop')),
    Instr(Ret),

    Label('stage3'),
        Instr(Mov.imm_to_reg, REG1, 0x30),
        Instr(Call.imm, Label('stage3_setup')),

        Instr(Mov.imm_to_reg, REG1, 0x30),
        Instr(Call.imm, Label('stage3_map_0_1')),

        Instr(Mov.imm_to_reg, REG1, 0x30),
        Instr(Call.imm, Label('stage3_sum')),
    Instr(Ret),

    Label('stage1_loop'),
        Instr(Mov.reg_to_reg, REG2, REG1),

        # flag[i]
        Instr(Mov.mem_to_reg, REG3, REG2),

        # flag[i+1]
        Instr(Add.imm_to_reg, REG2, 1),
        Instr(Mod.imm_to_reg, REG2, 0x20),
        Instr(Add.mem_to_reg, REG3, REG2),

        # flag[i+2]
        Instr(Add.imm_to_reg, REG2, 1),
        Instr(Mod.imm_to_reg, REG2, 0x20),
        Instr(Add.mem_to_reg, REG3, REG2),

        # a[i] = flag[i] + flag[i+1] + flag[i+2] + 0x1337
        Instr(Add.imm_to_reg, REG1, 0x30),
        Instr(Add.imm_to_reg, REG3, 0x1337),
        Instr(Xor.reg_to_mem, REG1, REG3),
        Instr(Sub.imm_to_reg, REG1, 0x30),

        # jump if we are at idx=0 again
        Instr(Add.imm_to_reg, REG1, 1),
        Instr(Mod.imm_to_reg, REG1, 0x20),
        Instr(Jnz.imm, REG1, Label('stage1_loop')),
    Instr(Ret),

    Label('add_const'),
        Instr(Add.reg_to_mem, REG1, REG2),
        Instr(Add.imm_to_reg, REG1, 1),

        # 0x50 is the end of 'a' array
        Instr(Mov.reg_to_reg, REG3, REG1),
        Instr(Sub.imm_to_reg, REG3, 0x30 + 0x20),
        Instr(Jnz.imm, REG3, Label('add_const')),
    Instr(Ret),

    Label('stage2_loop'),
        # add two values, then search such a number that multiplied by 3 gives the sum
        Instr(Mov.reg_to_reg, REG2, REG1),

        # flag[i]
        Instr(Mov.mem_to_reg, REG3, REG2),

        # flag[i+1]
        Instr(Add.imm_to_reg, REG2, 1),
        Instr(Mod.imm_to_reg, REG2, 0x20),
        Instr(Add.mem_to_reg, REG3, REG2),

        # tmp(reg3) = flag[i] + flag[i+1]
        Instr(Call.imm, 'stage2_search'),

        # a[i] ^= b[i]
        Instr(Mov.imm_to_reg, REG3, 0x30),
        Instr(Add.reg_to_reg, REG3, REG1),
        Instr(Xor.reg_to_mem, REG3, REG2),

        # a[i] &= 0xFF
        Instr(Mov.imm_to_reg, REG2, 0xFF),
        Instr(And.reg_to_mem, REG3, REG2),

        # jump if we are at idx=0 again
        Instr(Add.imm_to_reg, REG1, 1),
        Instr(Mod.imm_to_reg, REG1, 0x20),
        Instr(Jnz.imm, REG1, Label('stage2_loop')),
    Instr(Ret),

    Label('stage2_search'),
        # iterate from [reg3; 0] and find value that multiplied by 3 gives reg3 (reg3/3 is the result)
        # return value in reg2

        # backup reg1
        Instr(Mov.imm_to_reg, REG2, 0x7F),
        Instr(Mov.reg_to_mem, REG2, REG1),

        # reg1 - addr; reg2 - counter; reg3 - target val
        Instr(Mov.reg_to_reg, REG2, REG3),
        Label('stage2_search_loop'),
        Instr(Sub.imm_to_reg, REG2, 1),
        Instr(Mov.reg_to_reg, REG1, REG2),
        Instr(Mul.imm_to_reg, REG1, 0x3),

        # check if equal
        Instr(Sub.reg_to_reg, REG1, REG3),
        Instr(Jz.imm, REG1, Label('stage2_search_loop_found')),

        # check if rest is 1
        Instr(Add.imm_to_reg, REG1, 1),
        Instr(Jz.imm, REG1, Label('stage2_search_loop_found')),

        # check if rest is 2
        Instr(Add.imm_to_reg, REG1, 1),
        Instr(Jz.imm, REG1, Label('stage2_search_loop_found')),
        Instr(Jnz.imm, REG1, Label('stage2_search_loop')),

        Label('stage2_search_loop_found'),
        # restore reg1
        Instr(Mov.imm_to_reg, REG3, 0x7F),
        Instr(Mov.mem_to_reg, REG1, REG3),
    Instr(Ret),

    Label('stage3_setup'),
        'GEN_VERIFIER_PLACEHOLDER',
    Instr(Ret),

    Label('stage3_map_0_1'),
        Instr(Mov.imm_to_reg, REG2, 1),

        Instr(Mov.mem_to_reg, REG3, REG1),
        Instr(Jnz.imm, REG3, Label('store_1')),
        Instr(Jz.imm, REG3, Label('store_0')),

        Label('store_1'),
        Instr(Mov.reg_to_mem, REG1, REG2),

        Label('store_0'),
        Instr(Add.imm_to_reg, REG1, 1),
        Instr(Mod.imm_to_reg, REG1, 0x30 + 0x20),
        Instr(Jnz.imm, REG1, Label('stage3_map_0_1')),
    Instr(Ret),

    Label('stage3_sum'),
        Instr(Mov.imm_to_reg, REG2, 0),
        Label('stage3_sum_loop'),
        Instr(Mov.mem_to_reg, REG3, REG1),
        Instr(Add.reg_to_reg, REG2, REG3),

        Instr(Add.imm_to_reg, REG1, 1),
        Instr(Mod.imm_to_reg, REG1, 0x30 + 0x20),
        Instr(Jnz.imm, REG1, Label('stage3_sum_loop')),
        Instr(Mov.reg_to_reg, REG1, REG2),
    Instr(Ret),

    Label('exit'),
    Instr(Stop.reg, REG1)
]

if __name__ == '__main__':
    to_replace_idx = instr.index('GEN_VERIFIER_PLACEHOLDER')
    instr = instr[:to_replace_idx] + gen_verifier() + instr[to_replace_idx + 1:]
    p = Program(instr, args.FLAG)
    p.execute()
