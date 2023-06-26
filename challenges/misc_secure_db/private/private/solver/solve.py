#!/usr/bin/env python3

import time
from pwn import *

name_map = {
    "pulse rate": 0,
    "systolic pressure": 1,
    "diastolic pressure": 2,
    "oxygen saturation": 3
}

# Locally on MacOS use: PROXY=host.docker.internal
if args.PROXY:
    info("SETTING PROXY: " + args.PROXY)
    context.proxy = args.PROXY


def try_solve():
    info("CONNECTING TO {}:{}".format(args.HOST, args.PORT))
    with remote(args.HOST, args.PORT) as p:
        info("RECEIVING TASK")
        p.recvuntil(b"values of ")

        column_1 = p.recvuntil(b" and ")[:-5].decode("utf-8")
        print(column_1)
        column_1 = name_map[column_1]

        column_2 = p.recvuntil(b" for")[:-4].decode("utf-8")
        print(column_2)
        column_2 = name_map[column_2]

        p.recvuntil(b"ids are in (")

        task = p.recvuntil(b")")[:-1]
        p.recvuntil(b"ascending by ")
        sort_column = p.recvuntil(b",")[:-1].decode("utf-8")
        print(sort_column)

        if sort_column != "pulse rate":
            return False

        info("TASK RECEIVED")

        info("CALCULATING")

        start = time.time()

        with process("./secure_db_task-solution", ) as lp:
            time.sleep(20)
            lp.sendline(task)
            lp.sendline(str(column_1).encode("utf-8"))
            lp.sendline(str(column_2).encode("utf-8"))

            solution = lp.recvall()

        end = time.time()
        info(f"CALCULATED in ${end-start} sec")

        info("SENDING SOLUTION")
        p.sendline(solution)

        info("RESULT")
        print(p.recvall())
        return True

while True:
    if try_solve():
        break
    else:
        info("Preprocessed data not available. Trying again")
