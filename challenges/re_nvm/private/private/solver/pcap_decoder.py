import pyshark
from pwn import *
from textwrap import wrap


def extract_enc_from_pcap(path):
    cap = pyshark.FileCapture(path, display_filter='tcp')

    last_ts = 0
    hbits = []
    ip_data = {}
    for c in cap:
        if hasattr(c.tcp, 'payload'):
            payload = unhex(c.tcp.payload.replace(':', '')).decode()
            ts = float(c.frame_info.time_relative)
            # print(round(ts, 3), payload)
            port = int(c.tcp.srcport)
            if port == 2137:
                continue

            if len(payload) == 32:
                pass
            else:
                for _ in payload:
                    if ts - last_ts >= 0.3:
                        hbits.append(1)
                    else:
                        hbits.append(0)

                    last_ts = ts

            last_ts = ts

        packet_len = 8 * (2 + 1 + 2 + 2)
        if len(hbits) >= packet_len:
            chunk = hbits[:packet_len]
            chunks = list(map(lambda c: int(c, 2), wrap(''.join(map(str, chunk)), 4)))
            instr_iter = iter(chunks)
            opcode = []
            for size in [4, 2, 4, 4]:
                v = 0
                for _ in range(size):
                    v <<= 4
                    v |= next(instr_iter)
                opcode.append(v)

            ip, off, type, data = opcode
            padded_type = bin(type)[2:].zfill(8)
            type1, type2 = padded_type[:4], padded_type[4:]
            print(f'ip:{ip:#x}  instr_type:{off:#x}  op_type:{type1} {type2}  data:{data:#x}')
            ip_data[ip] = data
            hbits = hbits[packet_len:]

    # Disassemble(ip_data)

    # extract only enc values
    expected = [ip_data[i] for i in range(0x49, 0xa9, 3)]
    return expected
