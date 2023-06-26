from z3 import *

from pcap_decoder import extract_enc_from_pcap

FLAG_LEN = 0x20

enc = extract_enc_from_pcap("trace.pcap")

flag = BitVecs(' '.join([f'c{i}' for i in range(FLAG_LEN)]), 16)
a = [(flag[i] + flag[(i+1)%FLAG_LEN] + flag[(i+2)%FLAG_LEN]) + 0x1337 for i in range(FLAG_LEN)]
b = [(flag[i] + flag[(i+1)%FLAG_LEN]) / 0x3 for i in range(FLAG_LEN)]
d = [(a[i] ^ b[i]) & 0xFF for i in range(FLAG_LEN)]

s = Solver()
for dd, e in zip(d, enc):
    s.add(dd == e)

for i in range(len(flag)):
    s.add(BV2Int(flag[i], is_signed=False) < 0x80)
    s.add(BV2Int(flag[i], is_signed=False) >= 0x20)

for i,c in enumerate('justCTF{'):
    s.add(BV2Int(flag[i], is_signed=False) == ord(c))

s.add(BV2Int(flag[-1], is_signed=False) == ord('}'))

print("solving...")
print(s.check())

m = s.model()
print(''.join(chr(m[c].as_long()) for c in flag))
