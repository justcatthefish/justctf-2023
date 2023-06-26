from pprint import pprint as pp
import matplotlib.pyplot as plt
from collections import defaultdict, Counter, deque
import sys

lines = sys.stdin.readlines()

times = []
for line in lines:
    xyz = line[:3]
    stage = int(line[3])
    time = float.fromhex("0x" + line[4:])
    times.append((xyz, stage, time))

totals = defaultdict(float)
laps = defaultdict(list)
for xyz, stage, time in times:
    if stage == 3:
        totals[xyz] += time
        laps[xyz].append(time)

dd = []
for x, y in totals.items():
    dd.append((x, y))

dd = sorted(dd, key=lambda x: x[1])
top10 = dd[:10]

pp(dd)
print("top10")

top10 = [x for x, y in top10]
pp(top10)

cc = Counter()
LAPS = defaultdict(dict)
for xyz, stage, time in times:
    if stage == 3:
        cc[xyz] += 1
        LAPS[cc[xyz]][xyz] = time


bits = []
for lap, times in LAPS.items():
    bit = 0
    for xyz, time in times.items():
        if xyz in top10 and time >= 81.37:
            bit = 1

    bits.append(bit)

bits = "".join(str(b) for b in bits)
Q = deque(bits)
out = []
while Q:
    buf = []
    while len(buf) < 7:
        buf.append(Q.popleft())

    ch = int(''.join(buf), 2)
    print(out)
    out.append(chr(ch))

print("".join(out))
