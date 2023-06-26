from datetime import datetime
from pprint import pprint as pp
import numpy as np
import random
import string
import sys

print(
    "Formula L test connected \o/. You can encode your test string here."
)


def name(x):
    return "".join(random.choice(string.ascii_uppercase) for _ in range(x))

top10 = set()
while len(top10) != 10:
    top10.add(name(3))

rest = set()
while len(rest) != 30:
    n = name(3)
    if n in top10:
        continue

    rest.add(n)

def noise():
    noise_options = np.linspace(-0.05, +0.05, 50)
    return random.choice(noise_options)

def lap(player, lo, hi):
    time_options = np.linspace(lo, hi, 50)
    target = random.choice(time_options)
    third = round(target / 3, 3)
    x = third + noise()
    y = x + third
    z = target

    x,y,z = round(x, 3), round(y, 3), round(z, 3)

    return [
        (player, 1, x),
        (player, 2, y),
        (player, 3, z),
    ]

def top10_lap(player):
    # To make it easier to generate the data I just picked some constants,
    # so that top10 will always be in this range, rest will always be in the
    # rest_lap range, and pitstop will always be slower than both.
    lo = 72.137
    hi = 73.37
    return lap(player, lo, hi)

def rest_lap(player):
    lo = 73.38
    hi = 81.36
    return lap(player, lo, hi)

def pitstop_lap(player):
    lo = 81.37
    hi = 82
    return lap(player, lo, hi)


def encode_in_bits(flag):
    bb = [ord(f) for f in flag]
    out = []
    for b in bb:
        zz = bin(b)[2:]
        zz = zz.rjust(7, "0")
        assert len(zz) == 7
        out.append(zz)

    s = "".join(out)
    assert len(s) % 7 == 0
    return s

flag = input()
bits = encode_in_bits(flag)
times = []

for bit in bits:
    if bit == "1":
        pitstop = random.choice(list(top10))
    else:
        pitstop = None

    for t in top10:
        if t == pitstop:
            times += pitstop_lap(t)
        else:
            times += top10_lap(t)

    for r in rest:
        times += rest_lap(r)

rows = []
for t in times:
    rows.append(f"{t[0]}{t[1]}{t[2].hex()[2:]}")

print("\n".join(rows))
