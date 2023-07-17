#!/usr/bin/env python3
import numpy as np

samples = [np.fromfile(f'Receiver_{i}.bin', np.complex64) for i in range(9)]

print("average phase diffs..")
for i, s in enumerate(samples):
    avg_diff = np.mean(np.angle(s / samples[0]))
    print(i, avg_diff/np.pi*180)

print("Correcting phases..")
for i, s in enumerate(samples):
    avg_diff = np.mean(np.angle(s / samples[0]))
    s *= np.exp(-1j*avg_diff)

print("get mean signal..")
mean_signal = np.mean(samples, axis=0)


symbols = []
for s in samples[0] - mean_signal:
    i = np.real(s)
    q = np.imag(s)
    # Symbol Table: [(1+1j), (-1+1j), (-1-1j), (1-1j)]
    # Symbol rate is 1/2 times the sample rate
    if i > 0 and q > 0:
        symbols += [0] # 11
    elif i > 0 and q < 0:
        symbols += [1] # 10
    elif i < 0 and q < 0:
        symbols += [2] # 01
    else:
        symbols += [3] # 00

# "flag" in symbols
# 2 1 2 1  2 1 0 3  2 1 ...
# "flag" in bits
# 01100110 01101100 01100001 01100111

out = ""
for s in symbols[::2]:
    if s == 0:
        out += "11"
    if s == 1:
        out += "10"
    if s == 2:
        out += "01"
    if s == 3:
        out += "00"

flag = int(out, 2).to_bytes(len(out) // 8, byteorder='big')
print(flag)
