#!/usr/bin/env python3
import numpy as np
import scipy
import matplotlib.pyplot as plt
from itertools import groupby

def run_length_encode(data):
    return ((x, sum(1 for _ in y)) for x, y in groupby(data))


fs, signal_data = scipy.io.wavfile.read("baseband_shifted.wav")

signal_data = signal_data[2000:,:]
symbols = signal_data[:,0] > 0

rle_dat = list(run_length_encode(symbols))

# Plot lengths
#lengths = [x[1] for x in rle_dat]
#counts, bins = np.histogram(lengths,bins=10000)
#plt.stairs(counts, bins)
#plt.show()
# splits at 20, 55, 90, 130, 166, 200
# -> guess symbol length to be around 35 and adapt as needed.

symbol_length_in_samples = 36.75 # manually adapted until it worked

dedupsym = []
for sym,rle in rle_dat:
    dedupsym += [sym] * int(round(rle/symbol_length_in_samples))

out_bin = ""
last = ""
for s in dedupsym:
    if last == s:
        out_bin += "0"
    else:
        out_bin += "1"
    last = s

print("\n\nParsing Packets...")
packets = out_bin.split("00011010110011111111110000011101")[1:]
for p in packets:
    packet = "00011010110011111111110000011101"+p[:864-32]
    print(packet)
    extra = p[864-32:]
    print("Extra", extra, extra.find("01111110"))
    print(packet[-8:], len(packet))
    header = packet[:32]
    length1 = packet[32:48]
    length2 = packet[48:64]
    startflag = packet[64:72]
    addr = packet[72:184]
    ctrl = packet[184:192]
    pid = packet[192:200]
    flagf = packet[200:840]
    fcs = packet[840:856]
    endf = packet[856:864]
    assert packet == header + length1 + length2 + startflag + addr + ctrl + pid + flagf + fcs + endf

    flagfb = int(flagf, 2).to_bytes(len(flagf) // 8, byteorder='big')
    print(f"{length1=} (expected {bin(0x64)})")
    print(f"{length2=} (expected {bin(0x64)})")
    print(f"{startflag=} (expected {bin(0x7e)})")
    print(f"{addr=}")
    print(f"{ctrl=}(expected {bin(0x03)})")
    print(f"{pid=}(expected {bin(0xF0)})")
    print(f"{flagf=} [{flagfb}]")
    print(f"{fcs=}")
    print(f"{endf=}(expected {bin(0x7e)})")
    print("\n")

# flag{juliet422165hotel4:GEHcyMz0-lG5ECral59sCkgHSIsw9wapbs-Dh3wGAN3V9pF2vsRYtXyJctNBfoDD7CFVmeV-xBIusRqEyPMud38}
