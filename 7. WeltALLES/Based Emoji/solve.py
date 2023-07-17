#!/usr/bin/env python3
from pwn import *
from pprint import pprint
import z3
from cache import *
from Crypto.Util.number import long_to_bytes


def connect():
    io = remote("emoji.quals2023-kah5Aiv9.satellitesabove.me", 5300)
    io.sendlineafter(
        b"Ticket please:",
        b"[REDACTED]")

    n = io.recvline_contains("🇳   🟰   ".encode(
        "UTF-8")).strip()[len("🇳   🟰   ".encode("UTF-8")):].decode("UTF-8")
    e = io.recvline_contains("🇪   🟰   ".encode(
        "UTF-8")).strip()[len("🇪   🟰   ".encode("UTF-8")):].decode("UTF-8")
    c = io.recvline_contains("🇨   🟰   ".encode(
        "UTF-8")).strip()[len("🇨   🟰   ".encode("UTF-8")):].decode("UTF-8")

    return io, n, e, c


def get_factors(io, emoji):
    io.sendlineafter("🇪 🇽 🇮 🇹".encode("UTF-8"), "1⃣".encode("UTF-8"))
    io.sendlineafter("🇫 🇦 🇨 🇹 🇴 🇷 🇸   🇴 🇫 ❓".encode(
        "UTF-8"), emoji.encode("UTF-8"))
    io.recvline()
    return io.recvline().strip().decode("UTF-8").split("  ")


def get_prime(io, bits):
    io.sendlineafter("🇪 🇽 🇮 🇹".encode("UTF-8"), "2⃣".encode("UTF-8"))
    io.sendlineafter("🇧 🇮 🇹 🇸 ❓".encode("UTF-8"),
                     str(bits).encode("UTF-8") + b"\xe2\x83\xa3")
    return io.recvline_contains("🟰".encode("UTF-8")).strip().decode(
        "UTF-8").split("🟰")[1].lstrip()


def get_rand_factors(io, bits):
    io.sendlineafter("🇪 🇽 🇮 🇹".encode("UTF-8"), "3⃣".encode("UTF-8"))
    io.sendlineafter("🇧 🇮 🇹 🇸 ❓".encode("UTF-8"),
                     str(bits).encode("UTF-8") + b"\xe2\x83\xa3")
    io.recvline()
    return io.recvline().strip().decode("UTF-8").split("  ")


def get_all_models(s, max_count=100) -> bool:
    s.push()
    models = []

    i = 0
    while s.check() == z3.sat:
        i += 1

        if i > max_count:
            raise RuntimeError("Too many solutions")

        model = s.model()
        block = [d() != model[d] for d in model]
        s.add(z3.Or(block))
        models.append(model)

    s.pop()
    return models


def parse_with_mapping(emoji_str: str, mapping) -> int:
    bin_repr = ""
    for emoji in emoji_str:
        bin_repr += format(mapping[emoji], "#07b")[2:]
        assert (len(bin_repr) % 5 == 0)

    return int(bin_repr, 2)


def decrypt_with_model(emojis, vars, model, n, e, c):
    mapping = {k: model[vars[k]].as_long() for k in emojis}
    n = parse_with_mapping(n, mapping)
    e = parse_with_mapping(e, mapping)
    c = parse_with_mapping(c, mapping)
    return long_to_bytes(pow(c, e, n))[::-1]


io, n, e, c = connect()
emojis = set(n)
z3Vars = {x: z3.BitVec(x, 5) for x in emojis}
assert (len(z3Vars) == 32)

s = z3.Solver()

# Known values
for k, v in cachedMappings.items():
    s.add(z3Vars[k] == v)

# All are known to be different
for k1, v1 in z3Vars.items():
    for k2, v2 in z3Vars.items():
        if k1 == k2:
            continue
        s.add(v1 != v2)

# Collect all factors
hasNew = False
for k, v in z3Vars.items():
    if k == ZERO:
        continue

    if k in cachedFactors:
        f = cachedFactors[k]
    else:
        hasNew = True
        f = get_factors(io, k)
        cachedFactors[k] = f
        print(f"Factors ({len(cachedFactors)}/31): {k} => {f}")

    # Factor contraints
    for x in f:
        s.add(z3.URem(v, z3Vars[x]) == 0)

if hasNew:
    print("cachedFactors = ", end="")
    pprint(cachedFactors)

# Load cached prime hits
for bitCount, cachedPrimes in cachedPrimeHits.items():
    for cachedPrime in cachedPrimes:
        if len(cachedPrime) == 2:
            cVar = z3.Concat(*[z3Vars[x] for x in cachedPrime])
        else:
            cVar = z3Vars[cachedPrime]
        s.add(z3.Or(*[cVar == x for x in primes[bitCount]]))

# # Find all primes
for i in range(2, 6):
    hits = cachedPrimeHits[i] if i in cachedPrimeHits else set()
    while len(hits) < len(primes[i]):
        prime = get_prime(io, i)
        if prime in hits:
            continue

        hits.add(prime)
        print(f"{i}-bit prime ({len(hits)}/{len(primes[i])}): {prime}")
        s.add(z3.Or([z3Vars[prime] == x for x in primes[i]]))
    if len(hits) > len(cachedPrimeHits.get(i, [])):
        print(f"cachedPrimeHits[{i}] = ", end="")
        pprint(hits)

# Grab top bits of numbers and primes >5 bit
hits = set()
limit = 100
for i in range(6, 10):
    primeHits = cachedPrimeHits[i] if i in cachedPrimeHits else set()
    while len(hits) < (2 ** (i - 5)) - 1:
        f = get_rand_factors(io, i)
        if len(f) == 2:
            for x in f:
                if x == ONE:
                    continue

                cVar = z3.Concat(*[z3Vars[y] for y in x])
                if x in primeHits:
                    continue

                primeHits.add(x)
                print(
                    f"{i}-bit prime ({len(primeHits)}/{len(primes[i])}): {cVar}")
                s.add(z3.Or(*[cVar == x for x in primes[i]]))

                try:
                    models = get_all_models(s, limit)
                    print("Possible solutions: ", len(models))
                    if len(models) == 1:
                        break
                except:
                    print(f"Possible solutions: >{limit}")

        for x in f:
            if len(x) != 2:
                continue

            x = x[0]
            if x in hits:
                continue

            hits.add(x)
            print(f"{i - 5}-bit int ({len(hits)}/{(2 ** (i - 5)) - 1}): {x}")
            s.add(z3.ULT(z3Vars[x], 2**(i - 5)))
            s.add(z3.UGE(z3Vars[x], 2**(i - 6)))
    else:
        if len(primeHits) > len(cachedPrimeHits.get(i, [])):
            print(f"cachedPrimeHits[{i}] = ", end="")
            pprint(primeHits)
        
        continue
    break


models = get_all_models(s)
for model in models:
    decrypted = decrypt_with_model(emojis, z3Vars, model, n, e, c)
    if b"flag" in decrypted:
        print("Flag:", decrypted.decode())
