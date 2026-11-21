#!/usr/bin/env python3
"""LLBC-128-128: encrypt the five plaintext/key pairs from IEEE Table XVI."""

S1 = (0x4, 0x7, 0x5, 0x1, 0xC, 0xB, 0xD, 0x8,
      0xE, 0xF, 0x6, 0x3, 0xA, 0x9, 0x2, 0x0)
S2 = (0xE, 0xC, 0x8, 0x4, 0xB, 0xD, 0x1, 0x5,
      0xF, 0x3, 0xA, 0x2, 0x9, 0x7, 0x0, 0x6)
MASK64 = (1 << 64) - 1
ROUNDS = 20
RC0_32 = 0x243F6A88

INPUTS = (
    ("00000000000000000000000000000000",
     "00000000000000000000000000000000"),
    ("00000000000000000000000000000000",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
    ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "00000000000000000000000000000000"),
    ("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
    ("0123456789ABCDEFFEDCBA9876543210",
     "0123456789ABCDEFFEDCBA9876543210"),
)


def rol(x: int, n: int, width: int = 64) -> int:
    mask = (1 << width) - 1
    n %= width
    x &= mask
    if n == 0:
        return x
    return ((x << n) | (x >> (width - n))) & mask


def round_constant(i: int) -> int:
    return rol(RC0_32, i, 32) << 32


def substitute(x: int, box: tuple[int, ...]) -> int:
    y = 0
    for pos in range(16):
        shift = 60 - 4 * pos
        y |= box[(x >> shift) & 0xF] << shift
    return y


def g64(x: int) -> int:
    a = (x >> 48) & 0xFFFF
    b = (x >> 32) & 0xFFFF
    c = (x >> 16) & 0xFFFF
    d = x & 0xFFFF
    ra = rol(a, 3, 16)
    rb = rol(b, 1, 16)
    return (((ra ^ c) << 48) | ((rb ^ d) << 32) |
            (ra << 16) | rb)


def mixword(ml: int, mr: int) -> int:
    x = ml ^ mr
    t0 = rol(x, 3) ^ ml
    t1 = rol(t0, 19) ^ x
    u = rol(t1, 3) ^ t0
    return (u ^ rol(u, 19) ^ t1) & MASK64


def expand_key(key: bytes) -> list[int]:
    if len(key) != 16:
        raise ValueError("key must be 16 bytes")
    words = [int.from_bytes(key[:8], "big"), int.from_bytes(key[8:], "big")]
    for j in range(ROUNDS - 1):
        words.append(g64(g64(words[j + 1])) ^ words[j] ^ round_constant(j))
    return words


def encrypt(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    words = expand_key(key)
    left = int.from_bytes(block[:8], "big")
    right = int.from_bytes(block[8:], "big")
    for i in range(ROUNDS):
        t = left ^ words[i + 1] ^ round_constant(i)
        ml = substitute(rol(left, 3), S1)
        mr = substitute(rol(t, 19), S2)
        left, right = mixword(ml, mr) ^ right ^ words[i], t
    return left.to_bytes(8, "big") + right.to_bytes(8, "big")


def main() -> None:
    for i, (pt_hex, key_hex) in enumerate(INPUTS, 1):
        pt = bytes.fromhex(pt_hex)
        key = bytes.fromhex(key_hex)
        ct = encrypt(pt, key).hex().upper()
        print(f"Test {i}")
        print(f"Plaintext : {pt_hex}")
        print(f"Key       : {key_hex}")
        print(f"Ciphertext: {ct}")
        if i != len(INPUTS):
            print()


main()
