#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROUNDS 20u
#define RC0_32 UINT32_C(0x243F6A88)
#define MASK64 UINT64_MAX

static const uint8_t S1[16] = {
    0x4, 0x7, 0x5, 0x1, 0xC, 0xB, 0xD, 0x8,
    0xE, 0xF, 0x6, 0x3, 0xA, 0x9, 0x2, 0x0
};

static const uint8_t S2[16] = {
    0xE, 0xC, 0x8, 0x4, 0xB, 0xD, 0x1, 0x5,
    0xF, 0x3, 0xA, 0x2, 0x9, 0x7, 0x0, 0x6
};

static const char *PLAINTEXTS[5] = {
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "0123456789ABCDEFFEDCBA9876543210"
};

static const char *KEYS[5] = {
    "00000000000000000000000000000000",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "00000000000000000000000000000000",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "0123456789ABCDEFFEDCBA9876543210"
};

static uint64_t rol64(uint64_t x, unsigned n) {
    n &= 63u;
    return n == 0u ? x : (x << n) | (x >> (64u - n));
}

static uint32_t rol32(uint32_t x, unsigned n) {
    n &= 31u;
    return n == 0u ? x : (uint32_t)((x << n) | (x >> (32u - n)));
}

static uint16_t rol16(uint16_t x, unsigned n) {
    n &= 15u;
    return n == 0u ? x : (uint16_t)(
        (uint16_t)(x << n) | (uint16_t)(x >> (16u - n))
    );
}

static uint64_t round_constant(unsigned i) {
    return (uint64_t)rol32(RC0_32, i) << 32;
}

static uint64_t load_be64(const uint8_t p[8]) {
    uint64_t x = 0;
    unsigned i;

    for (i = 0; i < 8; ++i)
        x = (x << 8) | p[i];

    return x;
}

static void store_be64(uint8_t p[8], uint64_t x) {
    int i;

    for (i = 7; i >= 0; --i) {
        p[i] = (uint8_t)x;
        x >>= 8;
    }
}

static uint64_t substitute(uint64_t x, const uint8_t box[16]) {
    uint64_t y = 0;
    unsigned i;

    for (i = 0; i < 16; ++i) {
        unsigned shift = 60u - 4u * i;
        y |= (uint64_t)box[(x >> shift) & 0xFu] << shift;
    }

    return y;
}

static uint64_t g64(uint64_t x) {
    uint16_t a = (uint16_t)(x >> 48);
    uint16_t b = (uint16_t)(x >> 32);
    uint16_t c = (uint16_t)(x >> 16);
    uint16_t d = (uint16_t)x;

    uint16_t ra = rol16(a, 3u);
    uint16_t rb = rol16(b, 1u);

    return ((uint64_t)(uint16_t)(ra ^ c) << 48) |
           ((uint64_t)(uint16_t)(rb ^ d) << 32) |
           ((uint64_t)ra << 16) |
           (uint64_t)rb;
}

static uint64_t mixword(uint64_t ml, uint64_t mr) {
    uint64_t x = ml ^ mr;
    uint64_t t0 = rol64(x, 3u) ^ ml;
    uint64_t t1 = rol64(t0, 19u) ^ x;
    uint64_t u = rol64(t1, 3u) ^ t0;

    return (u ^ rol64(u, 19u) ^ t1) & MASK64;
}

static void expand_key(
    const uint8_t key[16],
    uint64_t words[ROUNDS + 1u]
) {
    unsigned j;

    words[0] = load_be64(key);
    words[1] = load_be64(key + 8);

    for (j = 0; j < ROUNDS - 1u; ++j) {
        words[j + 2u] =
            g64(g64(words[j + 1u])) ^
            words[j] ^
            round_constant(j);
    }
}

static void encrypt_block(
    const uint8_t in[16],
    const uint8_t key[16],
    uint8_t out[16]
) {
    uint64_t words[ROUNDS + 1u];
    uint64_t left = load_be64(in);
    uint64_t right = load_be64(in + 8);

    unsigned i;

    expand_key(key, words);

    for (i = 0; i < ROUNDS; ++i) {
        uint64_t t = left ^ words[i + 1u] ^ round_constant(i);

        uint64_t ml = substitute(rol64(left, 3u), S1);
        uint64_t mr = substitute(rol64(t, 19u), S2);

        left = mixword(ml, mr) ^ right ^ words[i];
        right = t;
    }

    store_be64(out, left);
    store_be64(out + 8, right);
}

static int hex_to_bytes(const char *hex, uint8_t out[16]) {
    unsigned i;

    for (i = 0; i < 16; ++i) {
        unsigned value;

        if (sscanf(hex + 2u * i, "%2x", &value) != 1)
            return 0;

        out[i] = (uint8_t)value;
    }

    return hex[32] == '\0';
}

static void print_hex(const uint8_t x[16]) {
    unsigned i;

    for (i = 0; i < 16; ++i)
        printf("%02X", x[i]);

    putchar('\n');
}

int main(void) {
    unsigned i;

    uint8_t pt[16];
    uint8_t key[16];
    uint8_t ct[16];

    for (i = 0; i < 5; ++i) {
        if (!hex_to_bytes(PLAINTEXTS[i], pt) ||
            !hex_to_bytes(KEYS[i], key)) {
            return 1;
        }

        encrypt_block(pt, key, ct);

        printf("Test %u\n", i + 1u);
        printf("Plaintext : %s\n", PLAINTEXTS[i]);
        printf("Key       : %s\n", KEYS[i]);
        printf("Ciphertext: ");

        print_hex(ct);

        if (i != 4u)
            putchar('\n');
    }

    return 0;
}
