# LLBC-128-128

The LLBC-128-128 encryption/decryption algorithm is specified in Section II of the paper, using rotation parameters `(3, 19)`.

The rotation parameters `(32, 16)` were used only to generate the ciphertext values in Appendix Table XVI; the algorithm specification in Section II remains unchanged.

The five plaintext/key pairs from Table XVI are retained in this repository. The provided implementations follow Section II using `(3, 19)`, and therefore their ciphertext outputs differ from those originally reported in Table XVI.

## Files

- `llbc128.c` — C encryption test program (five plaintext/key pairs).
- `llbc128.py` — Python encryption test program (the same five pairs).
- `rtl/llbc128.v` — Verilog-2001 encryption/decryption implementation.
- `tests/tb_llbc128.v` — Verilog testbench with 64 embedded encryption/decryption vectors.

## Run

Python:

```bash
python3 llbc128.py
```

C:

```bash
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic llbc128.c -o llbc128
./llbc128
```

## Validation

- The C and Python programs produce identical ciphertexts for all five included plaintext/key pairs.
- The 64-vector RTL testbench was run by the project author in ISE 14.6 / ISim and reported: `PASS: all 64 LLBC-128-128 encryption/decryption vectors`.
