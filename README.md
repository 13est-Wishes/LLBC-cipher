# LLBC-128-128

The previously released reference implementation used rotation amounts `(32, 16)`, which were inconsistent with the encryption/decryption procedure specified in Section II of the paper. This release follows Section II and uses `(3, 19)`. The five plaintext/key pairs from Appendix Table XVI are retained; their published ciphertexts are not used as expected outputs for this specification-aligned implementation.

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
