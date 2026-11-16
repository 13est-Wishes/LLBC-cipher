# LLBC Cipher

## Important Notice

We have identified inconsistencies in the previously released reference implementation of LLBC.

Specifically, the previous implementation used rotation amounts (32, 16), which do not conform to the algorithm specification described in the published IEEE paper. The rotation amounts specified in the paper are (3, 19).

We are currently updating the reference implementation to ensure consistency with the published algorithm specification, using (3, 19) as the correct rotation parameters.

The revised source code, algorithm description, and test vectors will be released after verification.

The previous implementation is retained for research reproducibility. Please refer to the forthcoming updated release for the corrected implementation.
