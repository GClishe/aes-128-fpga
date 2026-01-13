This directory contains implementation-agnostic AES-128 test vectors used to
verify correctness across all implementations in this repository.

The files in this directory represent the ground-truth behavior of the AES
algorithm and are shared by:
- the Python reference implementation,
- the C++ implementation,
- and the RTL/FPGA testbench.

Vector files are expected to contain keys, plaintexts, and corresponding
ciphertexts in a simple, language-neutral format (e.g., hexadecimal encoding).
Official NIST test vectors as well as randomly generated vectors will be stored
here.

No code should live in this directory.