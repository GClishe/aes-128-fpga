This directory contains Python-specific test code used to verify the correctness
of the Python AES-128 reference implementation.

Test scripts in this directory load test vectors from the top-level `vectors/`
directory and assert that the Python implementation produces the expected
ciphertext outputs. These tests serve to validate the Python code itself and to
establish it as a trusted reference model for later C++ and RTL implementations.

To run the the tests, open terminal and navigate to repo root. Run `python -m pytest`