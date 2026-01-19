For the RTL portion of the project, I want to implement the AES128 algorithm on the FPGA hardware.
For the first iteration, I want to hold {key, plaintext, expected_ciphertext} in the basys3 BRAM.

The AES core will have inputs `key[127:0]`, `pt[127:0]`, and `start`. It will have outputs `ct[127:0]`, 
and `done`. I will implement via a FSM. The AES core will be fed inputs, wait for the done flag, and
compare `ct` with expected result. Switches on the basys3 board will be used to select which vector index
to run. The user I/O will have `btnC` to start the test, `sw[?]` to select which vector index to run,
`led[0]` for PASS (ct matches expected ciphertext), and `led[1]` for FAIL (ct does not match expected ciphertext).

Essentially, the user will simply flip a switch to select the {key,plaintext,expected_ciphertext} vector, 
click btnC, and wait for either led0 or led1 to light, indicating either a pass or a fail. The switches will be 
implemented  as binary indices for the vectors stored in the ROM. For example, if no switches are on, vector 0 will 
be chosen. If sw[3] alone is on, then vector 8 will be chosen. Etc. 

For later iterations, I would like to implement some kind of system (perhaps using UART interface) where plaintext
and key are fed in serially and ciphertext is output through the same interface. 