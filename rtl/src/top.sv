`timescale 1ns/1ps

/*
/////////////////////////////////////////////////////////////////////////////////////
The AES core FSM will follow this flow:

IDLE
    wait for start
    round = 0
    state = plaintext

INIT_ADDKEY
    state ^= round_key[0]
    round = 1

ROUND
    SubBytes
    ShiftRows
    if round < 10:
        MixColumns
    AddRoundKey(round_key[round])
    
    if round == 10:
        DONE
    else: 
        round += 1
        repeat ROUND

DONE
    ct valid (indicating value on ct[127:0] is stable)
    done = 1 (level rather than pulse; stays high until the next start or reset.)

////////////////////////////////////////////////////////////////////////////////////

The controller FSM will follow this flow:

IDLE
    wait for btnC press

READ
    set the ROM address

LATCH
    capture the key/pt/expected_ct into registers

START_AES
    pulse aes_start (moving AES FSM to INIT_ADDKEY state)

WAIT_AES
    wait for aes_done flag

CHECK
    compute pass/fail; raise led[0], led[1] accordingly

DONE
    hold LEDs; wait for next button press

/////////////////////////////////////////////////////////////////////////////////////
*/

module top(
    input   logic        clk,
    input   logic        btnC,
    input   logic [15:0] sw,    // will make use of the basys3 switches at sw[15:0]
    output  logic [15:0] led    // will also use basys3 LEDs at led[15:0]
);