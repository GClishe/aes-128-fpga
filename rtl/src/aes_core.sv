module aes_core (
    input  logic         clk,
    input  logic         rst,
    input  logic         start,         // 1 cycle pulse; clears done
    input  logic [127:0] key,
    input  logic [127:0] pt,
    output logic [127:0] ct,
    output logic         done           // level to 1 when ct is stable until next start or rst.
);