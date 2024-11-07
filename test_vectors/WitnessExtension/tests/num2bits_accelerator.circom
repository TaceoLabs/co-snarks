pragma circom 2.1.8;

include "libs/bitify.circom";

template Main() {
    signal input in;
    signal output out[8];

    component num2_bits = Num2Bits(8);
    num2_bits.in <== in;

    out[0] <== num2_bits.out[0];
    out[1] <== num2_bits.out[1];
    out[2] <== num2_bits.out[2];
    out[3] <== num2_bits.out[3];
    out[4] <== num2_bits.out[4];
    out[5] <== num2_bits.out[5];
    out[6] <== num2_bits.out[6];
    out[7] <== num2_bits.out[7];
}

component main = Main(); 
