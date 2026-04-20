pragma circom 2.2.2;

include "libs/range.circom";
include "libs/commit.circom";

template PedersenCommitBitsMain() {
    signal input value_bits[251];
    signal input r_bits[251];

    signal output out_x;
    signal output out_y;

    component c = PedersenCommitBits();

    for (var i = 0; i < 251; i++) {
        c.value_bits[i] <== value_bits[i];
        c.r_bits[i] <== r_bits[i];
    }

    out_x <== c.out.x;
    out_y <== c.out.y;
}

component main = PedersenCommitBitsMain();
