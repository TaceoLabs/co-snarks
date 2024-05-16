pragma circom 2.0.0;

include "poseidon.circom";

template PoseidonHasher() {
    signal input in;
    signal output out;

    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== in;
    out <== poseidon.out;
}

component main = PoseidonHasher();
