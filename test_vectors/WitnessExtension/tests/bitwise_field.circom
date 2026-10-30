pragma circom 2.0.0;

// Bitwise ops on full field elements; results may be >= p before reduction.
template BitwiseField() {
    signal input in[2];
    signal output out[3];
    out[0] <-- in[0] ^ in[1];
    out[1] <-- in[0] | in[1];
    out[2] <-- in[0] ^ 7059779437489773633646340506914701874769131765994106666166191815402473914367; // 2^254 - p
}

component main = BitwiseField();
