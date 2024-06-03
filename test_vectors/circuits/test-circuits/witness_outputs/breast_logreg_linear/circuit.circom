pragma circom 2.0.0;

include "../node_modules/circomlib-ml/circuits/Dense.circom";

template Model() {
signal input in[30];
signal input dense_weights[30][1];
signal input dense_bias[1];
signal input dense_out[1];
signal input dense_remainder[1];

component dense = Dense(30, 1, 10**1);

for (var i0 = 0; i0 < 30; i0++) {
    dense.in[i0] <== in[i0];
}
for (var i0 = 0; i0 < 30; i0++) {
    for (var i1 = 0; i1 < 1; i1++) {
        dense.weights[i0][i1] <== dense_weights[i0][i1];
}}
for (var i0 = 0; i0 < 1; i0++) {
    dense.bias[i0] <== dense_bias[i0];
}
for (var i0 = 0; i0 < 1; i0++) {
    dense.out[i0] <== dense_out[i0];
}
for (var i0 = 0; i0 < 1; i0++) {
    dense.remainder[i0] <== dense_remainder[i0];
}

}

component main = Model();
