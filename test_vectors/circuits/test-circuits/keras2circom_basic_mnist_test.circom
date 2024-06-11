pragma circom 2.0.0;

include "../libs/circomlib-ml/circuits/MaxPooling2D.circom";
include "../libs/circomlib-ml/circuits/ArgMax.circom";
include "../libs/circomlib-ml/circuits/Dense.circom";
include "../libs/circomlib-ml/circuits/Flatten2D.circom";

template Model() {
signal input in[28][28][1];
signal input max_pooling2d_out[14][14][1];
signal input flatten_out[196];
signal input dense_weights[196][128];
signal input dense_bias[128];
signal input dense_out[128];
signal input dense_remainder[128];
signal input dense_1_weights[128][10];
signal input dense_1_bias[10];
signal input dense_1_out[10];
signal input dense_1_remainder[10];
signal input dense_1_softmax_out[1];
signal output out[1];

component max_pooling2d = MaxPooling2D(28, 28, 1, 2, 2);
component flatten = Flatten2D(14, 14, 1);
component dense = Dense(196, 128, 10**18);
component dense_1 = Dense(128, 10, 10**18);
component dense_1_softmax = ArgMax(10);

for (var i0 = 0; i0 < 28; i0++) {
    for (var i1 = 0; i1 < 28; i1++) {
        for (var i2 = 0; i2 < 1; i2++) {
            max_pooling2d.in[i0][i1][i2] <== in[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 14; i0++) {
    for (var i1 = 0; i1 < 14; i1++) {
        for (var i2 = 0; i2 < 1; i2++) {
            max_pooling2d.out[i0][i1][i2] <== max_pooling2d_out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 14; i0++) {
    for (var i1 = 0; i1 < 14; i1++) {
        for (var i2 = 0; i2 < 1; i2++) {
            flatten.in[i0][i1][i2] <== max_pooling2d.out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 196; i0++) {
    flatten.out[i0] <== flatten_out[i0];
}
for (var i0 = 0; i0 < 196; i0++) {
    dense.in[i0] <== flatten.out[i0];
}
for (var i0 = 0; i0 < 196; i0++) {
    for (var i1 = 0; i1 < 128; i1++) {
        dense.weights[i0][i1] <== dense_weights[i0][i1];
}}
for (var i0 = 0; i0 < 128; i0++) {
    dense.bias[i0] <== dense_bias[i0];
}
for (var i0 = 0; i0 < 128; i0++) {
    dense.out[i0] <== dense_out[i0];
}
for (var i0 = 0; i0 < 128; i0++) {
    dense.remainder[i0] <== dense_remainder[i0];
}
for (var i0 = 0; i0 < 128; i0++) {
    dense_1.in[i0] <== dense.out[i0];
}
for (var i0 = 0; i0 < 128; i0++) {
    for (var i1 = 0; i1 < 10; i1++) {
        dense_1.weights[i0][i1] <== dense_1_weights[i0][i1];
}}
for (var i0 = 0; i0 < 10; i0++) {
    dense_1.bias[i0] <== dense_1_bias[i0];
}
for (var i0 = 0; i0 < 10; i0++) {
    dense_1.out[i0] <== dense_1_out[i0];
}
for (var i0 = 0; i0 < 10; i0++) {
    dense_1.remainder[i0] <== dense_1_remainder[i0];
}
for (var i0 = 0; i0 < 10; i0++) {
    dense_1_softmax.in[i0] <== dense_1.out[i0];
}
dense_1_softmax.out <== dense_1_softmax_out[0];
out[0] <== dense_1_softmax.out;

}

component main = Model();
