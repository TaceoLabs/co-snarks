pragma circom 2.0.0;

include "../libs/circomlib-ml/circuits/Dense.circom";
include "../libs/circomlib-ml/circuits/ArgMax.circom";
include "../libs/circomlib-ml/circuits/Flatten2D.circom";
include "../libs/circomlib-ml/circuits/Conv2D.circom";
include "../libs/circomlib-ml/circuits/MaxPooling2D.circom";
include "../libs/circomlib-ml/circuits/ReLU.circom";

template Model() {
signal input in[28][28][1];
signal input conv2d_weights[5][5][1][8];
signal input conv2d_bias[8];
signal input conv2d_out[24][24][8];
signal input conv2d_remainder[24][24][8];
signal input conv2d_re_lu_out[24][24][8];
signal input max_pooling2d_out[12][12][8];
signal input conv2d_1_weights[5][5][8][16];
signal input conv2d_1_bias[16];
signal input conv2d_1_out[8][8][16];
signal input conv2d_1_remainder[8][8][16];
signal input conv2d_1_re_lu_out[8][8][16];
signal input max_pooling2d_1_out[2][2][16];
signal input flatten_out[64];
signal input dense_weights[64][10];
signal input dense_bias[10];
signal input dense_out[10];
signal input dense_remainder[10];
signal input dense_softmax_out[1];
signal output out[1];

component conv2d = Conv2D(28, 28, 1, 8, 5, 1, 10**18);
component conv2d_re_lu[24][24][8];
for (var i0 = 0; i0 < 24; i0++) {
    for (var i1 = 0; i1 < 24; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            conv2d_re_lu[i0][i1][i2] = ReLU();
}}}
component max_pooling2d = MaxPooling2D(24, 24, 8, 2, 2);
component conv2d_1 = Conv2D(12, 12, 8, 16, 5, 1, 10**18);
component conv2d_1_re_lu[8][8][16];
for (var i0 = 0; i0 < 8; i0++) {
    for (var i1 = 0; i1 < 8; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            conv2d_1_re_lu[i0][i1][i2] = ReLU();
}}}
component max_pooling2d_1 = MaxPooling2D(8, 8, 16, 3, 3);
component flatten = Flatten2D(2, 2, 16);
component dense = Dense(64, 10, 10**18);
component dense_softmax = ArgMax(10);

for (var i0 = 0; i0 < 28; i0++) {
    for (var i1 = 0; i1 < 28; i1++) {
        for (var i2 = 0; i2 < 1; i2++) {
            conv2d.in[i0][i1][i2] <== in[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 5; i0++) {
    for (var i1 = 0; i1 < 5; i1++) {
        for (var i2 = 0; i2 < 1; i2++) {
            for (var i3 = 0; i3 < 8; i3++) {
                conv2d.weights[i0][i1][i2][i3] <== conv2d_weights[i0][i1][i2][i3];
}}}}
for (var i0 = 0; i0 < 8; i0++) {
    conv2d.bias[i0] <== conv2d_bias[i0];
}
for (var i0 = 0; i0 < 24; i0++) {
    for (var i1 = 0; i1 < 24; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            conv2d.out[i0][i1][i2] <== conv2d_out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 24; i0++) {
    for (var i1 = 0; i1 < 24; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            conv2d.remainder[i0][i1][i2] <== conv2d_remainder[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 24; i0++) {
    for (var i1 = 0; i1 < 24; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            conv2d_re_lu[i0][i1][i2].in <== conv2d.out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 24; i0++) {
    for (var i1 = 0; i1 < 24; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            conv2d_re_lu[i0][i1][i2].out <== conv2d_re_lu_out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 24; i0++) {
    for (var i1 = 0; i1 < 24; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            max_pooling2d.in[i0][i1][i2] <== conv2d_re_lu[i0][i1][i2].out;
}}}
for (var i0 = 0; i0 < 12; i0++) {
    for (var i1 = 0; i1 < 12; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            max_pooling2d.out[i0][i1][i2] <== max_pooling2d_out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 12; i0++) {
    for (var i1 = 0; i1 < 12; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            conv2d_1.in[i0][i1][i2] <== max_pooling2d.out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 5; i0++) {
    for (var i1 = 0; i1 < 5; i1++) {
        for (var i2 = 0; i2 < 8; i2++) {
            for (var i3 = 0; i3 < 16; i3++) {
                conv2d_1.weights[i0][i1][i2][i3] <== conv2d_1_weights[i0][i1][i2][i3];
}}}}
for (var i0 = 0; i0 < 16; i0++) {
    conv2d_1.bias[i0] <== conv2d_1_bias[i0];
}
for (var i0 = 0; i0 < 8; i0++) {
    for (var i1 = 0; i1 < 8; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            conv2d_1.out[i0][i1][i2] <== conv2d_1_out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 8; i0++) {
    for (var i1 = 0; i1 < 8; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            conv2d_1.remainder[i0][i1][i2] <== conv2d_1_remainder[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 8; i0++) {
    for (var i1 = 0; i1 < 8; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            conv2d_1_re_lu[i0][i1][i2].in <== conv2d_1.out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 8; i0++) {
    for (var i1 = 0; i1 < 8; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            conv2d_1_re_lu[i0][i1][i2].out <== conv2d_1_re_lu_out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 8; i0++) {
    for (var i1 = 0; i1 < 8; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            max_pooling2d_1.in[i0][i1][i2] <== conv2d_1_re_lu[i0][i1][i2].out;
}}}
for (var i0 = 0; i0 < 2; i0++) {
    for (var i1 = 0; i1 < 2; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            max_pooling2d_1.out[i0][i1][i2] <== max_pooling2d_1_out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 2; i0++) {
    for (var i1 = 0; i1 < 2; i1++) {
        for (var i2 = 0; i2 < 16; i2++) {
            flatten.in[i0][i1][i2] <== max_pooling2d_1.out[i0][i1][i2];
}}}
for (var i0 = 0; i0 < 64; i0++) {
    flatten.out[i0] <== flatten_out[i0];
}
for (var i0 = 0; i0 < 64; i0++) {
    dense.in[i0] <== flatten.out[i0];
}
for (var i0 = 0; i0 < 64; i0++) {
    for (var i1 = 0; i1 < 10; i1++) {
        dense.weights[i0][i1] <== dense_weights[i0][i1];
}}
for (var i0 = 0; i0 < 10; i0++) {
    dense.bias[i0] <== dense_bias[i0];
}
for (var i0 = 0; i0 < 10; i0++) {
    dense.out[i0] <== dense_out[i0];
}
for (var i0 = 0; i0 < 10; i0++) {
    dense.remainder[i0] <== dense_remainder[i0];
}
for (var i0 = 0; i0 < 10; i0++) {
    dense_softmax.in[i0] <== dense.out[i0];
}
dense_softmax.out <== dense_softmax_out[0];
out[0] <== dense_softmax.out;

}

component main = Model();
