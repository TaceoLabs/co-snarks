pragma circom 2.0.0;

// Large enough that the scalar expansion (2 instructions per iteration) exceeds the
// default ordinary unroll budget, while still fitting the dedicated vectorization cap.
template ElementwiseMulLarge() {
    signal input a[4096];
    signal input b[4096];
    signal output out[4096];

    for (var i = 0; i < 4096; i++) {
        out[i] <== a[i] * b[i];
    }
}

component main = ElementwiseMulLarge();
