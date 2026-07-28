pragma circom 2.0.0;

// A descending `for` loop indexing a signal array. It can be statically unrolled; with
// unrolling disabled it stays rolled with an ISub-stepped integer mirror and a trip
// counter deciding loop exit. This circuit proves that form is semantically correct.
template LoopDescending() {
    signal input a[5];
    signal output out[5];
    for (var i = 4; i >= 0; i--) {
        out[i] <== a[i] + 1;
    }
}

component main = LoopDescending();
