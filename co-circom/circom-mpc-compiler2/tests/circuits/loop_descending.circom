pragma circom 2.0.0;

// A descending `for` loop indexing a signal array. It can be statically unrolled, but
// with unrolling disabled it uses the rolled fallback because the ISA has no `ISub`.
// This circuit proves that fallback path remains semantically correct.
template LoopDescending() {
    signal input a[5];
    signal output out[5];
    for (var i = 4; i >= 0; i--) {
        out[i] <== a[i] + 1;
    }
}

component main = LoopDescending();
