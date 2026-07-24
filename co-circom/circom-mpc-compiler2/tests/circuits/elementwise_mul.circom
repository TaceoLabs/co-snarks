pragma circom 2.0.0;

// Purpose-written elementwise-multiply loop for the Task 5 BinN-fusion milestone test
// (see `tests/kat_progression.rs`): a plain ascending-counter loop whose body is a single
// scalar `Bin(Mul)` per iteration, over an array wide enough (>= 4) that a fully unrolled
// compile has a fusable run.
template ElementwiseMul(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];
    for (var i = 0; i < n; i++) {
        out[i] <== a[i] * b[i];
    }
}

component main = ElementwiseMul(8);
