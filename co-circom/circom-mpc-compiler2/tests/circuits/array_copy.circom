pragma circom 2.0.0;

// Regression fixture for the multi-register `LoadN` frame-size bug: `b <== a` lowers to
// a size-2 `LoadBucket` materialized into a register range, which previously reserved
// only one register instead of the whole block (see `tests/kat_progression.rs` for the
// straight-line-only milestone fixture this mirrors).
template ArrayCopy() {
    signal input a[2];
    signal output b[2];
    b <== a;
}

component main = ArrayCopy();
