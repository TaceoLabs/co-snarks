pragma circom 2.0.0;

// Straight-line signal- and constant-indexed array access (no loops/branches/functions/
// subcomponents) -- the Task 3 milestone circuit for `codegen::index`'s symbolic address
// evaluation. `out1` exercises a 1D `ToAddress -> Instr::ToIndex -> Dynamic` read (the
// brief's own `in[a]` example); `out2` exercises the same path nested inside
// `AddAddress`/`MulAddress` folding for a 2D array (both dimensions signal-valued, so
// both fold to `Dynamic`, materializing into `IMul`/`IAdd`); `out3` is a constant-indexed
// 2D read, going through the very same `eval_index`/`addr_from_location_rule` path that
// replaced Task 2's constant-only special case (circom's front end folds literal indices
// to a flat offset before this crate ever sees them, so it never actually reaches the
// `AddAddress`/`MulAddress` ComputeBucket shape for `out3` -- see the Task 3 report for
// why the affine-folding algebra's `Const`/`Affine` arms are pure-unit-tested instead).
template DynamicIndex() {
    signal input a[4];
    signal input idx;
    signal input b[2][3];
    signal input i;
    signal input j;
    signal output out1;
    signal output out2;
    signal output out3;
    out1 <-- a[idx];
    out2 <-- b[i][j];
    out3 <== b[0][1];
}

component main = DynamicIndex();
