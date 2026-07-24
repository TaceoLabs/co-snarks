pragma circom 2.0.0;

// Non-unit loop-step fixture (Task 7 of the rep3-accel-bench plan): `detect_conforming`
// (`codegen/stmt.rs`) tracks a per-iteration `step` generally, not just `step == 1`, but
// every other loop fixture in this directory (`loop_ascending`, `elementwise_mul`, ...)
// happens to use `i++`. This circuit exercises `i += 3` explicitly, gathering every third
// element of `a` (indices 0, 3, 6, 9) into a compact output array via a *second*,
// ordinary-increment counter `j` -- real "array work" (a strided gather), not just a
// bare read-modify-write. `j` is deliberately not the for-loop's own control variable, so
// `out[j]`'s indexing takes the generic dynamic-addressing path regardless of whether
// `i`'s conforming/Affine path is taken -- only `a[i]`'s indexing is meant to exercise the
// non-unit-step stride.
template LoopStepGather() {
    signal input a[10];
    signal output out[4];

    var j = 0;
    for (var i = 0; i < 10; i += 3) {
        out[j] <== a[i] + 1;
        j++;
    }
}

component main = LoopStepGather();
