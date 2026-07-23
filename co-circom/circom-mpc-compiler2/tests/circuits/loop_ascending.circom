pragma circom 2.0.0;

// A conforming ascending `for` loop indexing a signal array both for its read and its
// write -- the Task 4 milestone circuit for `codegen::stmt::lower_loop`'s conforming
// (induction-variable-promotion) path. `i`'s continue_condition (`i < 5`) and increment
// (`i = i + 1`, the last statement circom's own `for`-to-`while` desugaring places in the
// body) match `detect_conforming`'s pattern exactly, so `i` is promoted: bound to
// `Binding::IReg`, mirrored via `ISet`/`IAdd`, and every index-position read of it
// (`a[i]`/`out[i]`) resolves to `Addr::Affine` instead of a runtime `ToIndex` conversion.
template LoopAscending() {
    signal input a[5];
    signal output out[5];
    for (var i = 0; i < 5; i++) {
        out[i] <== a[i] + 1;
    }
}

component main = LoopAscending();
