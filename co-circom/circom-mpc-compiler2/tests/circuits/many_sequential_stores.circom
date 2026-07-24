pragma circom 2.0.0;

// Regression fixture for the per-statement field-register-leak bug: `lower_stmt` used to
// rewind only `cg.iregs`, never `cg.regs`, on every top-level statement — so each of these
// ~20 sequential `var` stores' result register stayed permanently allocated instead of
// being freed once its `Store` instruction was emitted, growing `num_field_regs` with the
// body's *length* rather than its (tiny, constant) maximum expression width. See
// `many_sequential_stores_bounds_field_regs` in `tests/kat_progression.rs`.
template ManySequentialStores() {
    signal input a;
    signal output out;

    var x0 = a;
    var x1 = x0 + 1;
    var x2 = x1 + 1;
    var x3 = x2 + 1;
    var x4 = x3 + 1;
    var x5 = x4 + 1;
    var x6 = x5 + 1;
    var x7 = x6 + 1;
    var x8 = x7 + 1;
    var x9 = x8 + 1;
    var x10 = x9 + 1;
    var x11 = x10 + 1;
    var x12 = x11 + 1;
    var x13 = x12 + 1;
    var x14 = x13 + 1;
    var x15 = x14 + 1;
    var x16 = x15 + 1;
    var x17 = x16 + 1;
    var x18 = x17 + 1;
    var x19 = x18 + 1;
    var x20 = x19 + 1;

    out <== x20;
}

component main = ManySequentialStores();
