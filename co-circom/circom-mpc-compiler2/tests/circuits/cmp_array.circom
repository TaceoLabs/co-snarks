pragma circom 2.0.0;

// The Task 8 instruction-shape milestone circuit: `component c[3]` accessed through the
// conforming loop's own promoted mirror register (`i`), not a literal constant -- so both
// the store into `c[i].a`/`c[i].b` and the read of `c[i].out` must resolve their
// subcomponent index (`Instr::InputSub`/`Instr::OutputSub`'s `cmp`) to `ISrc::Reg`, not
// `ISrc::Const`. `unroll.threshold: 0` (set by the test) keeps the loop rolled so `i` stays
// a mirrored `ireg` throughout, rather than folding away via unrolling (which would fold
// `cmp` to `ISrc::Const` for every iteration and defeat the point of this fixture).
template Mul() {
    signal input a;
    signal input b;
    signal output out;
    out <== a * b;
}

template CmpArray() {
    signal input a[3];
    signal input b[3];
    signal output out[3];

    component c[3];
    for (var i = 0; i < 3; i++) {
        c[i] = Mul();
        c[i].a <== a[i];
        c[i].b <== b[i];
        out[i] <== c[i].out;
    }
}

component main = CmpArray();
