pragma circom 2.0.0;

// A descending `for` loop indexing a signal array -- non-conforming *by design*
// (`codegen::stmt::detect_conforming`'s docs: the ISA has no `ISub`, only `IAdd`/`IMul`,
// so there is no mirror-update instruction for a decrement). `i` stays a plain
// `Binding::FieldSlot`; every index-position read of it falls through the ordinary
// `ToAddress`/`Instr::ToIndex`/`Dynamic` path, exactly as if no promotion logic existed.
// This circuit's job is proving that fallback path is still semantically correct.
template LoopDescending() {
    signal input a[5];
    signal output out[5];
    for (var i = 4; i >= 0; i--) {
        out[i] <== a[i] + 1;
    }
}

component main = LoopDescending();
