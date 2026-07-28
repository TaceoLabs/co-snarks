pragma circom 2.0.0;

// A compound array index mixing a rolled loop variable with an unrolled one *through a
// subtraction*: circom's front end lowers `i*4 + 3 - k` as one field expression under a
// single ToAddress (unlike pure `i*c + k` shapes, which it emits as address-domain
// arithmetic), exercising codegen::index::eval_field_linear's fold to Addr::Affine.
// Mirrors the shape sha256compression's `w[t][k] <== inp[t*32+31-k]` produces.
template LoopCompoundIndex() {
    signal input a[16];
    signal output out[16];

    for (var i = 0; i < 4; i++) {
        for (var k = 0; k < 4; k++) {
            out[i*4 + k] <== a[i*4 + 3 - k];
        }
    }
}

component main = LoopCompoundIndex();
