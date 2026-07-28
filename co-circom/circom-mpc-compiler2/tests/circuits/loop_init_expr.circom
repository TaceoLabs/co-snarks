pragma circom 2.0.0;

// InsertionSort-shaped nesting: the inner loop's induction variable is initialized from
// an *expression* over the outer loop's variable (`j = i - 1`), not a literal — the shape
// codegen::stmt::eval_const_expr exists for. With the outer loop unrolled, `i` is a
// compile-time constant, the inner init evaluates statically, and the inner descending
// loop (`j >= 0`) conforms and unrolls too; without that evaluation the inner loop falls
// back to runtime field-domain loop control.
template LoopInitExpr() {
    signal input a[4];
    signal output out[4];

    var acc[4];
    for (var k = 0; k < 4; k++) {
        acc[k] = a[k];
    }
    for (var i = 1; i < 4; i++) {
        for (var j = i - 1; j >= 0; j--) {
            acc[j] = acc[j] + acc[j + 1];
        }
    }
    for (var k = 0; k < 4; k++) {
        out[k] <-- acc[k];
        out[k] === acc[k];
    }
}

component main = LoopInitExpr();
