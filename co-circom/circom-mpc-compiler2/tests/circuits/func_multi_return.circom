pragma circom 2.0.0;

// minmax(a, b) returns a 2-element array [min(a,b), max(a,b)] -- a ReturnBucket with
// with_size == 2 (Task 7's multi-value-return milestone: RetSrc::Var/eval_index, not
// RetSrc::Reg).
function minmax(a, b) {
    var r[2];
    if (a < b) {
        r[0] = a;
        r[1] = b;
    } else {
        r[0] = b;
        r[1] = a;
    }
    return r;
}

template MinMax() {
    signal input a;
    signal input b;
    signal output out[2];
    var r[2] = minmax(a, b);
    out[0] <-- r[0];
    out[1] <-- r[1];
}

component main = MinMax();
