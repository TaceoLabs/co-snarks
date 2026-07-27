pragma circom 2.0.0;

template ConstantFolding() {
    signal input in;
    signal output out;

    if (in - in) {
        out <-- in * 99;
    } else {
        out <-- (in * 0) + 7;
    }
    out === 7;
}

component main = ConstantFolding();
