pragma circom 2.0.0;

template Multiplier2(X) {
    signal input a;
    signal input b;
    signal output c;
    log("This is a test to see whether the logging work: ", a*b);
    assert(a * X < 14);
    c <== a*b*X;
    c === a*b*X+32; // this does fail but this is fine
 }

 component main = Multiplier2(17);