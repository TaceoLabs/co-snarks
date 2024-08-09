pragma circom 2.0.0;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    log("This is a test to see whether the logging work: ", a*b);
    c <== a*b+31561;
 }

 component main = Multiplier2(public [b]);
