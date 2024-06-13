pragma circom 2.0.0;

//this can be dangerous... as it allows non-quadratic constraints..
//think about it some more
/*
function sqrt(x) {
    //stub for accelerator
    return x;
}
*/
include "../libs/pointbits.circom";

template Main() {
    signal input in;
    signal output out;
    var x = sqrt(in);
    out <-- x;
    in === out * out;
}

component main = Main();
