pragma circom 2.0.0;

include "./circomlib/sign.circom";
include "./circomlib/bitify.circom";
include "./circomlib/comparators.circom";
include "./circomlib/switcher.circom";

template IsNegative() {
    signal input in;
    signal output out;

    component num2Bits = Num2Bits(254);
    num2Bits.in <== in;
    component sign = Sign();
    
    for (var i = 0; i < 254; i++) {
        sign.in[i] <== num2Bits.out[i];
    }

    out <== sign.sign;
}

/* Currently, IsPositive() treats zero as a positive number for better performance. 
   The following is the correct version which output is 1 when the signal in is a positive number, 0 when it is zero or a negative number

template IsPositive() {
    signal input in;
    signal output out;

    component num2Bits = Num2Bits(254);
    num2Bits.in <== in;
    component sign = Sign();
    
    for (var i = 0; i < 254; i++) {
        sign.in[i] <== num2Bits.out[i];
    }
    
    component isz = IsZero();
    isz.in <== in;
    

    out <== (1 - sign.sign) * (1 - isz.out);
}
*/

template IsPositive() {
    signal input in;
    signal output out;

    component num2Bits = Num2Bits(254);
    num2Bits.in <== in;
    component sign = Sign();
    
    for (var i = 0; i < 254; i++) {
        sign.in[i] <== num2Bits.out[i];
    }

    out <== 1 - sign.sign;
}

template Sum(nInputs) {
    signal input in[nInputs];
    signal output out;

    signal partialSum[nInputs];
    partialSum[0] <== in[0];
    
    for (var i=1; i<nInputs; i++) {
        partialSum[i] <== partialSum[i-1] + in[i];
    }

    out <== partialSum[nInputs-1];
}

template Max(n) {
    signal input in[n];
    signal output out;

    component gts[n];        // store comparators
    component switchers[n+1];  // switcher for comparing maxs

    signal maxs[n+1];

    maxs[0] <== in[0];
    for(var i = 0; i < n; i++) {
        gts[i] = GreaterThan(252); // changed to 252 (maximum) for better compatibility
        switchers[i+1] = Switcher();

        gts[i].in[1] <== maxs[i];
        gts[i].in[0] <== in[i];

        switchers[i+1].sel <== gts[i].out;
        switchers[i+1].L <== maxs[i];
        switchers[i+1].R <== in[i];

        maxs[i+1] <== switchers[i+1].outL;
    }

    out <== maxs[n];
}
