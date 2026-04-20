pragma circom 2.2.2;

include "aliascheck.circom";
include "comparators.circom";

template range_check_with_output_flag(BITSIZE) {
    assert(BITSIZE <= 254);
    assert(BITSIZE > 0);
    signal input in;
    signal output valid;
    signal output in_bits[BITSIZE];

    // Num2Bits_strict with taceo_precomputation
    component aliasCheck = AliasCheck();
    component n2b = Num2Bits(254);
    in ==> n2b.in;

    for (var i=0; i<254; i++) {
        n2b.out[i] ==> aliasCheck.in[i];
    }
    for (var i=0; i<BITSIZE; i++) {
        in_bits[i] <== n2b.out[i];
    }

    // Sum up all bits above BITSIZE
    // Works since bits are enforced to be 0 or 1 already.
    // Thus this sum cannot overflow and if at least one bit is 1, sum > 0
    var sum = 0;
    for (var i=BITSIZE; i<254; i++) {
        sum += n2b.out[i];
    }

    component isZero = IsZero();
    isZero.in <== sum;
    valid <== isZero.out;
}
