pragma circom 2.0.0;

// Start of inlined file: "../../../lib/comparators.circom"
/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

// Start of inlined file: "../../../lib/bitify.circom"
/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

// Start of inlined file: "../../../lib/aliascheck.circom"
/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

// Start of inlined file: "../../../lib/compconstant.circom"
/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/


// Returns 1 if in (in binary) > ct

template CompConstant(ct) {
    signal input in[254];
    signal output out;

    signal parts[127];
    signal sout;

    var clsb;
    var cmsb;
    var slsb;
    var smsb;

    var sum=0;

    var b = (1 << 128) -1;
    var a = 1;
    var e = 1;
    var i;

    for (i=0;i<127; i++) {
        clsb = (ct >> (i*2)) & 1;
        cmsb = (ct >> (i*2+1)) & 1;
        slsb = in[i*2];
        smsb = in[i*2+1];

        if ((cmsb==0)&&(clsb==0)) {
            parts[i] <== -b*smsb*slsb + b*smsb + b*slsb;
        } else if ((cmsb==0)&&(clsb==1)) {
            parts[i] <== a*smsb*slsb - a*slsb + b*smsb - a*smsb + a;
        } else if ((cmsb==1)&&(clsb==0)) {
            parts[i] <== b*smsb*slsb - a*smsb + a;
        } else {
            parts[i] <== -a*smsb*slsb + a;
        }

        sum = sum + parts[i];

        b = b -e;
        a = a +e;
        e = e*2;
    }

    sout <== sum;

    component num2bits = Num2Bits(135);

    num2bits.in <== sout;

    out <== num2bits.out[127];
}
// End of inlined file: "../../../lib/compconstant.circom"


template AliasCheck() {

    signal input in[254];

    component  compConstant = CompConstant(-1);

    for (var i=0; i<254; i++) in[i] ==> compConstant.in[i];

    compConstant.out === 0;
}
// End of inlined file: "../../../lib/aliascheck.circom"


template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

template Num2Bits_strict() {
    signal input in;
    signal output out[254];

    component aliasCheck = AliasCheck();
    component n2b = Num2Bits(254);
    in ==> n2b.in;

    for (var i=0; i<254; i++) {
        n2b.out[i] ==> out[i];
        n2b.out[i] ==> aliasCheck.in[i];
    }
}

template Bits2Num(n) {
    signal input in[n];
    signal output out;
    var lc1=0;

    var e2 = 1;
    for (var i = 0; i<n; i++) {
        lc1 += in[i] * e2;
        e2 = e2 + e2;
    }

    lc1 ==> out;
}

template Bits2Num_strict() {
    signal input in[254];
    signal output out;

    component aliasCheck = AliasCheck();
    component b2n = Bits2Num(254);

    for (var i=0; i<254; i++) {
        in[i] ==> b2n.in[i];
        in[i] ==> aliasCheck.in[i];
    }

    b2n.out ==> out;
}

template Num2BitsNeg(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    component isZero;

    isZero = IsZero();

    var neg = n == 0 ? 0 : 2**n - in;

    for (var i = 0; i<n; i++) {
        out[i] <-- (neg >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * 2**i;
    }

    in ==> isZero.in;



    lc1 + isZero.out * 2**n === 2**n - in;
}
// End of inlined file: "../../../lib/bitify.circom"
// Start of inlined file: "../../../lib/binsum.circom"
/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

/*

Binary Sum
==========

This component creates a binary sum componet of ops operands and n bits each operand.

e is Number of carries: Depends on the number of operands in the input.

Main Constraint:
   in[0][0]     * 2^0  +  in[0][1]     * 2^1  + ..... + in[0][n-1]    * 2^(n-1)  +
 + in[1][0]     * 2^0  +  in[1][1]     * 2^1  + ..... + in[1][n-1]    * 2^(n-1)  +
 + ..
 + in[ops-1][0] * 2^0  +  in[ops-1][1] * 2^1  + ..... + in[ops-1][n-1] * 2^(n-1)  +
 ===
   out[0] * 2^0  + out[1] * 2^1 +   + out[n+e-1] *2(n+e-1)

To waranty binary outputs:

    out[0]     * (out[0] - 1) === 0
    out[1]     * (out[0] - 1) === 0
    .
    .
    .
    out[n+e-1] * (out[n+e-1] - 1) == 0

 */


/*
    This function calculates the number of extra bits in the output to do the full sum.
 */

function nbits(a) {
    var n = 1;
    var r = 0;
    while (n-1<a) {
        r++;
        n *= 2;
    }
    return r;
}


template BinSum(n, ops) {
    var nout = nbits((2**n -1)*ops);
    signal input in[ops][n];
    signal output out[nout];

    var lin = 0;
    var lout = 0;

    var k;
    var j;

    var e2;

    e2 = 1;
    for (k=0; k<n; k++) {
        for (j=0; j<ops; j++) {
            lin += in[j][k] * e2;
        }
        e2 = e2 + e2;
    }

    e2 = 1;
    for (k=0; k<nout; k++) {
        out[k] <-- (lin >> k) & 1;

        // Ensure out is binary
        out[k] * (out[k] - 1) === 0;

        lout += out[k] * e2;

        e2 = e2+e2;
    }

    // Ensure the sum;

    lin === lout;
}
// End of inlined file: "../../../lib/binsum.circom"

template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== -in*inv +1;
    in*out === 0;
}


template IsEqual() {
    signal input in[2];
    signal output out;

    component isz = IsZero();

    in[1] - in[0] ==> isz.in;

    isz.out ==> out;
}

template ForceEqualIfEnabled() {
    signal input enabled;
    signal input in[2];

    component isz = IsZero();

    in[1] - in[0] ==> isz.in;

    (1 - isz.out)*enabled === 0;
}

/*
// N is the number of bits the input  have.
// The MSF is the sign bit.
template LessThan(n) {
    signal input in[2];
    signal output out;

    component num2Bits0;
    component num2Bits1;

    component adder;

    adder = BinSum(n, 2);

    num2Bits0 = Num2Bits(n);
    num2Bits1 = Num2BitsNeg(n);

    in[0] ==> num2Bits0.in;
    in[1] ==> num2Bits1.in;

    var i;
    for (i=0;i<n;i++) {
        num2Bits0.out[i] ==> adder.in[0][i];
        num2Bits1.out[i] ==> adder.in[1][i];
    }

    adder.out[n-1] ==> out;
}
*/

template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);

    n2b.in <== in[0]+ (1<<n) - in[1];

    out <== 1-n2b.out[n];
}



// N is the number of bits the input  have.
// The MSF is the sign bit.
template LessEqThan(n) {
    signal input in[2];
    signal output out;

    component lt = LessThan(n);

    lt.in[0] <== in[0];
    lt.in[1] <== in[1]+1;
    lt.out ==> out;
}

// N is the number of bits the input  have.
// The MSF is the sign bit.
template GreaterThan(n) {
    signal input in[2];
    signal output out;

    component lt = LessThan(n);

    lt.in[0] <== in[1];
    lt.in[1] <== in[0];
    lt.out ==> out;
}

// N is the number of bits the input  have.
// The MSF is the sign bit.
template GreaterEqThan(n) {
    signal input in[2];
    signal output out;

    component lt = LessThan(n);

    lt.in[0] <== in[1];
    lt.in[1] <== in[0]+1;
    lt.out ==> out;
}
// End of inlined file: "../../../lib/comparators.circom"
// Start of inlined file: "../../../lib/mux1.circom"
/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

template MultiMux1(n) {
    signal input c[n][2];  // Constants
    signal input s;   // Selector
    signal output out[n];

    for (var i=0; i<n; i++) {

        out[i] <== (c[i][1] - c[i][0])*s + c[i][0];

    }
}

template Mux1() {
    var i;
    signal input c[2];  // Constants
    signal input s;   // Selector
    signal output out;

    component mux = MultiMux1(1);

    for (i=0; i<2; i++) {
        mux.c[0][i] <== c[i];
    }

    s ==> mux.s;

    mux.out[0] ==> out;
}
// End of inlined file: "../../../lib/mux1.circom"


// Checks whether the input is in the range [MIN, MAX] with N bits
template CheckRange(MIN, MAX, N) {
    signal input inp;

    assert(MIN >= 0);
    assert(MIN < MAX);
    assert(N > 0);
    assert((1 << N) > MAX);

    component leq = LessEqThan(N);
    leq.in[0] <== inp;
    leq.in[1] <== MAX;
    leq.out === 1;

    component geq = GreaterEqThan(N);
    geq.in[0] <== inp;
    geq.in[1] <== MIN;
    geq.out === 1;
}

// Swaps if a > b
template CompareSwap(N) {
    signal input a;
    signal input b;
    signal output out_a;
    signal output out_b;

    component gt = GreaterThan(N);
    gt.in[0] <== a;
    gt.in[1] <== b;
    var cmp = gt.out;

    component mux1 = Mux1();
    mux1.c[0] <== a; // false
    mux1.c[1] <== b; // true
    mux1.s <== cmp;
    out_a <== mux1.out;

    component mux2 = Mux1();
    mux2.c[0] <== b; // false
    mux2.c[1] <== a; // true
    mux2.s <== cmp;
    out_b <== mux2.out;
}

template BatcherOddEvenMergeSort(nInputs, N) {
    signal input inputs[nInputs];
    signal output sorted[nInputs];

    var next_power = 1;
    var log_power = 0;
    while (next_power < nInputs) {
        next_power *= 2;
        log_power += 1;
    }
    // This is just an too large upper bound
    var COMPARISONS = next_power * log_power * log_power / 4;
    component compare_swap[COMPARISONS];


    // initialization
    var state[nInputs];
    for (var i = 0; i < nInputs; i++) {
        state[i] = inputs[i];
    }

    var index = 0;
    for (var p = 1; p < nInputs; p *= 2) {
        for (var k = p; k > 0; k \= 2) {
            for (var j = k % p; j + k < nInputs; j += 2 * k) {
                var min = (k < nInputs - j - k) ? k : (nInputs - j - k);
                for (var i = 0; i < min; i++) {
                    if ((i + j) \ (2 * p) == (i + j + k) \ (2 * p)) {
                        compare_swap[index] = CompareSwap(N);
                        compare_swap[index].a <== state[i + j];
                        compare_swap[index].b <== state[i + j + k];
                        state[i + j] = compare_swap[index].out_a;
                        state[i + j + k] = compare_swap[index].out_b;
                        index += 1;
                    }
                }
            }
        }
    }

    for (var i = 0; i < nInputs; i++) {
        sorted[i] <== state[i];
    }
}

template InsertionSort(nInputs, N) {
    signal input inputs[nInputs];
    signal output sorted[nInputs];

    var COMPARISONS = nInputs * (nInputs - 1) / 2;
    component lt[COMPARISONS];
    component mux1[COMPARISONS];
    component mux2[COMPARISONS];

    var state[nInputs];

    // initialization
    for (var i = 0; i < nInputs; i++) {
        state[i] = inputs[i];
    }

    // actual sorting
    var index = 0;
    for (var i = 1; i < nInputs; i++) {
        var key = state[i];
        for (var j = i - 1; j >= 0; j--) {
            // Compare
            lt[index] = LessThan(N);
            lt[index].in[0] <== key;
            lt[index].in[1] <== state[j];
            var cmp = lt[index].out;

            // First Mux
            mux1[index] = Mux1();
            mux1[index].c[0] <== state[j + 1]; // false
            mux1[index].c[1] <== state[j]; // true
            mux1[index].s <== cmp;
            state[j + 1] = mux1[index].out;

            // Second Mux
            mux2[index] = Mux1();
            mux2[index].c[0] <== state[j]; // false
            mux2[index].c[1] <== key; // true
            mux2[index].s <== cmp;
            state[j] = mux2[index].out;

            index += 1;
        }
    }

    for (var i = 0; i < nInputs; i++) {
        sorted[i] <== state[i];
    }
}

component main = BatcherOddEvenMergeSort(100, 16);