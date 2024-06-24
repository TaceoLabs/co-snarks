pragma circom 2.0.0;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";

// Checks whether the input is in the range [MIN, MAX] with N bits
template CheckRange(MIN, MAX, N) {
    signal input inp;

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

template Commit2() {
    signal input input0;
    signal input input1;
    signal input r;
    signal output c;

    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== input0;
    poseidon.inputs[1] <== input1;
    poseidon.inputs[2] <== r;
    c <== poseidon.out;
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

template InsertionSortWithID(nInputs, N) {
    signal input inputs[nInputs];
    signal input ids[nInputs];
    signal output sorted[nInputs];
    signal output sorted_id[nInputs];

    var COMPARISONS = nInputs * (nInputs - 1) / 2;
    component lt[COMPARISONS];
    component mux1[COMPARISONS];
    component mux2[COMPARISONS];
    component mux3[COMPARISONS];
    component mux4[COMPARISONS];

    var state[nInputs];
    var state_id[nInputs];

    // initialization
    for (var i = 0; i < nInputs; i++) {
        state[i] = inputs[i];
        state_id[i] = ids[i];
    }

    // actual sorting
    var index = 0;
    for (var i = 1; i < nInputs; i++) {
        var key = state[i];
        var key_id = state_id[i];
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

            // First ID Mux
            mux3[index] = Mux1();
            mux3[index].c[0] <== state_id[j + 1]; // false
            mux3[index].c[1] <== state_id[j]; // true
            mux3[index].s <== cmp;
            state_id[j + 1] = mux3[index].out;

            // Second ID Mux
            mux4[index] = Mux1();
            mux4[index].c[0] <== state_id[j]; // false
            mux4[index].c[1] <== key_id; // true
            mux4[index].s <== cmp;
            state_id[j] = mux4[index].out;

            index += 1;
        }
    }

    for (var i = 0; i < nInputs; i++) {
        sorted[i] <== state[i];
        sorted_id[i] <== state_id[i];
    }
}


template UniqueHighestVal(nInputs, N) {
    signal input inputs[nInputs];
    signal output outp;

    assert(nInputs > 1);
    var DEFAULT = 0;

    // Sort
    var sorted[nInputs];
    component sort = InsertionSort(nInputs, N);
    sort.inputs <== inputs;
    sorted = sort.sorted;

    // Compare consecutive elements
    var cmp[nInputs - 1];
    component eq[nInputs - 1];
    for (var i = 0; i < nInputs - 1; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== sorted[i];
        eq[i].in[1] <== sorted[i + 1];
        cmp[i] = 1 - eq[i].out;
    }

    // Find whether element in array is unique
    signal unique[nInputs];
    unique[0] <== cmp[0];
    for (var i = 1; i < nInputs - 1; i++) {
        unique[i] <== cmp[i - 1] * cmp[i];
    }
    unique[nInputs - 1] <== cmp[nInputs - 2];

    // Find the highest unique element
    component mux1[nInputs];
    component mux2[nInputs - 1];

    mux1[nInputs - 1] = Mux1();
    mux1[nInputs - 1].c[0] <== DEFAULT; // false
    mux1[nInputs - 1].c[1] <== sorted[nInputs - 1]; // true
    mux1[nInputs - 1].s <== unique[nInputs - 1];
    var max = mux1[nInputs - 1].out;
    var found = unique[nInputs - 1];

    for (var i = nInputs - 2; i >= 0; i--) {
        var flag = unique[i] * (1 - found);
        mux1[i] = Mux1();
        mux1[i].c[0] <== max; // false
        mux1[i].c[1] <== sorted[i]; // true
        mux1[i].s <== flag;
        max = mux1[i].out;

        mux2[i] = Mux1();
        mux2[i].c[0] <== found; // false
        mux2[i].c[1] <== flag; // true
        mux2[i].s <== flag;
        found = mux2[i].out;
    }

    outp <== max;
}

template UniqueHighestValWithId(nInputs, N) {
    signal input inputs[nInputs];
    signal input ids[nInputs];
    signal output outp;
    signal output outp_id;

    assert(nInputs > 1);
    var DEFAULT = 0;
    var DEFAULT_ID = 0;

    // Sort
    var sorted[nInputs];
    var sorted_id[nInputs];
    component sort = InsertionSortWithID(nInputs, N);
    sort.inputs <== inputs;
    sort.ids <== ids;
    sorted = sort.sorted;
    sorted_id = sort.sorted_id;

    // Compare consecutive elements
    var cmp[nInputs - 1];
    component eq[nInputs - 1];
    for (var i = 0; i < nInputs - 1; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== sorted[i];
        eq[i].in[1] <== sorted[i + 1];
        cmp[i] = 1 - eq[i].out;
    }

    // Find whether element in array is unique
    signal unique[nInputs];
    unique[0] <== cmp[0];
    for (var i = 1; i < nInputs - 1; i++) {
        unique[i] <== cmp[i - 1] * cmp[i];
    }
    unique[nInputs - 1] <== cmp[nInputs - 2];

    // Find the highest unique element
    component mux1[nInputs];
    component mux2[nInputs - 1];
    component mux3[nInputs];

    mux1[nInputs - 1] = Mux1();
    mux1[nInputs - 1].c[0] <== DEFAULT; // false
    mux1[nInputs - 1].c[1] <== sorted[nInputs - 1]; // true
    mux1[nInputs - 1].s <== unique[nInputs - 1];
    var max = mux1[nInputs - 1].out;

    mux3[nInputs - 1] = Mux1();
    mux3[nInputs - 1].c[0] <== DEFAULT_ID; // false
    mux3[nInputs - 1].c[1] <== sorted_id[nInputs - 1]; // true
    mux3[nInputs - 1].s <== unique[nInputs - 1];
    var max_id = mux3[nInputs - 1].out;

    var found = unique[nInputs - 1];

    for (var i = nInputs - 2; i >= 0; i--) {
        var flag = unique[i] * (1 - found);
        mux1[i] = Mux1();
        mux1[i].c[0] <== max; // false
        mux1[i].c[1] <== sorted[i]; // true
        mux1[i].s <== flag;
        max = mux1[i].out;

        mux3[i] = Mux1();
        mux3[i].c[0] <== max_id; // false
        mux3[i].c[1] <== sorted_id[i]; // true
        mux3[i].s <== flag;
        max_id = mux3[i].out;

        mux2[i] = Mux1();
        mux2[i].c[0] <== found; // false
        mux2[i].c[1] <== flag; // true
        mux2[i].s <== flag;
        found = mux2[i].out;
    }

    outp <== max;
    outp_id <== max_id;
}

