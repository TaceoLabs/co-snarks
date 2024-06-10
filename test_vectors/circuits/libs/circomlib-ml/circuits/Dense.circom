pragma circom 2.0.0;

include "./circomlib-matrix/matMul.circom";
// Dense layer
// n = 10 to the power of the number of decimal places
template Dense (nInputs, nOutputs, n) {
    signal input in[nInputs];
    signal input weights[nInputs][nOutputs];
    signal input bias[nOutputs];
    signal input out[nOutputs];
    signal input remainder[nOutputs];

    component dot[nOutputs];

    for (var i=0; i<nOutputs; i++) {
        assert (remainder[i] < n);
        dot[i] = matMul(1,nInputs,1);
        
        for (var j=0; j<nInputs; j++) {
            dot[i].a[0][j] <== in[j];
            dot[i].b[j][0] <== weights[j][i];
        }

        out[i] * n + remainder[i] === dot[i].out[0][0] + bias[i];
    }
}