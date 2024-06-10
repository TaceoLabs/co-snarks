pragma circom 2.0.0;

include "./circomlib-matrix/matElemMul.circom";
include "./circomlib-matrix/matElemSum.circom";
include "./util.circom";

// Conv1D layer with valid padding
// n = 10 to the power of the number of decimal places
template Conv1D (nInputs, nChannels, nFilters, kernelSize, strides, n) {
    signal input in[nInputs][nChannels];
    signal input weights[kernelSize][nChannels][nFilters];
    signal input bias[nFilters];
    signal input out[(nInputs-kernelSize)\strides+1][nFilters];
    signal input remainder[(nInputs-kernelSize)\strides+1][nFilters];

    component mul[(nInputs-kernelSize)\strides+1][nChannels][nFilters];
    component elemSum[(nInputs-kernelSize)\strides+1][nChannels][nFilters];
    component sum[(nInputs-kernelSize)\strides+1][nFilters];

    for (var i=0; i<(nInputs-kernelSize)\strides+1; i++) {
        for (var j=0; j<nChannels; j++) {
            for (var k=0; k<nFilters; k++) {
                mul[i][j][k] = matElemMul(kernelSize,1);
                for (var x=0; x<kernelSize; x++) {
                    mul[i][j][k].a[x][0] <== in[i*strides+x][j];
                    mul[i][j][k].b[x][0] <== weights[x][j][k];
                }
                elemSum[i][j][k] = matElemSum(kernelSize,1);
                for (var x=0; x<kernelSize; x++) {
                    elemSum[i][j][k].a[x][0] <== mul[i][j][k].out[x][0];
                }
            }
        }
        for (var k=0; k<nFilters; k++) {
            assert (remainder[i][k] < n);
            sum[i][k] = Sum(nChannels);
            for (var j=0; j<nChannels; j++) {
                sum[i][k].in[j] <== elemSum[i][j][k].out;
            }
            out[i][k] * n + remainder[i][k] === sum[i][k].out + bias[k];
        }
    }
}