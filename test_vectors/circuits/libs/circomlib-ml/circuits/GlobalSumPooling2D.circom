pragma circom 2.0.0;

include "./circomlib-matrix/matElemSum.circom";
include "./util.circom";

// GlobalSumPooling2D layer, basically GlobalAveragePooling2D layer with a constant scaling, more optimized for circom
template GlobalSumPooling2D (nRows, nCols, nChannels) {
    signal input in[nRows][nCols][nChannels];
    signal output out[nChannels];

    component elemSum[nChannels];

    for (var k=0; k<nChannels; k++) {
        elemSum[k] = matElemSum(nRows,nCols);
        for (var i=0; i<nRows; i++) {
            for (var j=0; j<nCols; j++) {
                elemSum[k].a[i][j] <== in[i][j][k];
            }
        }
        out[k] <== elemSum[k].out;
    }
}