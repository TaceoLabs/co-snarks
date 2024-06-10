pragma circom 2.0.0;

include "./circomlib-matrix/matElemSum.circom";
include "./util.circom";

// SumPooling2D layer, basically AveragePooling2D layer with a constant scaling, more optimized for circom
template SumPooling2D (nRows, nCols, nChannels, poolSize, strides) {
    signal input in[nRows][nCols][nChannels];
    signal output out[(nRows-poolSize)\strides+1][(nCols-poolSize)\strides+1][nChannels];

    component elemSum[(nRows-poolSize)\strides+1][(nCols-poolSize)\strides+1][nChannels];

    for (var i=0; i<(nRows-poolSize)\strides+1; i++) {
        for (var j=0; j<(nCols-poolSize)\strides+1; j++) {
            for (var k=0; k<nChannels; k++) {
                elemSum[i][j][k] = matElemSum(poolSize,poolSize);
                for (var x=0; x<poolSize; x++) {
                    for (var y=0; y<poolSize; y++) {
                        elemSum[i][j][k].a[x][y] <== in[i*strides+x][j*strides+y][k];
                    }
                }
                out[i][j][k] <== elemSum[i][j][k].out;
            }
        }
    }
}