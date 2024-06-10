pragma circom 2.0.0;

include "./SumPooling2D.circom";

// AveragePooling2D layer, poolSize is required to be equal for both dimensions, might lose precision compared to SumPooling2D
template AveragePooling2D (nRows, nCols, nChannels, poolSize, strides) {
    signal input in[nRows][nCols][nChannels];
    signal input out[(nRows-poolSize)\strides+1][(nCols-poolSize)\strides+1][nChannels];
    signal input remainder[(nRows-poolSize)\strides+1][(nCols-poolSize)\strides+1][nChannels];

    component sumPooling2D = SumPooling2D (nRows, nCols, nChannels, poolSize, strides);

    for (var i=0; i<nRows; i++) {
        for (var j=0; j<nCols; j++) {
            for (var k=0; k<nChannels; k++) {
                sumPooling2D.in[i][j][k] <== in[i][j][k];
            }
        }
    }

    for (var i=0; i<(nRows-poolSize)\strides+1; i++) {
        for (var j=0; j<(nCols-poolSize)\strides+1; j++) {
            for (var k=0; k<nChannels; k++) {
                assert(remainder[i][j][k] < poolSize * poolSize);
                out[i][j][k] * poolSize * poolSize + remainder[i][j][k] === sumPooling2D.out[i][j][k];
            }
        }
    }
}