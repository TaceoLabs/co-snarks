pragma circom 2.0.0;

include "./util.circom";

// MaxPooling2D layer
template MaxPooling2D (nRows, nCols, nChannels, poolSize, strides) {
    signal input in[nRows][nCols][nChannels];
    signal input out[(nRows-poolSize)\strides+1][(nCols-poolSize)\strides+1][nChannels];

    component max[(nRows-poolSize)\strides+1][(nCols-poolSize)\strides+1][nChannels];

    for (var i=0; i<(nRows-poolSize)\strides+1; i++) {
        for (var j=0; j<(nCols-poolSize)\strides+1; j++) {
            for (var k=0; k<nChannels; k++) {
                max[i][j][k] = Max(poolSize*poolSize);
                for (var x=0; x<poolSize; x++) {
                    for (var y=0; y<poolSize; y++) {
                        max[i][j][k].in[x*poolSize+y] <== in[i*strides+x][j*strides+y][k];
                    }
                }
                out[i][j][k] === max[i][j][k].out;
            }
        }
    }
}