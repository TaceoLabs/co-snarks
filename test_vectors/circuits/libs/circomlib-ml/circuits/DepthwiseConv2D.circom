pragma circom 2.1.1;
// include "./Conv2D.circom";

include "./circomlib/sign.circom";
include "./circomlib/bitify.circom";
include "./circomlib/comparators.circom";
include "./circomlib-matrix/matElemMul.circom";
include "./circomlib-matrix/matElemSum.circom";
include "./util.circom";

// Depthwise Convolution layer with valid padding
// Note that nFilters must be a multiple of nChannels
// n = 10 to the power of the number of decimal places
// component main = DepthwiseConv2D(34, 34, 8, 8, 3, 1);
template DepthwiseConv2D (nRows, nCols, nChannels, nFilters, kernelSize, strides, n) {
    var outRows = (nRows-kernelSize)\strides+1;
    var outCols = (nCols-kernelSize)\strides+1;

    signal input in[nRows][nCols][nChannels];
    signal input weights[kernelSize][kernelSize][nFilters]; // weights are 3d because depth is 1
    signal input bias[nFilters];
    signal input remainder[outRows][outCols][nFilters];

    signal input out[outRows][outCols][nFilters];

    component mul[outRows][outCols][nFilters];
    component elemSum[outRows][outCols][nFilters];

    var valid_groups = nFilters % nChannels;
    var filtersPerChannel = nFilters / nChannels;

    signal groups;
    groups <== valid_groups;
    component is_zero = IsZero();
    is_zero.in <== groups;
    is_zero.out === 1;

    for (var row=0; row<outRows; row++) {
        for (var col=0; col<outCols; col++) {
            for (var filterMultiplier=1; filterMultiplier<=filtersPerChannel; filterMultiplier++) {
                for (var channel=0; channel<nChannels; channel++) {
                    var filter = filterMultiplier*channel;

                    mul[row][col][filter] = matElemMul(kernelSize,kernelSize);

                    for (var x=0; x<kernelSize; x++) {
                        for (var y=0; y<kernelSize; y++) {
                            mul[row][col][filter].a[x][y] <== in[row*strides+x][col*strides+y][channel];
                            mul[row][col][filter].b[x][y] <== weights[x][y][filter];
                        }
                    }

                    elemSum[row][col][filter] = matElemSum(kernelSize,kernelSize);
                    for (var x=0; x<kernelSize; x++) {
                        for (var y=0; y<kernelSize; y++) {
                            elemSum[row][col][filter].a[x][y] <== mul[row][col][filter].out[x][y];
                        }
                    }
                    out[row][col][filter] * n + remainder[row][col][filter] === elemSum[row][col][filter].out + bias[filter];
                }
            }
        }
    }
}
