pragma circom 2.0.0;

template ControlFlow(R){
  signal input a;
  signal values[4][R];
  signal output b;
  values[0][0] <== a + 1;
  assert(R>1);
  for (var j=1; j<R; j++) {
    if (j<R/2) {
        values[0][j] <== values[0][j-1] + 1;
    } else {
        values[0][j] <== values[0][j-1] + 2;
    }
  }
  values[1][0] <== values[0][R-1] + 1;
  var counter = 1;
  while (counter < R) {
    if (counter<R/2) {
        values[1][counter] <== values[1][counter-1] + 1;
    } else {
        values[1][counter] <== values[1][counter-1] + 2;
    }
    counter += 1;
  } 
  values[2][0] <== values[1][R-1] + 1;
  for (var j=1; j<R; j++) {
    if (j<R/3) {
        values[2][j] <== values[2][j-1] + 1;
    } else if (j<R/2) {
        values[2][j] <== values[2][j-1] + 2;
    } else if (j<R-1) {
        values[2][j] <== values[2][j-1] + 3;
    } else {
        for (var i=0;i<R;i+=2) {
            if (i == 2) {
                values[2][j] <== values[2][j-1] + 4;
            }
        }
    }
  }
  b <== values[2][R-1];
}

component main = ControlFlow(4);