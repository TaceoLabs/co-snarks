pragma circom 2.0.0;

template ControlFlow(R){
  signal input a;
  signal values[2][R];
  signal output b;
  values[0][0] <== a + 1;
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
  b <== values[1][R-1];
}

component main = ControlFlow(4);