pragma circom 2.2.2;

include "poseidon2.circom";


template Main(n) {
  signal input a[n];
  signal out[n];
  
  component poseidon2_0 = Poseidon2(n);
  for (var i = 0; i < n; i++) {
    poseidon2_0.in[i] <== a[i];
  }
  for (var i = 0; i < n; i++) {
    out[i] <== poseidon2_0.out[i];
  }

}

component main = Main(2);
