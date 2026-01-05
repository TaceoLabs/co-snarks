pragma circom 2.2.2;

include "poseidon2.circom";


template Main(n) {
  signal input a[n];
  signal output out[n];

  component poseidon2_0 = Poseidon2(n);
  poseidon2_0.in <== a;
  out <== poseidon2_0.out;

}

component main = Main(3);
