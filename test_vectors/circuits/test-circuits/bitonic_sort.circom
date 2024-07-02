pragma circom 2.0.0;

include "../libs/utils.circom";

template Sorter(n, BITS) {
  signal input in[n];
  signal input in_ids[n];
  signal output out[n];
  signal output out_ids[n];

  component sorter = BatcherOddEvenMergeSortWithId(n, BITS);
  sorter.inputs <== in;
  sorter.ids <== in_ids;
  out <== sorter.sorted;
  out_ids <== sorter.sorted_id;
}

component main = Sorter(10, 10);
