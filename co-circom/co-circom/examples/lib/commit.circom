pragma circom 2.2.2;

include "babyjubjub.circom";

// Does not includes range checks!
template PedersenCommitBits() {
    signal input value_bits[251];
    signal input r_bits[251];
    output BabyJubJubPoint() { twisted_edwards } out;

    component g_value = BabyJubJubScalarGeneratorBits();
    g_value.e <== value_bits;

    // The default h-generator. We generated it from the hashing g.x to the curve using the implementation in this repo.
    var h_x = 18070489056226311699126950111606780081892760427770517382371397914121919205062;
    var h_y = 15271815330304366999180694217454548993927804584117026509847005260140807626286;
    component g_r = BabyJubJubScalarMulFixBits([h_x, h_y]);
    g_r.e <== r_bits;

    component add = BabyJubJubAdd();
    add.lhs <== g_value.out;
    add.rhs <== g_r.out;
    out <== add.out;
}