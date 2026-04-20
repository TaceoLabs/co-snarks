pragma circom 2.2.2;

include "babyjub.circom";
include "escalarmulany.circom";
include "comparators.circom";
include "compconstant.circom";
include "bitify.circom";

// Utilities for working with the BabyJubJub curve in Circom 2.x, using Twisted Edwards form.
// This file defines:
// - Buses for points and field elements.
// - Checks and helpers for constructing valid points and field elements.
// - Basic group operations (negation, subtraction).
// - Scalar multiplication variants (fixed-base, arbitrary-base, and base-field exponent).

// A point on the BabyJubJub curve.
// See the template BabyJubJubCheck if you want to construct an instance of this bus safely.
bus BabyJubJubPoint {
    signal x;
    signal y;
}

// An element in the base field Fq of BabyJubJub.
// Since Fq is the ScalarField of BN254 (i.e., the field Circom operates over), we do not
// need additional range checks to construct an instance of this bus.
bus BabyJubJubBaseField {
    signal f;
}

// An element in the scalar field Fr of BabyJubJub.
// See the template BabyJubJubIsInFr if you want to construct an instance of this bus safely.
bus BabyJubJubScalarField {
    signal f;
}


// Checks whether two input signals representing the x and y coordinates define a valid
// BabyJubJub point in Twisted Edwards form, i.e., they satisfy:
//
//   a * x^2 + y^2 === 1 + d * x^2 * y^2
//
// where a = 168700 and d = 168696.
//
// If the check succeeds, outputs a BabyJubJubPoint bus tagged twisted_edwards.
template BabyJubJubCheck() {
    signal input x;
    signal input y;
    output BabyJubJubPoint() { twisted_edwards } p;
    BabyCheck()(x,y);
    p.x <== x;
    p.y <== y;
}

// Checks whether two input signals representing the x and y coordinates define a valid
// BabyJubJub point in Twisted Edwards form, i.e., they satisfy:
//
//   a * x^2 + y^2 === 1 + d * x^2 * y^2
//
// where a = 168700 and d = 168696.
//
// Additionally it is checked if the point lies in the prime-order subgroup of BabyJubJub.
//
// If the check succeeds, outputs a BabyJubJubPoint bus tagged twisted_edwards_in subgroup.
// This template is the canonical way to obtain a point that can be safely used with the other templates defined in this file.
//
// Use this method to construct BabyJubJub points in Twisted Edwards form unless you explicitly know what you are doing.
template BabyJubJubCheckAndSubgroupCheck() {
    signal input x;
    signal input y;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } p;
    BabyJubJubPoint() { twisted_edwards } p_on_curve <== BabyJubJubCheck()(x,y);
    BabyJubJubCheckInCorrectSubgroup()(p_on_curve);
    p.x <== x;
    p.y <== y;
}

// Computes the negation -P of a point P in Twisted Edwards form.
// Negation is performed by negating the x-coordinate and keeping y unchanged.
template BabyJubJubNeg() {
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } in;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;
    out.x <== -in.x;
    out.y <== in.y;
}

// Computes the subtraction P - Q for two points in Twisted Edwards form.
// Implemented as P + (-Q).
template BabyJubJubSub() {
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } lhs;
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } rhs;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    BabyJubJubPoint() neg_rhs <== BabyJubJubNeg()(rhs);

    signal (res_x, res_y) <== BabyAdd()(lhs.x,lhs.y,neg_rhs.x,neg_rhs.y);
    out.x <== res_x;
    out.y <== res_y;
}

// Computes the addition P + Q for two points in Twisted Edwards form.
template BabyJubJubAdd() {
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } lhs;
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } rhs;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    signal (res_x, res_y) <== BabyAdd()(lhs.x,lhs.y,rhs.x,rhs.y);
    out.x <== res_x;
    out.y <== res_y;
}

// Performs fixed-base scalar multiplication e·G, where G is the BabyJubJub generator.
// This is a thin wrapper around EscalarMulFix with the hardcoded generator.
template BabyJubJubScalarGenerator() {
    // do with generator (scalarmul fix)
    input BabyJubJubScalarField() e;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    out <== BabyJubJubScalarGeneratorBits()(Num2Bits(251)(e.f));
}

// Performs fixed-base scalar multiplication e·G, where G is the BabyJubJub generator.
// This is a thin wrapper around EscalarMulFix with the hardcoded generator.
template BabyJubJubScalarGeneratorBits() {
    // do with generator (scalarmul fix)
    signal input e[251];
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;
    // The generator of BabyJubJub
    var GENERATOR[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    signal result[2] <== EscalarMulFix(251, GENERATOR)(e);
    out.x <== result[0];
    out.y <== result[1];
}

// Performs fixed-point scalar multiplication e·P for a constant point P.
// When P is known at compile time (e.g., the generator), prefer this over BabyJubJubScalarMul to reduce constraints.
//
// Precondition: This template assumes P is on the curve and belongs to the correct subgroup. It does not perform any checks to verify these conditions.
template BabyJubJubScalarMulFix(BASE) {
    input BabyJubJubScalarField() e;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    out <== BabyJubJubScalarMulFixBits(BASE)(Num2Bits(251)(e.f));
}

// Performs fixed-point scalar multiplication e·P for a constant point P.
// When P is known at compile time (e.g., the generator), prefer this over BabyJubJubScalarMul to reduce constraints.
//
// Precondition: This template assumes P is on the curve and belongs to the correct subgroup. It does not perform any checks to verify these conditions.
template BabyJubJubScalarMulFixBits(BASE) {
    signal input e[251];
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;
    signal result[2] <== EscalarMulFix(251, BASE)(e);
    out.x <== result[0];
    out.y <== result[1];
}


// Performs scalar multiplication e·P for an arbitrary point P in Twisted Edwards form.
//
// Precondition: This template assumes P is on the curve and belongs to the correct subgroup.
// It does not perform any checks to verify these conditions. It tries to ensure this by requiring the input point to be tagged as twisted_edwards_in_subgroup.
template BabyJubJubScalarMul() {
    input BabyJubJubScalarField() e;
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } p;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    out <== BabyJubJubScalarMulBits()(Num2Bits(251)(e.f), p);
}

// Performs scalar multiplication e·P for an arbitrary point P in Twisted Edwards form.
//
// Precondition: This template assumes P is on the curve and belongs to the correct subgroup.
// It does not perform any checks to verify these conditions. It tries to ensure this by requiring the input point to be tagged as twisted_edwards_in_subgroup.
template BabyJubJubScalarMulBits() {
    signal input e[251];
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } p;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    signal result[2] <== EscalarMulAny(251)(e, [p.x,p.y]);
    out.x <== result[0];
    out.y <== result[1];
}


// Performs scalar multiplication e·P where e is provided in the base field Fq of BabyJubJub.
//
// The scalar field Fr has 251 bits. To avoid an explicit modular reduction in-circuit, we use a strict 254-bit decomposition. EscalarMulAny correctly handles the modular reduction internally despite the redundant high bits.
//
// This is useful for verifiers that provide scalars in Fq: reducing them to Fr in-circuit would be more expensive than letting EscalarMulAny handle the modular reduction.
//
// Precondition: This template assumes P is on the curve and belongs to the correct subgroup.
// It does not perform any checks to verify these conditions. It tries to ensure this by requiring the input point to be tagged as twisted_edwards_in_subgroup.
template BabyJubJubScalarMulBaseField() {
    input BabyJubJubBaseField() e;
    input BabyJubJubPoint() { twisted_edwards_in_subgroup } p;
    output BabyJubJubPoint() { twisted_edwards_in_subgroup } out;

    signal bits[254] <== Num2Bits_strict()(e.f);
    // performs the module reduction correctly
    signal result[2] <== EscalarMulAny(254)(bits, [p.x,p.y]);
    out.x <== result[0];
    out.y <== result[1];
}

// Asserts that an input signal lies in the BabyJubJub scalar field Fr.
// If the constraint holds, returns an instance of BabyJubJubScalarField.
// If the input is NOT in Fr, an assertion will fail.
//
// Use this to obtain an element of Fr unless you explicitly know what you are doing.
template BabyJubJubIsInFr() {
    signal input in;
    output BabyJubJubScalarField() out;
    output signal out_bits[251];
    // Prime order of BabyJubJub's scalar field Fr.
    var fr = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    signal bits[253] <== Num2Bits(253)(in);
    // CompConstant enforces <=, so compare against (fr - 1).
    component compConstant = CompConstant(fr - 1);
    for (var i=0; i<253; i++) {
        bits[i] ==> compConstant.in[i];
    }
    compConstant.in[253] <== 0;

    for (var i=0; i<251; i++) {
        out_bits[i] <== bits[i];
    }

    // compConstant.out === 0;
    out.f <== in;
}

// Adds constraints to ensure a provided Twisted Edwards point is NOT the identity element.
// The identity in Twisted Edwards form is (x = 0, y = 1).
// We do not require tags here since this component is valid for all combinations of x/y.
template BabyJubJubCheckNotIdentity() {
    input BabyJubJubPoint() p;
    signal x_check <== IsZero()(p.x);
    signal y_check <== IsZero()(1 - p.y);

    // At least one of the is zero check must be 0. If both are one, it is the identity element which fails the constraint.
    x_check * y_check === 0;
}

// Adds constraints to ensure a provided Twisted Edwards point is the identity element.
// The identity in Twisted Edwards form is (x = 0, y = 1).
// We do not require tags here since this component is valid for all combinations of x/y.
template BabyJubJubCheckIsIdentity() {
    input BabyJubJubPoint() p;

    p.x === 0;
    p.y === 1;
}

// Checks whether a given point in Twisted Edwards form is in the prime-order subgroup
// of BabyJubJub. The simplest way is to multiply the point by r, the characteristic
// (i.e., prime modulus) of the scalar field Fr, and check that the result is the identity.
// Precondition: the input point is required to be on the BabyJubJub curve.
//
// We use a simple double and add ladder for this implementation since the scalar is fixed.
template BabyJubJubCheckInCorrectSubgroup() {
    input BabyJubJubPoint() { twisted_edwards } p;
    // Bit decomposition of Fr.
    var characteristic[251] = [1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1];

    component bitmuls[250];

    // ensure the highest bit is set
    // we can therefore start with accumulator = P
    assert(characteristic[250] == 1);


    for (var i = 249; i >= 0; i--) {
        bitmuls[i] = BitElementTeMulFixSclalar(characteristic[i]);
        bitmuls[i].add_in[0] <== p.x;
        bitmuls[i].add_in[1] <== p.y;
        if (i == 249) {
            bitmuls[i].dbl_in[0] <== p.x;
            bitmuls[i].dbl_in[1] <== p.y;
        } else {
            bitmuls[i].dbl_in[0] <== bitmuls[i+1].out[0];
            bitmuls[i].dbl_in[1] <== bitmuls[i+1].out[1];
        }
    }
    BabyJubJubPoint() { twisted_edwards } result;

    result.x <== bitmuls[0].out[0];
    result.y <== bitmuls[0].out[1];

    // Assert that the resulting point is the identity element.
    BabyJubJubCheckIsIdentity()(result);
}

template BitElementTeMulFixSclalar(bit) {
    assert(bit == 0 || bit == 1);
    signal input dbl_in[2];
    signal input add_in[2];
    signal output out[2];

    component dbl = BabyDbl();
    dbl.x <== dbl_in[0];
    dbl.y <== dbl_in[1];

    if (bit == 1) {
        component add = BabyAdd();
        add.x1 <== dbl.xout;
        add.y1 <== dbl.yout;
        add.x2 <== add_in[0];
        add.y2 <== add_in[1];
        out[0] <== add.xout;
        out[1] <== add.yout;
    } else {
        out[0] <== dbl.xout;
        out[1] <== dbl.yout;
    }
}
