//! Tests for SPDZ gadgets: bit decomposition, comparison, bitwise ops,
//! SHA256, Blake2s, EC curve addition.
//!
//! All tests use two-party LocalNetwork to verify correctness.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, One, PrimeField, UniformRand, Zero};
use mpc_net::local::LocalNetwork;
use mpc_net::Network;
use rand::SeedableRng;
use spdz_core::arithmetic;
use spdz_core::preprocessing::{generate_dummy_preprocessing_with_rng, SpdzPreprocessing};
use spdz_core::types::{combine_field_element, share_field_element, SpdzPrimeFieldShare};
use spdz_core::SpdzState;
use std::thread;

/// Run a two-party computation with correlated preprocessing.
fn run_two_party_with_prep<R0, R1>(
    batch_size: usize,
    f0: impl FnOnce(&LocalNetwork, &mut SpdzState<Fr>) -> R0 + Send + 'static,
    f1: impl FnOnce(&LocalNetwork, &mut SpdzState<Fr>) -> R1 + Send + 'static,
) -> (R0, R1)
where
    R0: Send + 'static,
    R1: Send + 'static,
{
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(batch_size, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        f0(&net0, &mut state)
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        f1(&net1, &mut state)
    });

    (h0.join().unwrap(), h1.join().unwrap())
}

/// Share a value using preprocessing's MAC key
fn share_with_prep(
    val: Fr,
    p0: &dyn SpdzPreprocessing<Fr>,
    p1: &dyn SpdzPreprocessing<Fr>,
) -> [SpdzPrimeFieldShare<Fr>; 2] {
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(99);
    share_field_element(val, mac_key, &mut rng)
}

// ──────────────────── Bit Decomposition ────────────────────

#[test]
fn test_bit_decompose_small_value() {
    // Decompose the value 13 (binary: 1101) into 8 bits
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(1000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let val = Fr::from(13u64); // 1101 in binary
    let [s0, s1] = share_field_element(val, mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::decompose(&s0, 8, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::decompose(&s1, 8, &net1, &mut state).unwrap()
    });

    let bits0 = h0.join().unwrap();
    let bits1 = h1.join().unwrap();

    // Reconstruct each bit and verify
    let expected_bits = [1, 0, 1, 1, 0, 0, 0, 0]; // LSB first: 13 = 1+4+8
    for i in 0..8 {
        let bit_val = combine_field_element(bits0[i], bits1[i]);
        let bit_int: num_bigint::BigUint = bit_val.into();
        eprintln!("bit[{i}] = {bit_int} (expected {})", expected_bits[i]);
        assert_eq!(
            bit_val,
            Fr::from(expected_bits[i] as u64),
            "Bit {i} should be {}",
            expected_bits[i]
        );
    }
}

#[test]
fn test_bit_decompose_recompose() {
    // Decompose then recompose should give back the original value
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(1000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let val = Fr::from(12345u64);
    let [s0, s1] = share_field_element(val, mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        let bits = spdz_core::gadgets::bits::decompose(&s0, 32, &net0, &mut state).unwrap();
        // Recompose
        let mut recomposed = SpdzPrimeFieldShare::zero_share();
        let mut power = Fr::one();
        for bit in &bits {
            recomposed += *bit * power;
            power.double_in_place();
        }
        recomposed
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        let bits = spdz_core::gadgets::bits::decompose(&s1, 32, &net1, &mut state).unwrap();
        let mut recomposed = SpdzPrimeFieldShare::zero_share();
        let mut power = Fr::one();
        for bit in &bits {
            recomposed += *bit * power;
            power.double_in_place();
        }
        recomposed
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();
    assert_eq!(combine_field_element(r0, r1), val, "Decompose-recompose must roundtrip");
}

// ──────────────────── Equality ────────────────────

#[test]
fn test_equality_true() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let val = Fr::from(42u64);
    let [a0, a1] = share_field_element(val, mac_key, &mut rng);
    let [b0, b1] = share_field_element(val, mac_key, &mut rng); // same value

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::equal(&a0, &b0, 32, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::equal(&a1, &b1, 32, &net1, &mut state).unwrap()
    });

    let eq0 = h0.join().unwrap();
    let eq1 = h1.join().unwrap();
    assert_eq!(combine_field_element(eq0, eq1), Fr::one(), "Equal values should return 1");
}

#[test]
fn test_equality_false() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let [a0, a1] = share_field_element(Fr::from(42u64), mac_key, &mut rng);
    let [b0, b1] = share_field_element(Fr::from(43u64), mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::equal(&a0, &b0, 32, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::equal(&a1, &b1, 32, &net1, &mut state).unwrap()
    });

    let eq0 = h0.join().unwrap();
    let eq1 = h1.join().unwrap();
    assert_eq!(combine_field_element(eq0, eq1), Fr::zero(), "Unequal values should return 0");
}

// ──────────────────── Comparison ────────────────────

#[test]
fn test_greater_than() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(5000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let [a0, a1] = share_field_element(Fr::from(100u64), mac_key, &mut rng);
    let [b0, b1] = share_field_element(Fr::from(50u64), mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::greater_than(&a0, &b0, 32, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::greater_than(&a1, &b1, 32, &net1, &mut state).unwrap()
    });

    let gt0 = h0.join().unwrap();
    let gt1 = h1.join().unwrap();
    // 100 >= 50, so the MSB should be 1
    assert_eq!(combine_field_element(gt0, gt1), Fr::one(), "100 >= 50 should be true");
}

// ──────────────────── Bitwise Operations ────────────────────

#[test]
fn test_bitwise_and() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(5000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    // 0b1100 AND 0b1010 = 0b1000 = 8
    let [a0, a1] = share_field_element(Fr::from(12u64), mac_key, &mut rng);
    let [b0, b1] = share_field_element(Fr::from(10u64), mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::bitwise_and(&a0, &b0, 8, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::bitwise_and(&a1, &b1, 8, &net1, &mut state).unwrap()
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();
    assert_eq!(combine_field_element(r0, r1), Fr::from(8u64), "12 AND 10 = 8");
}

#[test]
fn test_bitwise_xor() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(5000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    // 0b1100 XOR 0b1010 = 0b0110 = 6
    let [a0, a1] = share_field_element(Fr::from(12u64), mac_key, &mut rng);
    let [b0, b1] = share_field_element(Fr::from(10u64), mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::bitwise_xor(&a0, &b0, 8, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::bitwise_xor(&a1, &b1, 8, &net1, &mut state).unwrap()
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();
    assert_eq!(combine_field_element(r0, r1), Fr::from(6u64), "12 XOR 10 = 6");
}

// ──────────────────── EC Curve Addition ────────────────────

/// Test EC curve addition using affine formulas on shared coordinates.
/// Uses Fr as the coordinate field (testing the arithmetic, not actual curve ops).
#[test]
fn test_ec_curve_add_arithmetic() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(1000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();

    // Test the affine addition formula on known coordinates:
    // Point 1: (1, 2), Point 2: (3, 4)
    // lambda = (4-2)/(3-1) = 1
    // x3 = 1^2 - 1 - 3 = -3
    // y3 = 1*(1-(-3)) - 2 = 4 - 2 = 2
    let x1 = Fr::from(1u64);
    let y1 = Fr::from(2u64);
    let x2 = Fr::from(3u64);
    let y2 = Fr::from(4u64);

    let expected_x = Fr::from(1u64) - Fr::from(1u64) - Fr::from(3u64); // lambda^2 - x1 - x2
    let expected_y = Fr::from(1u64) * (Fr::from(1u64) - expected_x) - Fr::from(2u64); // lambda*(x1-x3) - y1

    let [x1_0, x1_1] = share_field_element(x1, mac_key, &mut rng);
    let [y1_0, y1_1] = share_field_element(y1, mac_key, &mut rng);
    let [x2_0, x2_1] = share_field_element(x2, mac_key, &mut rng);
    let [y2_0, y2_1] = share_field_element(y2, mac_key, &mut rng);
    let [inf_0a, inf_1a] = share_field_element(Fr::zero(), mac_key, &mut rng);
    let [inf_0b, inf_1b] = share_field_element(Fr::zero(), mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::ec::embedded_curve_add(
            &x1_0, &y1_0, &inf_0a, &x2_0, &y2_0, &inf_0b,
            &net0, &mut state,
        )
        .unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::ec::embedded_curve_add(
            &x1_1, &y1_1, &inf_1a, &x2_1, &y2_1, &inf_1b,
            &net1, &mut state,
        )
        .unwrap()
    });

    let (rx0, ry0, _) = h0.join().unwrap();
    let (rx1, ry1, _) = h1.join().unwrap();

    assert_eq!(combine_field_element(rx0, rx1), expected_x, "EC add: x must match");
    assert_eq!(combine_field_element(ry0, ry1), expected_y, "EC add: y must match");
}

// ──────────────────── is_zero ────────────────────

#[test]
fn test_is_zero_true() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let [s0, s1] = share_field_element(Fr::zero(), mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::is_zero(&s0, 32, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::is_zero(&s1, 32, &net1, &mut state).unwrap()
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();
    assert_eq!(combine_field_element(r0, r1), Fr::one(), "is_zero(0) should be 1");
}

#[test]
fn test_is_zero_false() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(50_000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();
    let [s0, s1] = share_field_element(Fr::from(7u64), mac_key, &mut rng);

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::is_zero(&s0, 32, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::is_zero(&s1, 32, &net1, &mut state).unwrap()
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();
    assert_eq!(combine_field_element(r0, r1), Fr::zero(), "is_zero(7) should be 0");
}

// ──────────────────── SHA256 Compression ────────────────────

#[test]
fn test_sha256_compression_known_vector() {
    // Test SHA256 compression with the standard initial hash values and an empty-ish message.
    // The initial state is the SHA256 IV.
    let iv: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    // Simple message block: first byte = 0x80 (padding for empty message), rest zeros,
    // with length = 0 in the last 8 bytes.
    let mut msg = [0u32; 16];
    msg[0] = 0x80000000; // padding bit

    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(500_000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();

    let state_shares_0: Vec<_> = iv.iter().map(|v| {
        share_field_element(Fr::from(*v as u64), mac_key, &mut rng)[0]
    }).collect();
    let state_shares_1: Vec<_> = iv.iter().map(|v| {
        share_field_element(Fr::from(*v as u64), mac_key, &mut rng)[1]
    }).collect();

    // Actually we need CORRELATED shares — both parties sharing the SAME value.
    // Let me re-share properly:
    let mut iv_shares_0 = Vec::new();
    let mut iv_shares_1 = Vec::new();
    for v in &iv {
        let [s0, s1] = share_field_element(Fr::from(*v as u64), mac_key, &mut rng);
        iv_shares_0.push(s0);
        iv_shares_1.push(s1);
    }
    let mut msg_shares_0 = Vec::new();
    let mut msg_shares_1 = Vec::new();
    for v in &msg {
        let [s0, s1] = share_field_element(Fr::from(*v as u64), mac_key, &mut rng);
        msg_shares_0.push(s0);
        msg_shares_1.push(s1);
    }

    let iv0: [SpdzPrimeFieldShare<Fr>; 8] = iv_shares_0.try_into().unwrap();
    let iv1: [SpdzPrimeFieldShare<Fr>; 8] = iv_shares_1.try_into().unwrap();
    let msg0: [SpdzPrimeFieldShare<Fr>; 16] = msg_shares_0.try_into().unwrap();
    let msg1: [SpdzPrimeFieldShare<Fr>; 16] = msg_shares_1.try_into().unwrap();

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    // This test is expensive (~25K multiplications) - only run if we have enough preprocessing
    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::yao::sha256_compression(&iv0, &msg0, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::yao::sha256_compression(&iv1, &msg1, &net1, &mut state).unwrap()
    });

    let r0 = h0.join().unwrap();
    let r1 = h1.join().unwrap();

    // Reconstruct and verify against known SHA256("") hash
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let expected: [u32; 8] = [
        0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924,
        0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855,
    ];

    for i in 0..8 {
        let result = combine_field_element(r0[i], r1[i]);
        let result_int: num_bigint::BigUint = result.into();
        let result_u32 = result_int.iter_u32_digits().next().unwrap_or(0);
        assert_eq!(
            result_u32, expected[i],
            "SHA256 output word {i}: got {result_u32:#x}, expected {:#x}",
            expected[i]
        );
    }
}

// ──────────────────── decompose_many batch ────────────────────

#[test]
fn test_decompose_many_batch() {
    let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(42);
    let (p0, p1) = generate_dummy_preprocessing_with_rng::<Fr, _>(5000, &mut rng);
    let mac_key = p0.mac_key_share() + p1.mac_key_share();

    let vals = [Fr::from(5u64), Fr::from(10u64), Fr::from(15u64)];
    let mut shares_0 = Vec::new();
    let mut shares_1 = Vec::new();
    for v in &vals {
        let [s0, s1] = share_field_element(*v, mac_key, &mut rng);
        shares_0.push(s0);
        shares_1.push(s1);
    }

    let mut nets = LocalNetwork::new(2).into_iter();
    let net0 = nets.next().unwrap();
    let net1 = nets.next().unwrap();

    let h0 = thread::spawn(move || {
        let mut state = SpdzState::new(0, Box::new(p0));
        spdz_core::gadgets::bits::decompose_many(&shares_0, 8, &net0, &mut state).unwrap()
    });
    let h1 = thread::spawn(move || {
        let mut state = SpdzState::new(1, Box::new(p1));
        spdz_core::gadgets::bits::decompose_many(&shares_1, 8, &net1, &mut state).unwrap()
    });

    let all_bits_0 = h0.join().unwrap();
    let all_bits_1 = h1.join().unwrap();

    // Verify each value decomposes correctly
    for (val_idx, val) in vals.iter().enumerate() {
        let mut recomposed = Fr::zero();
        let mut power = Fr::one();
        for bit_idx in 0..8 {
            let bit = combine_field_element(all_bits_0[val_idx][bit_idx], all_bits_1[val_idx][bit_idx]);
            recomposed += bit * power;
            power.double_in_place();
        }
        assert_eq!(recomposed, *val, "decompose_many: value {val_idx} must roundtrip");
    }
}
