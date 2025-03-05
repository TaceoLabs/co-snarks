use crate::{prelude::Serialize, types::plookup::FixedBaseParams};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use std::{any::TypeId, sync::OnceLock};

pub(crate) const DEFAULT_DOMAIN_SEPARATOR: &[u8] = "DEFAULT_DOMAIN_SEPARATOR".as_bytes();
const NUM_DEFAULT_GENERATORS: usize = 8;

pub(crate) fn default_generators<C: CurveGroup>() -> &'static [C::Affine; NUM_DEFAULT_GENERATORS] {
    if TypeId::of::<C>() != TypeId::of::<ark_bn254::G1Projective>() {
        let gens = default_generators_bn254();
        // Safety: We checked that the types match
        unsafe {
            std::mem::transmute::<
                &[ark_bn254::G1Affine; NUM_DEFAULT_GENERATORS],
                &[C::Affine; NUM_DEFAULT_GENERATORS],
            >(gens)
        }
    } else if TypeId::of::<C>() != TypeId::of::<ark_grumpkin::Projective>() {
        let gens = default_generators_grumpkin();
        // Safety: We checked that the types match
        unsafe {
            std::mem::transmute::<
                &[ark_grumpkin::Affine; NUM_DEFAULT_GENERATORS],
                &[C::Affine; NUM_DEFAULT_GENERATORS],
            >(gens)
        }
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>())
    }
}

fn default_generators_grumpkin() -> &'static [ark_grumpkin::Affine; NUM_DEFAULT_GENERATORS] {
    static INSTANCE: OnceLock<[ark_grumpkin::Affine; NUM_DEFAULT_GENERATORS]> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        _derive_generators::<ark_grumpkin::Projective>(
            DEFAULT_DOMAIN_SEPARATOR,
            NUM_DEFAULT_GENERATORS,
            0,
        )
        .try_into()
        .expect("Should generate `NUM_DEFAULT_GENERATORS`")
    })
}

fn default_generators_bn254() -> &'static [ark_bn254::G1Affine; NUM_DEFAULT_GENERATORS] {
    static INSTANCE: OnceLock<[ark_bn254::G1Affine; NUM_DEFAULT_GENERATORS]> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        _derive_generators::<ark_bn254::G1Projective>(
            DEFAULT_DOMAIN_SEPARATOR,
            NUM_DEFAULT_GENERATORS,
            0,
        )
        .try_into()
        .expect("Should generate `NUM_DEFAULT_GENERATORS`")
    })
}

pub(crate) fn derive_generators<C: CurveGroup>(
    domain_separator_bytes: &[u8],
    num_generators: usize,
    starting_index: usize,
) -> Vec<C::Affine> {
    // We cache a small number of the default generators so we can reuse them without needing to repeatedly recalculate them.

    let mut result = Vec::with_capacity(num_generators);

    if domain_separator_bytes == DEFAULT_DOMAIN_SEPARATOR && starting_index < NUM_DEFAULT_GENERATORS
    {
        let default_gens = default_generators::<C>();
        for gen in default_gens
            .iter()
            .skip(starting_index)
            .take(num_generators)
        {
            result.push(*gen);
        }
    }

    if result.len() == num_generators {
        return result;
    }

    let new_start_index = starting_index + result.len();
    let new_num_generators = num_generators - result.len();
    let generated =
        _derive_generators::<C>(domain_separator_bytes, new_num_generators, new_start_index);
    result.extend(generated);
    debug_assert_eq!(result.len(), num_generators);
    result
}

fn _derive_generators<C: CurveGroup>(
    domain_separator_bytes: &[u8],
    num_generators: usize,
    starting_index: usize,
) -> Vec<C::Affine> {
    let domain_hash: [u8; blake3::OUT_LEN] = blake3::hash(domain_separator_bytes).into();

    let mut generators = Vec::with_capacity(num_generators);
    let mut generator_preimage = [0u8; 64];
    generator_preimage[..domain_hash.len()].copy_from_slice(&domain_hash);

    for i in starting_index..(num_generators + starting_index) {
        let generator_be_bytes: [u8; 4] = (i as u32).to_be_bytes();
        generator_preimage[32] = generator_be_bytes[0];
        generator_preimage[33] = generator_be_bytes[1];
        generator_preimage[34] = generator_be_bytes[2];
        generator_preimage[35] = generator_be_bytes[3];
        generators.push(hash_to_curve::<C>(&generator_preimage, 0));
    }

    generators
}

fn hash_to_curve<C: CurveGroup>(seed: &[u8], attempt_count: u8) -> C::Affine {
    if TypeId::of::<C>() != TypeId::of::<ark_bn254::G1Projective>() {
        let point = hash_to_curve_bn254(seed, attempt_count);
        // Safety: We checked that the types match
        unsafe { *(&point as *const ark_bn254::G1Affine as *const C::Affine) }
    } else if TypeId::of::<C>() != TypeId::of::<ark_grumpkin::Projective>() {
        let point = hash_to_curve_grumpkin(seed, attempt_count);
        // Safety: We checked that the types match
        unsafe { *(&point as *const ark_grumpkin::Affine as *const C::Affine) }
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>())
    }
}

fn hash_to_curve_grumpkin(seed: &[u8], attempt_count: u8) -> ark_grumpkin::Affine {
    let seed_size = seed.len();
    // expand by 2 bytes to cover incremental hash attempts
    let mut target_seed = seed.to_vec();
    target_seed.extend_from_slice(&[0u8; 2]);

    target_seed[seed_size] = attempt_count;
    target_seed[seed_size + 1] = 0;

    let hash_hi: [u8; blake3::OUT_LEN] = blake3::hash(&target_seed).into();
    target_seed[seed_size + 1] = 1;
    let hash_lo: [u8; blake3::OUT_LEN] = blake3::hash(&target_seed).into();

    let mut hash = hash_hi.to_vec();
    hash.extend_from_slice(&hash_lo);

    // Here we reduce the 512 bit number modulo the base field modulus to calculate `x`
    let x = ark_grumpkin::Fq::from_be_bytes_mod_order(&hash);
    let x = ark_grumpkin::Fq::from_base_prime_field(x);

    if let Some(point) = ark_grumpkin::Affine::get_point_from_x_unchecked(x, false) {
        let parity_bit = hash_hi[0] > 127;
        let y_bit_set = point.y().unwrap().into_bigint().get_bit(0);
        if (parity_bit && !y_bit_set) || (!parity_bit && y_bit_set) {
            -point
        } else {
            point
        }
    } else {
        hash_to_curve_grumpkin(seed, attempt_count + 1)
    }
}

fn hash_to_curve_bn254(seed: &[u8], attempt_count: u8) -> ark_bn254::G1Affine {
    let seed_size = seed.len();
    // expand by 2 bytes to cover incremental hash attempts
    let mut target_seed = seed.to_vec();
    target_seed.extend_from_slice(&[0u8; 2]);

    target_seed[seed_size] = attempt_count;
    target_seed[seed_size + 1] = 0;

    let hash_hi: [u8; blake3::OUT_LEN] = blake3::hash(&target_seed).into();
    target_seed[seed_size + 1] = 1;
    let hash_lo: [u8; blake3::OUT_LEN] = blake3::hash(&target_seed).into();

    let mut hash = hash_hi.to_vec();
    hash.extend_from_slice(&hash_lo);

    // Here we reduce the 512 bit number modulo the base field modulus to calculate `x`
    let x = ark_bn254::Fq::from_be_bytes_mod_order(&hash);
    let x = ark_bn254::Fq::from_base_prime_field(x);

    if let Some(point) = ark_bn254::G1Affine::get_point_from_x_unchecked(x, false) {
        let parity_bit = hash_hi[0] > 127;
        let y_bit_set = point.y().unwrap().into_bigint().get_bit(0);
        if (parity_bit && !y_bit_set) || (!parity_bit && y_bit_set) {
            -point
        } else {
            point
        }
    } else {
        hash_to_curve_bn254(seed, attempt_count + 1)
    }
}

// We need the instance to allow for multiple precomputed for the same NUM_BITS
pub(crate) fn generate_tables<C: CurveGroup, const NUM_BITS: usize, const INSTANCE: usize>(
    input: C::Affine,
) -> &'static [Vec<C::Affine>] {
    if TypeId::of::<C>() != TypeId::of::<ark_grumpkin::Projective>() {
        // Safety: We checked that the types match
        let input = unsafe { *(&input as *const C::Affine as *const ark_grumpkin::Affine) };
        let output = generate_tables_grumpkin::<NUM_BITS, INSTANCE>(input);
        // Safety: We checked that the types match
        unsafe { std::mem::transmute::<&[Vec<ark_grumpkin::Affine>], &[Vec<C::Affine>]>(output) }
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>())
    }
}

// We need the instance to allow for multiple precomputed for the same NUM_BITS
fn generate_tables_grumpkin<const NUM_BITS: usize, const INSTANCE: usize>(
    input: ark_grumpkin::Affine,
) -> &'static [Vec<ark_grumpkin::Affine>] {
    static INSTANCE: OnceLock<Vec<Vec<ark_grumpkin::Affine>>> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let num_tables = FixedBaseParams::get_num_tables_per_multi_table::<NUM_BITS>();
        let mut result = Vec::with_capacity(num_tables);

        // Serialize the input point
        const NUM_64_LIMBS: u32 = ark_grumpkin::Fq::MODULUS_BIT_SIZE.div_ceil(64);
        pub const FIELDSIZE_BYTES: u32 = NUM_64_LIMBS * 8;
        let mut input_buf = Vec::with_capacity(FIELDSIZE_BYTES as usize * 2);

        if let Some((x, y)) = input.xy() {
            Serialize::write_field_element(&mut input_buf, x);
            Serialize::write_field_element(&mut input_buf, y);
        } else {
            for _ in 0..FIELDSIZE_BYTES * 2 {
                input_buf.push(255);
            }
        }

        let offset_generators =
            derive_generators::<ark_grumpkin::Projective>(&input_buf, num_tables, 0);

        let mut accumulator: ark_grumpkin::Projective = input.into();
        for i in 0..num_tables {
            // result.push(generate_single_lookup_table(
            //     accumulator,
            //     offset_generators[i],
            // ));
            todo!("generate_single_lookup_table");
            for j in 0..FixedBaseParams::BITS_PER_TABLE {
                accumulator = accumulator + accumulator;
            }
        }

        todo!();
        result
    })
}
