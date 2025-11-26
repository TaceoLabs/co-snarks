use crate::types::plookup::FixedBaseParams;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, One, PrimeField};
use co_noir_common::{serialize::SerializeC, utils::Utils};
use num_bigint::BigUint;
use std::{any::TypeId, sync::OnceLock};

pub(crate) const DEFAULT_DOMAIN_SEPARATOR: &[u8] = "DEFAULT_DOMAIN_SEPARATOR".as_bytes();
const NUM_DEFAULT_GENERATORS: usize = 8;

pub(crate) fn default_generators<C: CurveGroup>() -> &'static [C::Affine; NUM_DEFAULT_GENERATORS] {
    if TypeId::of::<C>() == TypeId::of::<ark_grumpkin::Projective>() {
        let gens = _default_generators_grumpkin();
        // Safety: We checked that the types match
        unsafe {
            std::mem::transmute::<
                &'static [ark_grumpkin::Affine; NUM_DEFAULT_GENERATORS],
                &'static [C::Affine; NUM_DEFAULT_GENERATORS],
            >(gens)
        }
    } else if TypeId::of::<C>() == TypeId::of::<ark_bn254::G1Projective>() {
        let gens = _default_generators_bn254();
        // Safety: We checked that the types match
        unsafe {
            std::mem::transmute::<
                &[ark_bn254::G1Affine; NUM_DEFAULT_GENERATORS],
                &[C::Affine; NUM_DEFAULT_GENERATORS],
            >(gens)
        }
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>())
    }
}

fn _default_generators_grumpkin() -> &'static [ark_grumpkin::Affine; NUM_DEFAULT_GENERATORS] {
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

fn _default_generators_bn254() -> &'static [ark_bn254::G1Affine; NUM_DEFAULT_GENERATORS] {
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

pub fn derive_generators<C: CurveGroup>(
    domain_separator_bytes: &[u8],
    num_generators: usize,
    starting_index: usize,
) -> Vec<C::Affine> {
    // We cache a small number of the default generators so we can reuse them without needing to repeatedly recalculate them.

    let mut result = Vec::with_capacity(num_generators);

    if domain_separator_bytes == DEFAULT_DOMAIN_SEPARATOR && starting_index < NUM_DEFAULT_GENERATORS
    {
        let default_gens = default_generators::<C>();
        for r#gen in default_gens
            .iter()
            .skip(starting_index)
            .take(num_generators)
        {
            result.push(*r#gen);
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
    if TypeId::of::<C>() == TypeId::of::<ark_grumpkin::Projective>() {
        let point = _hash_to_curve_grumpkin(seed, attempt_count);
        *Utils::downcast(&point).expect("We checked types")
    } else if TypeId::of::<C>() == TypeId::of::<ark_bn254::G1Projective>() {
        let point = _hash_to_curve_bn254(seed, attempt_count);
        *Utils::downcast(&point).expect("We checked types")
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>())
    }
}

fn _hash_to_curve_grumpkin(seed: &[u8], attempt_count: u8) -> ark_grumpkin::Affine {
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
        _hash_to_curve_grumpkin(seed, attempt_count + 1)
    }
}

fn _hash_to_curve_bn254(seed: &[u8], attempt_count: u8) -> ark_bn254::G1Affine {
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
        _hash_to_curve_bn254(seed, attempt_count + 1)
    }
}

pub(crate) fn generate_fixed_base_tables<C: CurveGroup>()
-> &'static [Vec<Vec<C::Affine>>; FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES] {
    if TypeId::of::<C>() == TypeId::of::<ark_grumpkin::Projective>() {
        // Note: Cannot use C directly since I cannot use the `C` type as a const generic parameter for the OnceLock
        static INSTANCE: OnceLock<
            [Vec<Vec<ark_grumpkin::Affine>>; FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES],
        > = OnceLock::new();

        let res = INSTANCE.get_or_init(|| {
            let gens = default_generators::<ark_grumpkin::Projective>();
            let scale =
                ark_grumpkin::Fr::from(BigUint::one() << FixedBaseParams::BITS_PER_LO_SCALAR);
            let lhs_base_point_lo = &gens[0];
            let lhs_base_point_hi = *lhs_base_point_lo * scale;
            let rhs_base_point_lo = &gens[1];
            let rhs_base_point_hi = *rhs_base_point_lo * scale;

            let a = generate_table::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_LO_SCALAR },
            >(lhs_base_point_lo);
            let b = generate_table::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_HI_SCALAR },
            >(&lhs_base_point_hi.into_affine());
            let c = generate_table::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_LO_SCALAR },
            >(rhs_base_point_lo);
            let d = generate_table::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_HI_SCALAR },
            >(&rhs_base_point_hi.into_affine());

            [a, b, c, d]
        });

        // Safety: We checked that the types match
        unsafe {
            std::mem::transmute::<
                &'static [Vec<Vec<ark_grumpkin::Affine>>;
                             FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES],
                &'static [Vec<Vec<C::Affine>>; FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES],
            >(res)
        }
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>())
    }
}

fn generate_table<C: CurveGroup, const NUM_BITS: usize>(input: &C::Affine) -> Vec<Vec<C::Affine>> {
    let num_tables = FixedBaseParams::get_num_tables_per_multi_table::<NUM_BITS>();
    let mut result = Vec::with_capacity(num_tables);

    // Serialize the input point
    let mut input_buf = Vec::with_capacity(SerializeC::<C>::group_size());
    SerializeC::<C>::write_group_element(&mut input_buf, input, true);

    let offset_generators = derive_generators::<C>(&input_buf, num_tables, 0);

    let mut accumulator: C = input.to_owned().into();
    for r#gen in offset_generators.iter().take(num_tables).cloned() {
        result.push(generate_single_lookup_table::<C>(
            &accumulator,
            r#gen.into(),
        ));
        for _ in 0..FixedBaseParams::BITS_PER_TABLE {
            accumulator += accumulator;
        }
    }

    result
}

fn generate_single_lookup_table<C: CurveGroup>(
    base_point: &C,
    offset_generator: C,
) -> Vec<C::Affine> {
    let mut table = Vec::with_capacity(FixedBaseParams::MAX_TABLE_SIZE);

    let mut accumulator = offset_generator;
    for _ in 0..FixedBaseParams::MAX_TABLE_SIZE {
        table.push(accumulator.into());
        accumulator += base_point;
    }
    // BB uses batch normalize here

    table
}

pub(crate) fn fixed_base_table_offset_generators<C: CurveGroup>()
-> &'static [C; FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES] {
    if TypeId::of::<C>() == TypeId::of::<ark_grumpkin::Projective>() {
        // Note: Cannot use C directly since I cannot use the `C` type as a const generic parameter for the OnceLock
        static INSTANCE: OnceLock<
            [ark_grumpkin::Projective; FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES],
        > = OnceLock::new();
        let res = INSTANCE.get_or_init(|| {
            let gens = default_generators::<ark_grumpkin::Projective>();
            let scale =
                ark_grumpkin::Fr::from(BigUint::one() << FixedBaseParams::BITS_PER_LO_SCALAR);
            let lhs_base_point_lo = &gens[0];
            let lhs_base_point_hi = *lhs_base_point_lo * scale;
            let rhs_base_point_lo = &gens[1];
            let rhs_base_point_hi = *rhs_base_point_lo * scale;

            let a = generate_generator_offset::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_LO_SCALAR },
            >(lhs_base_point_lo);
            let b = generate_generator_offset::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_HI_SCALAR },
            >(&lhs_base_point_hi.into_affine());
            let c = generate_generator_offset::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_LO_SCALAR },
            >(rhs_base_point_lo);
            let d = generate_generator_offset::<
                ark_grumpkin::Projective,
                { FixedBaseParams::BITS_PER_HI_SCALAR },
            >(&rhs_base_point_hi.into_affine());

            [a, b, c, d]
        });

        // Safety: We checked that the types match
        unsafe {
            std::mem::transmute::<
                &'static [ark_grumpkin::Projective; FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES],
                &'static [C; FixedBaseParams::NUM_FIXED_BASE_MULTI_TABLES],
            >(res)
        }
    } else {
        panic!("Unsupported curve {}", std::any::type_name::<C>())
    }
}

fn generate_generator_offset<C: CurveGroup, const NUM_BITS: usize>(input: &C::Affine) -> C {
    let num_tables = FixedBaseParams::get_num_tables_per_multi_table::<NUM_BITS>();

    // Serialize the input point
    let mut input_buf = Vec::with_capacity(SerializeC::<C>::group_size());
    SerializeC::<C>::write_group_element(&mut input_buf, input, true);

    let offset_generators = derive_generators::<C>(&input_buf, num_tables, 0);
    let mut acc = C::zero();
    for r#gen in offset_generators {
        acc += r#gen;
    }
    acc
}

pub fn offset_generator_scaled<C: CurveGroup>() -> C::Affine {
    let domain_separator = "ECCVM_OFFSET_GENERATOR";
    let mut domain_bytes = Vec::with_capacity(domain_separator.len());
    for i in domain_separator.chars() {
        domain_bytes.push(i as u8);
    }
    let offset_generator = derive_generators::<C>(&domain_bytes, 1, 0)[0];
    (offset_generator * C::ScalarField::from(BigUint::one() << 124)).into()
}
pub fn offset_generator<C: CurveGroup>(domain_separator: &str) -> C::Affine {
    let mut domain_bytes = Vec::with_capacity(domain_separator.len());
    for i in domain_separator.chars() {
        domain_bytes.push(i as u8);
    }
    derive_generators::<C>(&domain_bytes, 1, 0)[0]
}
