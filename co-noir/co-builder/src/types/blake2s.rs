use std::{array, marker::PhantomData};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use itertools::izip;

use crate::builder::GenericUltraCircuitBuilder;

use super::{
    blake_util::{BlakeType, BlakeUtils},
    field_ct::{ByteArray, FieldCT},
    plookup::{ColumnIdx, MultiTableId, Plookup},
};

/**
 * Optimizations:
 *
 * 1. use lookup tables for basic XOR operations
 * 2. replace use of uint32 with basic field_t type
 *
 **/
const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const INITIAL_H: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

enum Blake2sConstant {
    Blake2sBlockbytes = 64,
    _Blake2sOutbytes = 32,
    _Blake2sKeybytes = 33,
    _Blake2sSaltbytes = 8,
    _Blake2sPersonalbytes = 9,
}

/**
 * The blake2s_state consists of the following components:
 * h: A 64-byte chain value denoted decomposed as (h_0, h_1, ..., h_7), each h_i
 * is a 32-bit number. It form the first two rows on the internal state matrix v
 * of the compression function G.
 *
 * t: It is a counter (t_0 lsb and t_1 msb) used in the initialization of the
 * internal state v.
 *
 * f: f_0 and f_1 are finalization flags used in the initialization of the
 * internal state v. /  0xfff...ff   if the block processed is the last f_0 = |
 *           \  0x000...00   otherwise
 *           /  0xfff...ff   if the last node is processed in merkle-tree
 * hashing f_1 = |
 *           \  0x000...00   otherwise
 *
 * Further, the internal state 4x4 matrix used by the compression function is
 * denoted by v. The input data is stored in the 16-word message m.
 */
pub(crate) struct Blake2sState<F: PrimeField> {
    h: [FieldCT<F>; 8],
    t: [FieldCT<F>; 2],
    f: [FieldCT<F>; 2],
}

impl<F: PrimeField> Blake2sState<F> {
    pub(crate) fn new() -> Self {
        let h: [FieldCT<F>; 8] = array::from_fn(|_| FieldCT::<F>::zero());
        let t: [FieldCT<F>; 2] = array::from_fn(|_| FieldCT::<F>::zero());
        let f: [FieldCT<F>; 2] = array::from_fn(|_| FieldCT::<F>::zero());
        Self { h, t, f }
    }
}

pub(crate) struct Blake2s<F: PrimeField> {
    phantom_data: PhantomData<F>,
}

impl<F: PrimeField> Blake2s<F> {
    pub(crate) fn blake2s_increment_counter<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        s: &mut Blake2sState<F>,
        inc: u32,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        let inc_scalar = FieldCT::from(F::from(inc));
        s.t[0] = s.t[0].add(&inc_scalar, builder, driver);
        let s_t_val = s.t[0].get_value(builder, driver);
        let to_inc = T::lt(driver, s_t_val, F::from(inc).into())?;
        // AZTEC TODO: Secure!? Think so as inc is known at "compile" time as it's derived
        // from the msg length.
        // TACEO: We open here since this does not get constrained in the original code, sas in the following:
        // const bool to_inc = uint32_t(uint256_t(S.t[0].get_value())) < inc;
        // S.t[1] = S.t[1] + (to_inc ? field_pt(1) : field_pt(0));
        let opened = if T::is_shared(&to_inc) {
            T::open_many(
                driver,
                &[T::get_shared(&to_inc).expect("Already checked it is shared")],
            )?[0]
        } else {
            T::get_public(&to_inc).expect("Already checked it is public")
        };
        s.t[1] = s.t[1].add(&FieldCT::from(opened), builder, driver);
        Ok(())
    }

    pub(crate) fn blake2s_compress<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        s: &mut Blake2sState<F>,
        input: &ByteArray<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        let mut m: [FieldCT<F>; 16] = array::from_fn(|_| FieldCT::<F>::zero());
        let mut v: [FieldCT<F>; 16] = array::from_fn(|_| FieldCT::<F>::zero());

        for (i, m_elem) in m.iter_mut().enumerate() {
            let mut sliced = input.slice(i * 4, 4);
            sliced.reverse();
            *m_elem = sliced.to_field_ct(builder, driver)?;
        }

        v[..8]
            .iter_mut()
            .zip(&s.h)
            .for_each(|(dest, src)| *dest = src.clone());

        v[8] = FieldCT::from(F::from(BLAKE2S_IV[0]));
        v[9] = FieldCT::from(F::from(BLAKE2S_IV[1]));
        v[10] = FieldCT::from(F::from(BLAKE2S_IV[2]));
        v[11] = FieldCT::from(F::from(BLAKE2S_IV[3]));

        // Use the lookup tables to perform XORs
        let lookup_1 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXor,
            s.t[0].clone(),
            FieldCT::from(F::from(BLAKE2S_IV[4])),
            true,
        )?;

        v[12] = lookup_1[ColumnIdx::C3][0].clone();

        let lookup_2 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXor,
            s.t[1].clone(),
            FieldCT::from(F::from(BLAKE2S_IV[5])),
            true,
        )?;

        v[13] = lookup_2[ColumnIdx::C3][0].clone();
        let lookup_3 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXor,
            s.f[0].clone(),
            FieldCT::from(F::from(BLAKE2S_IV[6])),
            true,
        )?;

        v[14] = lookup_3[ColumnIdx::C3][0].clone();
        let lookup_4 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXor,
            s.f[1].clone(),
            FieldCT::from(F::from(BLAKE2S_IV[7])),
            true,
        )?;

        v[15] = lookup_4[ColumnIdx::C3][0].clone();

        BlakeUtils::round_fn_lookup(&mut v, &m, 0, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 1, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 2, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 3, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 4, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 5, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 6, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 7, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 8, BlakeType::Blake2, builder, driver)?;
        BlakeUtils::round_fn_lookup(&mut v, &m, 9, BlakeType::Blake2, builder, driver)?;

        // At this point in the algorithm, the elements (v0, v1, v2, v3) and (v8, v9,
        // v10, v11) in the state matrix 'v' can be 'overflowed' i.e. contain values >
        // 2^{32}. However we do NOT need to normalize them to be < 2^{32}, the
        // following `read_sequence_from_table` calls correctly constrain the output
        // to be 32-bits

        for i in 0..8 {
            let lookup_a = Plookup::get_lookup_accumulators_ct(
                builder,
                driver,
                MultiTableId::BlakeXor,
                s.h[i].clone(),
                v[i].clone(),
                true,
            )?;
            let lookup_b = Plookup::get_lookup_accumulators_ct(
                builder,
                driver,
                MultiTableId::BlakeXor,
                lookup_a[ColumnIdx::C3][0].clone(),
                v[i + 8].clone(),
                true,
            )?;
            s.h[i] = lookup_b[ColumnIdx::C3][0].clone();
        }
        Ok(())
    }

    pub(crate) fn blake2s<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        s: &mut Blake2sState<F>,
        input: &ByteArray<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<()> {
        let mut offset = 0;
        let mut size = input.values.len();
        while size > Blake2sConstant::Blake2sBlockbytes as usize {
            Self::blake2s_increment_counter(
                s,
                Blake2sConstant::Blake2sBlockbytes as u32,
                builder,
                driver,
            )?;
            Self::blake2s_compress(
                s,
                &input.slice(offset, Blake2sConstant::Blake2sBlockbytes as usize),
                builder,
                driver,
            )?;
            offset += Blake2sConstant::Blake2sBlockbytes as usize;
            size -= Blake2sConstant::Blake2sBlockbytes as usize;
        }

        // Set last block.
        s.f[0] = FieldCT::from(F::from(u32::MAX));

        let mut final_input = ByteArray::<F>::new();
        let slice = input.slice_from_offset(offset);
        final_input.write(&slice);
        final_input.write(&ByteArray::<F>::default_with_length(
            Blake2sConstant::Blake2sBlockbytes as usize - size,
        ));
        Self::blake2s_increment_counter(s, size as u32, builder, driver)?;
        Self::blake2s_compress(s, &final_input, builder, driver)?;
        Ok(())
    }

    pub(crate) fn blake2s_init<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        input: &ByteArray<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> std::io::Result<ByteArray<F>> {
        let mut s = Blake2sState::<F>::new();

        #[expect(unused_mut)] // TACEO TODO: This is for the linter, remove once its fixed...
        for (mut el, init) in izip!(s.h.iter_mut().take(8), INITIAL_H.iter().take(8)) {
            *el = FieldCT::from(F::from(*init));
        }

        Self::blake2s(&mut s, input, builder, driver)?;

        let mut result = ByteArray::<F>::new();
        for h in &s.h {
            let mut v = ByteArray::<F>::from_field_ct(h, 4, builder, driver)?;
            v.reverse();
            result.write(&v);
        }
        Ok(result)
    }
}
