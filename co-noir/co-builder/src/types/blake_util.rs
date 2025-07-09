use crate::{TranscriptFieldType, prelude::HonkCurve, ultra_builder::GenericUltraCircuitBuilder};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;
use std::marker::PhantomData;

use super::{
    field_ct::FieldCT,
    plookup::{ColumnIdx, MultiTableId, Plookup},
};

pub struct BlakeUtils<F: PrimeField> {
    phantom_data: PhantomData<F>,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlakeType {
    Blake2,
    Blake3,
}
impl<F: PrimeField> BlakeUtils<F> {
    const _BLAKE3_STATE_SIZE: usize = 16;

    const MSG_SCHEDULE_BLAKE3: [[u8; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    const MSG_SCHEDULE_BLAKE2: [[u8; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    /*
     * This is the round function used in Blake2s and Blake3s for UltraPlonk.
     * Inputs: - 16-word state
     *         - 16-word msg
     *         - round numbe
     *         - which_blake to choose Blake2 or Blake3 (false -> Blake2)
     */
    pub(crate) fn round_fn_lookup<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        state: &mut [FieldCT<F>; 16],
        msg: &[FieldCT<F>; 16],
        round: usize,
        which_blake: BlakeType,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let schedule = if which_blake == BlakeType::Blake3 {
            Self::MSG_SCHEDULE_BLAKE3[round]
        } else {
            Self::MSG_SCHEDULE_BLAKE2[round]
        };

        // Mix the columns.
        Self::g_lookup(
            state,
            0,
            4,
            8,
            12,
            &msg[schedule[0] as usize],
            &msg[schedule[1] as usize],
            false,
            builder,
            driver,
        )?;
        Self::g_lookup(
            state,
            1,
            5,
            9,
            13,
            &msg[schedule[2] as usize],
            &msg[schedule[3] as usize],
            false,
            builder,
            driver,
        )?;
        Self::g_lookup(
            state,
            2,
            6,
            10,
            14,
            &msg[schedule[4] as usize],
            &msg[schedule[5] as usize],
            false,
            builder,
            driver,
        )?;
        Self::g_lookup(
            state,
            3,
            7,
            11,
            15,
            &msg[schedule[6] as usize],
            &msg[schedule[7] as usize],
            false,
            builder,
            driver,
        )?;

        // Mix the rows.
        Self::g_lookup(
            state,
            0,
            5,
            10,
            15,
            &msg[schedule[8] as usize],
            &msg[schedule[9] as usize],
            true,
            builder,
            driver,
        )?;
        Self::g_lookup(
            state,
            1,
            6,
            11,
            12,
            &msg[schedule[10] as usize],
            &msg[schedule[11] as usize],
            true,
            builder,
            driver,
        )?;
        Self::g_lookup(
            state,
            2,
            7,
            8,
            13,
            &msg[schedule[12] as usize],
            &msg[schedule[13] as usize],
            true,
            builder,
            driver,
        )?;
        Self::g_lookup(
            state,
            3,
            4,
            9,
            14,
            &msg[schedule[14] as usize],
            &msg[schedule[15] as usize],
            true,
            builder,
            driver,
        )?;
        Ok(())
    }

    /**
     *
     * Function `G' in the Blake2s and Blake3s algorithm which is the core
     * mixing step with additions, xors and right-rotates. This function is
     * used in  UltraPlonk version (with lookup tables).
     *
     * Inputs: - A pointer to a 16-word `state`,
     *         - indices a, b, c, d,
     *         - addition messages x and y
     *         - boolean `last_update` to make sure addition is normalised only in
     *           last update of the state
     *
     * Gate costs per call to function G in lookup case:
     *
     * Read sequence from table = 6 gates per read => 6 * 4 = 24
     * Addition gates = 4 gates
     * Range gates = 2 gates
     * Addition gate for correct output of XOR rotate 12 = 1 gate
     * Normalizing scaling factors = 2 gates
     *
     * Subtotal = 33 gates
     * Outside rounds, each of Blake2s and Blake3s needs 20 and 24 lookup reads respectively.
     *
     * +-----------+--------------+-----------------------+---------------------------+--------------+
     * |           |  calls to G  | gate count for rounds | gate count outside rounds |    total     |
     * |-----------|--------------|-----------------------|---------------------------|--------------|
     * |  Blake2s  |      80      |        80 * 33        |          20 * 6           |     2760     |
     * |  Blake3s  |      56      |        56 * 33        |          24 * 6           |     1992     |
     * +-----------+--------------+-----------------------+---------------------------+--------------+
     *
     * P.S. This doesn't include some more addition gates required after the rounds.
     *      This cost would be negligible as compared to the above gate counts.
     *
     *
     * TODO: Idea for getting rid of extra addition and multiplication gates by tweaking gate structure.
     *       To be implemented later.
     *
     *   q_plookup = 1        | d0 | a0 | d'0 | --  |
     *   q_plookup = 1        | d1 | a1 | d'1 | d2  | <--- set q_arith = 1 and validate d2 - d'5 * scale_factor = 0
     *   q_plookup = 1        | d2 | a2 | d'2 | d'5 |
     *   q_plookup = 1        | d3 | a3 | d'3 | --  |
     *   q_plookup = 1        | d4 | a4 | d'4 | --  |
     *   q_plookup = 1        | d5 | a5 | d'5 | c   |  <---- set q_arith = 1 and validate d'5 * scale_factor + c - c2 =
     * 0. |               | c2  |  <---- this row is start of another lookup table (b ^ c)
     *
     *
     **/
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn g_lookup<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        state: &mut [FieldCT<F>; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        x: &FieldCT<F>,
        y: &FieldCT<F>,
        last_update: bool,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        state[a] = state[a].add_two(&state[b], x, builder, driver);
        let lookup_1 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXorRotate16,
            &state[d],
            &state[a],
            true,
        )?;
        let scaling_factor_1 = F::from(1u32 << (32 - 16));
        state[d] = lookup_1[ColumnIdx::C3][0].multiply(
            &FieldCT::from(scaling_factor_1),
            builder,
            driver,
        )?;

        // c = c + d
        state[c] = state[c].add(&state[d], builder, driver);

        let lookup_2 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXor,
            &state[b],
            &state[c],
            true,
        )?;
        let lookup_output = &lookup_2[ColumnIdx::C3][2];
        let t2_term = FieldCT::from(F::from(1u32 << 12)).multiply(
            &lookup_2[ColumnIdx::C3][2],
            builder,
            driver,
        )?;
        let lookup_output = lookup_output.add(
            &lookup_2[ColumnIdx::C3][0]
                .sub(&t2_term, builder, driver)
                .multiply(&FieldCT::from(F::from(1u32 << 20)), builder, driver)?,
            builder,
            driver,
        );
        state[b] = lookup_output;

        // a = a + b + y
        if !last_update {
            state[a] = state[a].add_two(&state[b], y, builder, driver);
        } else {
            state[a] = Self::add_normalize(
                &state[a],
                &state[b].add(y, builder, driver),
                builder,
                driver,
            )?;
        }

        // d = (d ^ a).ror(8)

        let lookup_3 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXorRotate8,
            &state[d],
            &state[a],
            true,
        )?;
        let scaling_factor_3 = F::from(1u32 << (32 - 8));
        state[d] = lookup_3[ColumnIdx::C3][0].multiply(
            &FieldCT::from(scaling_factor_3),
            builder,
            driver,
        )?;

        // c = c + d
        if !last_update {
            state[c] = state[c].add(&state[d], builder, driver);
        } else {
            state[c] = Self::add_normalize(&state[c], &state[d], builder, driver)?;
        }

        // b = (b ^ c).ror(7)

        let lookup_4 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXorRotate7,
            &state[b],
            &state[c],
            true,
        )?;
        let scaling_factor_4 = F::from(1u32 << (32 - 7));
        state[b] = lookup_4[ColumnIdx::C3][0].multiply(
            &FieldCT::from(scaling_factor_4),
            builder,
            driver,
        )?;
        Ok(())
    }

    /**
     * Addition with normalisation (to ensure the addition is in the scalar field.)
     * Given two field_t elements a and b, this function computes ((a + b) % 2^{32}).
     * Additionally, it checks if the overflow of the addition is a maximum of 3 bits.
     * This is to ascertain that the additions of two 32-bit scalars in blake2s and blake3s do not exceed 35 bits.
     */
    fn add_normalize<
        P: Pairing<ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        a: &FieldCT<F>,
        b: &FieldCT<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<F>> {
        if a.is_constant() && b.is_constant() {
            let a_value = a.get_value(builder, driver);
            let b_value = b.get_value(builder, driver);

            let a_val = T::get_public(&a_value).expect("Already checked it is public");
            let b_val = T::get_public(&b_value).expect("Already checked it is public");

            let sum: BigUint = (a_val + b_val).into();

            let normalized_sum = F::from(sum % (1u64 << 32));

            Ok(FieldCT::from(normalized_sum))
        } else {
            let a_value = a.get_value(builder, driver);
            let b_value = b.get_value(builder, driver);

            let sum = T::add(driver, a_value, b_value);
            let overflow = if T::is_shared(&sum) {
                let sum_val = T::get_shared(&sum).expect("Already checked it is shared");
                // The same function is used in SHA, it also is range constraint to 3-bit there
                FieldCT::from_witness(T::sha256_get_overflow_bit(driver, sum_val)?.into(), builder)
            } else {
                let sum_val: BigUint = T::get_public(&sum)
                    .expect("Already checked it is public")
                    .into();
                let normalized_sum = sum_val.clone().to_u32_digits()[0];
                let overflow = (sum_val - normalized_sum) >> 32;
                FieldCT::from_witness(F::from(overflow).into(), builder)
            };

            overflow.create_range_constraint(3, builder, driver)?;

            let result = a.add_two(
                b,
                &overflow.multiply(&FieldCT::from(-F::from(1u64 << 32)), builder, driver)?,
                builder,
                driver,
            );

            Ok(result)
        }
    }
}
