use crate::{types::sha_compression::SHA256, ultra_builder::GenericUltraCircuitBuilder};
use co_noir_common::{honk_curve::HonkCurve, honk_proof::TranscriptFieldType};

use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
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
            builder,
            driver,
        )?;
        Ok(())
    }

    /**
     *
     * Function `G' in the Blake2s and Blake3s algorithm which is the core
     * mixing step with additions, xors and right-rotates. This function is
     * used in  Ultra version (with lookup tables).
     *
     * Inputs: - A pointer to a 16-word `state`,
     *         - indices a, b, c, d,
     *         - addition messages x and y
     *
     * Gate costs per call to function G in lookup case:
     *
     * Read sequence from table = 6 gates per read => 6 * 4 = 24
     * Addition gates = 2 gates
     * Range gates = 2 gates
     * Addition gate for correct output of XOR rotate 12 = 1 gate
     * Normalizing scaling factors = 2 gates
     *
     * Subtotal = 31 gates
     * Outside rounds, each of Blake2s and Blake3s needs 20 and 24 lookup reads respectively.
     *
     * +-----------+--------------+-----------------------+---------------------------+--------------+
     * |           |  calls to G  | gate count for rounds | gate count outside rounds |    total     |
     * |-----------|--------------|-----------------------|---------------------------|--------------|
     * |  Blake2s  |      80      |        80 * 31        |          20 * 6           |     2600     |
     * |  Blake3s  |      56      |        56 * 31        |          24 * 6           |     1880     |
     * +-----------+--------------+-----------------------+---------------------------+--------------+
     *
     * P.S. This doesn't include some more addition gates required after the rounds.
     *      This cost would be negligible as compared to the above gate counts.
     *
     *
     * NOTE: As a future optimization, the following idea can be used for getting rid of extra addition and multiplication
     * gates by tweaking gate structure. To be implemented later.
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
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // For simplicity, state[a] is written as `a' in comments.
        // a = a + b + x
        state[a] = state[a].add_two(&state[b], x, builder, driver);

        // d = (d ^ a).ror(16)
        // Get the lookup accumulator where `lookup_1[ColumnIdx::C3][0]` contains the
        // XORed and rotated (by 16) value scaled by 2^{-16}.
        let lookup_1 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXorRotate16,
            &state[d],
            &state[a],
            true,
        )?;
        // Compute the scaling factor 2^{32-16} = 2^{16} to get the correct rotated value.
        let scaling_factor_1 = F::from(1u32 << (32 - 16));
        // Multiply by the scaling factor to get the final rotated value.
        state[d] = lookup_1[ColumnIdx::C3][0].multiply(
            &FieldCT::from(scaling_factor_1),
            builder,
            driver,
        )?;

        // c = c + d
        state[c] = state[c].add(&state[d], builder, driver);

        // b = (b ^ c).ror(12)
        // Does not require a special XOR_ROTATE_12 table since we can get the correct value
        // by combining values from BLAKE_XOR table itself.
        // Let u = s_0 + 2^6 * s_1 + 2^{12} * s_2 + 2^{18} * s_3 + 2^{24} * s_4 + 2^{30} * s_5
        // be a 32-bit output of XOR, split into slices s_0, s_1, s_2, s_3, s_4 (6-bits each) and s_5 (5-bit).
        // We want to compute ROTATE_12(u) = s_2 + 2^6 * s_3 + 2^{12} * s_4 + 2^{18} * s_5 + 2^{20} * s_0 + 2^{26} * s_1.
        // The BLAKE_XOR table gives:
        // lookup_2[ColumnIdx::C3][0] = s_0 + 2^6 * s_1 + 2^{12} * s_2 + 2^{18} * s_3 + 2^{24} * s_4 + 2^{30} * s_5 = u.
        // lookup_2[ColumnIdx::C3][2] = s_2 + 2^6 * s_3 + 2^{12} * s_4 + 2^{18} * s_5 (i.e., u without s_0 and s_1).
        // Thus, we can compute ROTATE_12(u) as:
        // ROTATE_12(u) = lookup_2[ColumnIdx::C3][2] + (lookup_2[ColumnIdx::C3][0] - 2^{12} * lookup_2[ColumnIdx::C3][2]) *
        // 2^{20}.

        // Get the lookup accumulator for BLAKE_XOR table where lookup_2[ColumnIdx::C3][0] = u.

        let lookup_2 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXor,
            &state[b],
            &state[c],
            true,
        )?;
        // lookup_2[ColumnIdx::C3][2] = s_2 + 2^6 * s_3 + 2^{12} * s_4 + 2^{18} * s_5 (i.e., u without s_0 and s_1).
        let lookup_output = &lookup_2[ColumnIdx::C3][2];
        // Compute 2^{12} * lookup_2[ColumnIdx::C3][2].
        let t2_term = FieldCT::from(F::from(1u32 << 12)).multiply(
            &lookup_2[ColumnIdx::C3][2],
            builder,
            driver,
        )?;
        // Compute the final rotated value as described for ROTATE_12(u) above.
        let lookup_output = lookup_output.add(
            &lookup_2[ColumnIdx::C3][0]
                .sub(&t2_term, builder, driver)
                .multiply(&FieldCT::from(F::from(1u32 << 20)), builder, driver)?,
            builder,
            driver,
        );
        state[b] = lookup_output;

        // a = a + b + y
        state[a] = SHA256::add_normalize_unsafe(
            &state[a],
            &state[b].add(y, builder, driver),
            3,
            builder,
            driver,
        )?;

        // d = (d ^ a).ror(8)
        // Get the lookup accumulator where `lookup_3[ColumnIdx::C3][0]` contains the
        // XORed and rotated (by 8) value scaled by 2^{-24}.
        let lookup_3 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXorRotate8,
            &state[d],
            &state[a],
            true,
        )?;
        // Compute the scaling factor 2^{32-8} = 2^{24} to get the correct rotated value.
        let scaling_factor_3 = F::from(1u32 << (32 - 8));
        // Multiply by the scaling factor to get the final rotated value.
        state[d] = lookup_3[ColumnIdx::C3][0].multiply(
            &FieldCT::from(scaling_factor_3),
            builder,
            driver,
        )?;

        // c = c + d
        state[c] = SHA256::add_normalize_unsafe(&state[c], &state[d], 3, builder, driver)?;

        // b = (b ^ c).ror(7)
        // Get the lookup accumulator where `lookup_4[ColumnIdx::C3][0]` contains the
        // XORed and rotated (by 7) value scaled by 2^{-25}.
        let lookup_4 = Plookup::get_lookup_accumulators_ct(
            builder,
            driver,
            MultiTableId::BlakeXorRotate7,
            &state[b],
            &state[c],
            true,
        )?;
        // Compute the scaling factor 2^{32-7} = 2^{25} to get the correct rotated value.
        let scaling_factor_4 = F::from(1u32 << (32 - 7));
        // Multiply by the scaling factor to get the final rotated value.
        state[b] = lookup_4[ColumnIdx::C3][0].multiply(
            &FieldCT::from(scaling_factor_4),
            builder,
            driver,
        )?;
        Ok(())
    }
}
