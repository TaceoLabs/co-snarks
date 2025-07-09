use {
    super::blake_util::{BlakeType, BlakeUtils},
    super::blake2s::BLAKE2S_IV,
    super::plookup::{ColumnIdx, MultiTableId, Plookup},
    crate::TranscriptFieldType,
    crate::prelude::HonkCurve,
    crate::types::field_ct::{ByteArray, FieldCT},
    crate::ultra_builder::GenericUltraCircuitBuilder,
    ark_ff::PrimeField,
    co_acvm::mpc::NoirWitnessExtensionProtocol,
    std::array,
};

// Internal flags
#[repr(u8)]
enum Blake3Flags {
    ChunkStart = 1 << 0,
    ChunkEnd = 1 << 1,
    _Parent = 1 << 2,
    Root = 1 << 3,
    _KeyedHash = 1 << 4,
    _DeriveKeyContext = 1 << 5,
    _DeriveKeyMaterial = 1 << 6,
}

// Constants
const BLAKE3_KEY_LEN: usize = 32;
const BLAKE3_OUT_LEN: usize = 32;
const BLAKE3_BLOCK_LEN: usize = 64;
const _BLAKE3_CHUNK_LEN: usize = 1024;
const _BLAKE3_MAX_DEPTH: usize = 54;
const BLAKE3_STATE_SIZE: usize = 16;

const BLAKE3_IV: [u32; 8] = BLAKE2S_IV;

pub struct Blake3Hasher<F: PrimeField> {
    key: [FieldCT<F>; 8],
    cv: [FieldCT<F>; 8],
    buf: ByteArray<F>,
    buf_len: u8,
    blocks_compressed: u8,
    flags: u8,
}

impl<F: PrimeField> Blake3Hasher<F> {
    pub fn blake3_hasher_init() -> Self {
        let mut hasher = Self {
            key: Default::default(),
            cv: Default::default(),
            buf: ByteArray::default_with_length(BLAKE3_BLOCK_LEN),
            buf_len: 0,
            blocks_compressed: 0,
            flags: 0,
        };

        for (key, &iv) in hasher
            .key
            .iter_mut()
            .zip(BLAKE3_IV.iter())
            .take(BLAKE3_KEY_LEN >> 2)
        {
            *key = FieldCT::from(F::from(iv));
        }
        for (cv, &iv) in hasher
            .cv
            .iter_mut()
            .zip(BLAKE3_IV.iter())
            .take(BLAKE3_KEY_LEN >> 2)
        {
            *cv = FieldCT::from(F::from(iv));
        }

        hasher
    }

    pub fn blake3_hasher_update<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        input: &ByteArray<F>,
        input_len: usize,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        if input_len == 0 {
            return Ok(());
        }

        let mut start_counter = 0;
        let mut remaining_len = input_len;

        while remaining_len > BLAKE3_BLOCK_LEN {
            self.compress_in_place(
                &input.slice(start_counter, BLAKE3_BLOCK_LEN),
                BLAKE3_BLOCK_LEN as u8,
                self.flags | self.maybe_start_flag(),
                builder,
                driver,
            )?;
            self.blocks_compressed += 1;
            start_counter += BLAKE3_BLOCK_LEN;
            remaining_len -= BLAKE3_BLOCK_LEN;
        }

        let take = (BLAKE3_BLOCK_LEN - self.buf_len as usize).min(remaining_len);
        for i in 0..take {
            self.buf
                .set_byte(self.buf_len as usize + i, input.get_byte(start_counter + i));
        }

        self.buf_len += take as u8;
        Ok(())
    }

    pub fn blake3_hasher_finalize<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        out: &mut ByteArray<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let block_flags = self.flags | self.maybe_start_flag() | Blake3Flags::ChunkEnd as u8;
        let output = self.make_output(&self.cv, &self.buf, self.buf_len, block_flags);

        let mut wide_buf = ByteArray::default_with_length(BLAKE3_BLOCK_LEN);
        self.compress_xof(
            &output.input_cv,
            &output.block,
            output.block_len,
            output.flags | Blake3Flags::Root as u8,
            &mut wide_buf,
            builder,
            driver,
        )?;

        for i in 0..BLAKE3_OUT_LEN {
            out.set_byte(i, wide_buf.get_byte(i));
        }
        Ok(())
    }

    fn maybe_start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            Blake3Flags::ChunkStart as u8
        } else {
            0
        }
    }

    fn compress_in_place<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        block: &ByteArray<F>,
        block_len: u8,
        flags: u8,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let mut state: [FieldCT<F>; BLAKE3_STATE_SIZE] =
            array::from_fn(|_| FieldCT::<F>::default());
        self.compress_pre(
            &mut state, &self.cv, block, block_len, flags, builder, driver,
        )?;

        /*
         * At this point in the algorithm, a malicious prover could tweak the add_normalise function in `blake_util.hpp` to
         * create unexpected overflow in the state matrix. At the end of the `compress_pre()` function, there might be
         * overflows in the elements of the first and third rows of the state matrix. But this wouldn't be a problem because
         * in the below loop, while reading from the lookup table, we ensure that the overflow is ignored and the result is
         * contrained to 32 bits.
         */
        for i in 0..(BLAKE3_STATE_SIZE >> 1) {
            let lookup = Plookup::get_lookup_accumulators_ct(
                builder,
                driver,
                MultiTableId::BlakeXor,
                &state[i],
                &state[i + 8],
                true,
            )?;
            self.cv[i] = lookup[ColumnIdx::C3][0].clone();
        }
        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    fn compress_xof<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        cv: &[FieldCT<F>; 8],
        block: &ByteArray<F>,
        block_len: u8,
        flags: u8,
        out: &mut ByteArray<F>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let mut state: [FieldCT<F>; BLAKE3_STATE_SIZE] =
            array::from_fn(|_| FieldCT::<F>::default());
        self.compress_pre(&mut state, cv, block, block_len, flags, builder, driver)?;
        /*
         * The same note as in the above `blake3_compress_in_place()` function. Here too, reading from the lookup table
         * ensures that correct 32-bit inputs are used.
         */
        for i in 0..(BLAKE3_STATE_SIZE >> 1) {
            let lookup_1 = Plookup::get_lookup_accumulators_ct(
                builder,
                driver,
                MultiTableId::BlakeXor,
                &state[i],
                &state[i + 8],
                true,
            )?;
            let out_bytes_1 =
                ByteArray::from_field_ct(&lookup_1[ColumnIdx::C3][0], 4, builder, driver)?;
            out.write_at(&out_bytes_1.reverse(), i * 4);

            let lookup_2 = Plookup::get_lookup_accumulators_ct(
                builder,
                driver,
                MultiTableId::BlakeXor,
                &state[i + 8],
                &cv[i],
                true,
            )?;
            let out_bytes_2 =
                ByteArray::from_field_ct(&lookup_2[ColumnIdx::C3][0], 4, builder, driver)?;
            out.write_at(&out_bytes_2.reverse(), (i + 8) * 4);
        }
        Ok(())
    }

    /*
     * Core Blake3s functions. These are similar to that of Blake2s except for a few
     * constant parameters and fewer rounds.
     *
     */
    #[expect(clippy::too_many_arguments)]
    fn compress_pre<
        P: HonkCurve<TranscriptFieldType, ScalarField = F>,
        T: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &self,
        state: &mut [FieldCT<F>; BLAKE3_STATE_SIZE],
        cv: &[FieldCT<F>; 8],
        block: &ByteArray<F>,
        block_len: u8,
        flags: u8,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        let mut block_words: [FieldCT<F>; BLAKE3_STATE_SIZE] =
            array::from_fn(|_| FieldCT::<F>::default());
        for (i, word) in block_words.iter_mut().enumerate() {
            *word = block
                .slice(i * 4, 4)
                .reverse()
                .to_field_ct(builder, driver)?;
        }

        state
            .iter_mut()
            .zip(cv.iter())
            .for_each(|(dest, src)| *dest = src.clone());
        state[8] = FieldCT::from(F::from(BLAKE3_IV[0]));
        state[9] = FieldCT::from(F::from(BLAKE3_IV[1]));
        state[10] = FieldCT::from(F::from(BLAKE3_IV[2]));
        state[11] = FieldCT::from(F::from(BLAKE3_IV[3]));
        state[12] = FieldCT::from(F::from(0));
        state[13] = FieldCT::from(F::from(0));
        state[14] = FieldCT::from(F::from(block_len as u32));
        state[15] = FieldCT::from(F::from(flags as u32));

        for round in 0..7 {
            BlakeUtils::round_fn_lookup(
                state,
                &block_words,
                round,
                BlakeType::Blake3,
                builder,
                driver,
            )?;
        }
        Ok(())
    }

    fn make_output(
        &self,
        input_cv: &[FieldCT<F>; 8],
        block: &ByteArray<F>,
        block_len: u8,
        flags: u8,
    ) -> Output<F> {
        let mut output = Output {
            input_cv: input_cv.clone(),
            block: ByteArray::default_with_length(BLAKE3_BLOCK_LEN),
            block_len,
            flags,
        };

        for i in 0..BLAKE3_BLOCK_LEN {
            output.block.set_byte(i, block.get_byte(i));
        }

        output
    }
}

pub struct Output<F: PrimeField> {
    input_cv: [FieldCT<F>; 8],
    block: ByteArray<F>,
    block_len: u8,
    flags: u8,
}

pub fn blake3s<
    P: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
>(
    input: &ByteArray<P::ScalarField>,
    builder: &mut GenericUltraCircuitBuilder<P, T>,
    driver: &mut T,
) -> eyre::Result<ByteArray<P::ScalarField>> {
    let mut hasher = Blake3Hasher::blake3_hasher_init();
    hasher.blake3_hasher_update(input, input.values.len(), builder, driver)?;
    let mut result = ByteArray::default_with_length(BLAKE3_OUT_LEN);
    hasher.blake3_hasher_finalize(&mut result, builder, driver)?;
    Ok(result)
}
