use crate::co_decider::relations::CRAND_PAIRS_FACTOR;
use crate::co_decider::types::MAX_PARTIAL_RELATION_LENGTH;
use crate::co_oink::{
    CRAND_PAIRS_CONST, CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE, CRAND_PAIRS_FACTOR_N,
};
use crate::key::types::TraceData;
use crate::mpc::NoirUltraHonkProver;
use crate::prelude::{Rep3UltraHonkDriver, ShamirUltraHonkDriver};
use crate::types::Polynomials;
use ark_ec::pairing::Pairing;
use ark_ff::One;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::prelude::GenericUltraCircuitBuilder;
use co_builder::prelude::PairingPointAccumulatorPubInputIndices;
use co_builder::prelude::Polynomial;
use co_builder::prelude::PrecomputedEntities;
use co_builder::prelude::ProverCrs;
use co_builder::prelude::ProverWitnessEntities;
use co_builder::prelude::ProvingKey as PlainProvingKey;
use co_builder::prelude::VerifyingKey;
use co_builder::prelude::PAIRING_POINT_ACCUMULATOR_SIZE;
use co_builder::prelude::{ActiveRegionData, HonkCurve};
use co_builder::HonkProofResult;
use co_builder::{HonkProofError, TranscriptFieldType};
use eyre::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use ultrahonk::prelude::{VerifyingKeyBarretenberg, ZeroKnowledge};
use ultrahonk::Utils;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ProvingKey<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub circuit_size: u32,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub public_inputs: Vec<P::ScalarField>,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub contains_pairing_point_accumulator: bool,
    pub pairing_point_accumulator_public_input_indices: PairingPointAccumulatorPubInputIndices,
    pub polynomials: Polynomials<T::ArithmeticShare, P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub memory_records_shared: BTreeMap<u32, T::ArithmeticShare>,
    pub final_active_wire_idx: usize,
    pub active_region_data: ActiveRegionData,
    pub phantom: PhantomData<T>,
}

pub type Rep3ProvingKey<P, N> = ProvingKey<Rep3UltraHonkDriver<N>, P>;
pub type ShamirProvingKey<P, N> =
    ProvingKey<ShamirUltraHonkDriver<<P as Pairing>::ScalarField, N>, P>;

impl<T: NoirUltraHonkProver<P>, P: Pairing> ProvingKey<T, P> {
    const PUBLIC_INPUT_WIRE_INDEX: usize = ProverWitnessEntities::<T::ArithmeticShare>::W_R;

    // We ignore the TraceStructure for now (it is None in barretenberg for UltraHonk)
    pub fn create<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: T::PartyID,
        mut circuit: GenericUltraCircuitBuilder<P, U>,
        driver: &mut U,
    ) -> HonkProofResult<Self> {
        tracing::trace!("ProvingKey create");

        assert!(
            circuit.circuit_finalized,
            "the circuit must be finalized before creating the  proving key"
        );

        let dyadic_circuit_size = circuit.compute_dyadic_size();

        // Complete the public inputs execution trace block from builder.public_inputs
        circuit.populate_public_inputs_block();
        circuit.blocks.compute_offsets(false);

        // Find index of last non-trivial wire value in the trace
        let mut final_active_wire_idx = 0;
        for block in circuit.blocks.get() {
            if block.len() > 0 {
                final_active_wire_idx = block.trace_offset as usize + block.len() - 1;
            }
        }

        // TACEO TODO BB allocates less memory for the different polynomials

        let mut proving_key = Self::new(
            dyadic_circuit_size,
            circuit.public_inputs.len(),
            final_active_wire_idx,
        );
        // Construct and add to proving key the wire, selector and copy constraint polynomials
        proving_key.populate_trace(id, &mut circuit, driver, false);

        // First and last lagrange polynomials (in the full circuit size)
        proving_key.polynomials.precomputed.lagrange_first_mut()[0] = P::ScalarField::one();
        proving_key.polynomials.precomputed.lagrange_last_mut()[final_active_wire_idx] =
            P::ScalarField::one();

        PlainProvingKey::construct_lookup_table_polynomials(
            proving_key
                .polynomials
                .precomputed
                .get_table_polynomials_mut(),
            &circuit,
            dyadic_circuit_size,
            0,
        );
        PlainProvingKey::construct_lookup_read_counts(
            driver,
            proving_key
                .polynomials
                .witness
                .lookup_read_counts_and_tags_mut()
                .try_into()
                .unwrap(),
            &mut circuit,
        )?;

        // Construct the public inputs array
        let block = circuit.blocks.get_pub_inputs();
        assert!(block.is_pub_inputs);
        for var_idx in block.wires[Self::PUBLIC_INPUT_WIRE_INDEX]
            .iter()
            .take(proving_key.num_public_inputs as usize)
            .cloned()
        {
            let var = U::get_public(&circuit.get_variable(var_idx as usize))
                .ok_or(HonkProofError::ExpectedPublicWitness)?;
            proving_key.public_inputs.push(var);
        }

        // Set the pairing point accumulator indices
        proving_key.pairing_point_accumulator_public_input_indices =
            circuit.pairing_point_accumulator_public_input_indices;
        proving_key.contains_pairing_point_accumulator = circuit.contains_pairing_point_accumulator;
        Ok(proving_key)
    }

    pub fn create_keys<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: T::PartyID,
        circuit: GenericUltraCircuitBuilder<P, U>,
        prover_crs: &ProverCrs<P>,
        verifier_crs: P::G2Affine,
        driver: &mut U,
    ) -> HonkProofResult<(Self, VerifyingKey<P>)> {
        let pk = ProvingKey::create(id, circuit, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), prover_crs)?;
            *des = P::G1Affine::from(comm);
        }

        // Create and return the VerifyingKey instance
        let vk = VerifyingKey {
            crs: verifier_crs,
            circuit_size,
            num_public_inputs: pk.num_public_inputs,
            pub_inputs_offset: pk.pub_inputs_offset,
            commitments,
            contains_pairing_point_accumulator: pk.contains_pairing_point_accumulator,
            pairing_point_accumulator_public_input_indices: pk
                .pairing_point_accumulator_public_input_indices,
        };

        Ok((pk, vk))
    }

    pub fn create_keys_barretenberg<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: T::PartyID,
        circuit: GenericUltraCircuitBuilder<P, U>,
        crs: &ProverCrs<P>,
        driver: &mut U,
    ) -> HonkProofResult<(Self, VerifyingKeyBarretenberg<P>)> {
        let contains_pairing_point_accumulator = circuit.contains_pairing_point_accumulator;
        let pairing_point_accumulator_public_input_indices =
            circuit.pairing_point_accumulator_public_input_indices;

        let pk = ProvingKey::create(id, circuit, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), crs)?;
            *des = P::G1Affine::from(comm);
        }

        // Create and return the VerifyingKey instance
        let vk = VerifyingKeyBarretenberg {
            circuit_size: circuit_size as u64,
            log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
            num_public_inputs: pk.num_public_inputs as u64,
            pub_inputs_offset: pk.pub_inputs_offset as u64,
            contains_pairing_point_accumulator,
            pairing_point_accumulator_public_input_indices,
            commitments,
        };
        Ok((pk, vk))
    }

    pub fn get_public_inputs(&self) -> Vec<P::ScalarField> {
        self.public_inputs.clone()
    }

    fn new(circuit_size: usize, num_public_inputs: usize, final_active_wire_idx: usize) -> Self {
        tracing::trace!("ProvingKey new");
        let polynomials = Polynomials::new(circuit_size);

        Self {
            circuit_size: circuit_size as u32,
            public_inputs: Vec::with_capacity(num_public_inputs),
            num_public_inputs: num_public_inputs as u32,
            pub_inputs_offset: 0,
            polynomials,
            memory_read_records: Vec::new(),
            memory_write_records: Vec::new(),
            final_active_wire_idx,
            phantom: PhantomData,
            contains_pairing_point_accumulator: false,
            pairing_point_accumulator_public_input_indices: [0; PAIRING_POINT_ACCUMULATOR_SIZE],
            memory_records_shared: BTreeMap::new(),
            active_region_data: ActiveRegionData::new(),
        }
    }

    fn populate_trace<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        &mut self,
        id: T::PartyID,
        builder: &mut GenericUltraCircuitBuilder<P, U>,
        driver: &mut U,
        is_structured: bool,
    ) {
        tracing::trace!("Populating trace");

        let mut trace_data = TraceData::new(builder, self);
        let mut active_region_data = ActiveRegionData::new();
        trace_data.construct_trace_data(id, builder, is_structured, &mut active_region_data);

        let ram_rom_offset = trace_data.ram_rom_offset;
        let copy_cycles = trace_data.copy_cycles;
        self.pub_inputs_offset = trace_data.pub_inputs_offset;
        self.active_region_data = active_region_data;
        PlainProvingKey::add_memory_records_to_proving_key(
            ram_rom_offset,
            builder,
            &mut self.memory_read_records,
            &mut self.memory_write_records,
        );

        // We have to add the shared memory records to the proving key as well
        for (k, el) in builder.memory_records_shared.iter() {
            let val = if U::is_shared(el) {
                U::get_shared(el).expect("Already checked it is shared")
            } else {
                U::promote_to_trivial_share(
                    driver,
                    U::get_public(el).expect("Already checked it is public"),
                )
            };
            self.memory_records_shared.insert(k + ram_rom_offset, val);
        }

        // Compute the permutation argument polynomials (sigma/id) and add them to proving key
        PlainProvingKey::compute_permutation_argument_polynomials(
            &mut self.polynomials.precomputed,
            builder,
            copy_cycles,
            self.circuit_size as usize,
            self.pub_inputs_offset as usize,
            &self.active_region_data,
        );
    }

    pub fn from_plain_key_and_shares(
        plain_key: &PlainProvingKey<P>,
        shares: Vec<T::ArithmeticShare>,
    ) -> Result<Self> {
        let circuit_size = plain_key.circuit_size;
        let public_inputs = plain_key.public_inputs.to_owned();
        let num_public_inputs = plain_key.num_public_inputs;
        let pub_inputs_offset = plain_key.pub_inputs_offset;
        let memory_read_records = plain_key.memory_read_records.to_owned();
        let memory_write_records = plain_key.memory_write_records.to_owned();
        let final_active_wire_idx = plain_key.final_active_wire_idx;
        let active_region_data = plain_key.active_region_data.to_owned();

        if shares.len() != circuit_size as usize * 6 {
            return Err(eyre::eyre!("Share length is not 6 times circuit size"));
        }

        let mut polynomials = Polynomials::default();
        for (src, des) in plain_key
            .polynomials
            .precomputed
            .iter()
            .zip(polynomials.precomputed.iter_mut())
        {
            *des = src.to_owned();
        }

        for (src, des) in shares
            .chunks_exact(circuit_size as usize)
            .zip(polynomials.witness.iter_mut())
        {
            *des = Polynomial::new(src.to_owned());
        }
        Ok(Self {
            circuit_size,
            public_inputs,
            num_public_inputs,
            pub_inputs_offset,
            polynomials,
            memory_read_records,
            memory_write_records,
            final_active_wire_idx,
            phantom: PhantomData,
            contains_pairing_point_accumulator: plain_key.contains_pairing_point_accumulator,
            pairing_point_accumulator_public_input_indices: plain_key
                .pairing_point_accumulator_public_input_indices
                .to_owned(),
            memory_records_shared: BTreeMap::new(),
            active_region_data,
        })
    }

    pub fn ultrahonk_num_randomness(&self, has_zk: ZeroKnowledge) -> usize
    where
        P: HonkCurve<TranscriptFieldType>,
    {
        // TODO because a lot is skipped in sumcheck prove, we generate a lot more than we really need
        let active_domain_size_mul = if self.active_region_data.size() > 0 {
            self.active_region_data.size() - 1
        } else {
            self.final_active_wire_idx
        };

        let n = self.circuit_size as usize;
        let num_pairs_oink_prove = CRAND_PAIRS_FACTOR_N * n
            + CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE * active_domain_size_mul
            + CRAND_PAIRS_CONST;
        // log2(n) * ((n >>= 1) / 2) == n - 1
        let num_pairs_sumcheck_prove = CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH * (n - 1);

        let num_pairs_sumcheck_disabled_contributions = if has_zk == ZeroKnowledge::No {
            0
        } else {
            // compute_disabled_contribution: log2(n) rounds, each once relation, plus additional in round 0
            (n.ilog(2) as usize + 1) * CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH
        };

        let num_zk_randomness = if has_zk == ZeroKnowledge::No {
            0
        } else {
            n // compute_batched_polys
            + 1 // ZKData::new
            + n.ilog2() as usize * P::LIBRA_UNIVARIATES_LENGTH // generate_libra_univariates
            + 2 // compute_concatenated_libra_polynomial
            + 3 // compute_big_sum_polynomial
        };
        num_pairs_oink_prove
            + num_pairs_sumcheck_prove
            + num_pairs_sumcheck_disabled_contributions
            + num_zk_randomness
    }

    pub fn create_vk(
        &self,
        prover_crs: &ProverCrs<P>,
        verifier_crs: P::G2Affine,
    ) -> Result<VerifyingKey<P>> {
        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(self.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), prover_crs)?;
            *des = P::G1Affine::from(comm);
        }
        Ok(VerifyingKey {
            crs: verifier_crs,
            circuit_size: self.circuit_size,
            num_public_inputs: self.num_public_inputs,
            pub_inputs_offset: self.pub_inputs_offset,
            commitments,
            contains_pairing_point_accumulator: self.contains_pairing_point_accumulator,
            pairing_point_accumulator_public_input_indices: self
                .pairing_point_accumulator_public_input_indices,
        })
    }
}
