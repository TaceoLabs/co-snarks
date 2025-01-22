use crate::co_decider::relations::CRAND_PAIRS_FACTOR;
use crate::co_decider::types::MAX_PARTIAL_RELATION_LENGTH;
use crate::co_oink::{
    CRAND_PAIRS_CONST, CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE, CRAND_PAIRS_FACTOR_N,
};
use crate::key::types::TraceData;
use crate::mpc::NoirUltraHonkProver;
use crate::types::Polynomials;
use ark_ec::pairing::Pairing;
use ark_ff::One;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::prelude::Crs;
use co_builder::prelude::GenericUltraCircuitBuilder;
use co_builder::prelude::Polynomial;
use co_builder::prelude::PrecomputedEntities;
use co_builder::prelude::ProverCrs;
use co_builder::prelude::ProvingKey as PlainProvingKey;
use co_builder::prelude::VerifyingKey;
use co_builder::prelude::AGGREGATION_OBJECT_SIZE;
use co_builder::prelude::{AggregationObjectPubInputIndices, ProverWitnessEntities};
use co_builder::HonkProofError;
use co_builder::HonkProofResult;
use eyre::Result;
use serde::Deserialize;
use serde::Serialize;
use std::marker::PhantomData;
use ultrahonk::prelude::VerifyingKeyBarretenberg;
use ultrahonk::Utils;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ProvingKey<T: NoirUltraHonkProver<P>, P: Pairing> {
    pub crs: ProverCrs<P>,
    pub circuit_size: u32,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub public_inputs: Vec<P::ScalarField>,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub contains_pairing_point_accumulator: bool,
    pub pairing_point_accumulator_public_input_indices: AggregationObjectPubInputIndices,
    pub polynomials: Polynomials<T::ArithmeticShare, P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    pub final_active_wire_idx: usize,
    pub phantom: PhantomData<T>,
}

impl<T: NoirUltraHonkProver<P>, P: Pairing> ProvingKey<T, P> {
    const PUBLIC_INPUT_WIRE_INDEX: usize = ProverWitnessEntities::<T::ArithmeticShare>::W_R;

    // We ignore the TraceStructure for now (it is None in barretenberg for UltraHonk)
    pub fn create<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: T::PartyID,
        mut circuit: GenericUltraCircuitBuilder<P, U>,
        crs: ProverCrs<P>,
        driver: &mut U,
    ) -> HonkProofResult<Self> {
        tracing::trace!("ProvingKey create");
        circuit.finalize_circuit(true, driver)?;

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
            crs,
            final_active_wire_idx,
        );
        // Construct and add to proving key the wire, selector and copy constraint polynomials
        proving_key.populate_trace(id, &mut circuit, false);

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
            dyadic_circuit_size,
        );

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
        crs: Crs<P>,
        driver: &mut U,
    ) -> HonkProofResult<(Self, VerifyingKey<P>)> {
        let (prover_crs, verifier_crs) = crs.split();

        let pk = ProvingKey::create(id, circuit, prover_crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), &pk.crs)?;
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
        crs: ProverCrs<P>,
        driver: &mut U,
    ) -> HonkProofResult<(Self, VerifyingKeyBarretenberg<P>)> {
        let contains_pairing_point_accumulator = circuit.contains_pairing_point_accumulator;
        let pairing_point_accumulator_public_input_indices =
            circuit.pairing_point_accumulator_public_input_indices;

        let pk = ProvingKey::create(id, circuit, crs, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), &pk.crs)?;
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

    pub fn get_prover_crs<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        circuit: &GenericUltraCircuitBuilder<P, U>,
        path_g1: &str,
    ) -> Result<ProverCrs<P>> {
        PlainProvingKey::get_prover_crs(circuit, path_g1)
    }

    pub fn get_crs<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        circuit: &GenericUltraCircuitBuilder<P, U>,
        path_g1: &str,
        path_g2: &str,
    ) -> Result<Crs<P>> {
        PlainProvingKey::get_crs(circuit, path_g1, path_g2)
    }

    fn new(
        circuit_size: usize,
        num_public_inputs: usize,
        crs: ProverCrs<P>,
        final_active_wire_idx: usize,
    ) -> Self {
        tracing::trace!("ProvingKey new");
        let polynomials = Polynomials::new(circuit_size);

        Self {
            crs,
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
            pairing_point_accumulator_public_input_indices: [0; AGGREGATION_OBJECT_SIZE],
        }
    }

    fn populate_trace<
        U: NoirWitnessExtensionProtocol<P::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        &mut self,
        id: T::PartyID,
        builder: &mut GenericUltraCircuitBuilder<P, U>,
        is_structured: bool,
    ) {
        tracing::trace!("Populating trace");

        let mut trace_data = TraceData::new(builder, self);
        trace_data.construct_trace_data(id, builder, is_structured);

        let ram_rom_offset = trace_data.ram_rom_offset;
        let copy_cycles = trace_data.copy_cycles;
        self.pub_inputs_offset = trace_data.pub_inputs_offset;

        PlainProvingKey::add_memory_records_to_proving_key(
            ram_rom_offset,
            builder,
            &mut self.memory_read_records,
            &mut self.memory_write_records,
        );

        // Compute the permutation argument polynomials (sigma/id) and add them to proving key
        PlainProvingKey::compute_permutation_argument_polynomials(
            &mut self.polynomials.precomputed,
            builder,
            copy_cycles,
            self.circuit_size as usize,
            self.pub_inputs_offset as usize,
        );
    }

    pub fn from_plain_key_and_shares(
        plain_key: &PlainProvingKey<P>,
        shares: Vec<T::ArithmeticShare>,
    ) -> Result<Self> {
        let crs = plain_key.crs.to_owned();
        let circuit_size = plain_key.circuit_size;
        let public_inputs = plain_key.public_inputs.to_owned();
        let num_public_inputs = plain_key.num_public_inputs;
        let pub_inputs_offset = plain_key.pub_inputs_offset;
        let memory_read_records = plain_key.memory_read_records.to_owned();
        let memory_write_records = plain_key.memory_write_records.to_owned();
        let final_active_wire_idx = plain_key.final_active_wire_idx;

        if shares.len() != circuit_size as usize * 4 {
            return Err(eyre::eyre!("Share length is not 4 times circuit size"));
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
            crs,
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
        })
    }

    pub fn ultrahonk_num_randomness(&self) -> usize {
        // TODO because a lot is skipped in sumcheck prove, we generate a lot more than we really need
        let n = self.circuit_size as usize;
        let num_pairs_oink_prove = CRAND_PAIRS_FACTOR_N * n
            + CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE * self.final_active_wire_idx
            + CRAND_PAIRS_CONST;
        // log2(n) * ((n >>= 1) / 2) == n - 1
        let num_pairs_sumcheck_prove = CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH * (n - 1);
        num_pairs_oink_prove + num_pairs_sumcheck_prove
    }
}
