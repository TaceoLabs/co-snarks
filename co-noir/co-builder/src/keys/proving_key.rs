use crate::keys::plain_proving_key::PlainPkTrait;
use crate::keys::types::TraceData;
use crate::prelude::GenericUltraCircuitBuilder;
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::One;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, HonkProofResult, TranscriptFieldType},
    keys::plain_proving_key::PlainProvingKey,
    keys::proving_key::ProvingKey,
    keys::types::ActiveRegionData,
    keys::verification_key::{VerifyingKey, VerifyingKeyBarretenberg},
    mpc::NoirUltraHonkProver,
    mpc::rep3::Rep3UltraHonkDriver,
    mpc::shamir::ShamirUltraHonkDriver,
    polynomials::entities::Polynomials,
    polynomials::entities::PrecomputedEntities,
    utils::Utils,
};
use mpc_core::MpcState;
use std::collections::BTreeMap;
use std::marker::PhantomData;

pub type Rep3ProvingKey<P> = ProvingKey<Rep3UltraHonkDriver, P>;
pub type ShamirProvingKey<P> = ProvingKey<ShamirUltraHonkDriver, P>;

pub trait ProvingKeyTrait<T: NoirUltraHonkProver<C>, C: CurveGroup>: Sized {
    fn create<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: <T::State as MpcState>::PartyID,
        circuit: GenericUltraCircuitBuilder<C, U>,
        driver: &mut U,
    ) -> HonkProofResult<Self>;

    fn create_keys<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
        P: Pairing<G1Affine = C::Affine, G1 = C>,
    >(
        id: <T::State as MpcState>::PartyID,
        circuit: GenericUltraCircuitBuilder<C, U>,
        prover_crs: &ProverCrs<C>,
        verifier_crs: P::G2Affine,
        driver: &mut U,
    ) -> HonkProofResult<(Self, VerifyingKey<P>)>;

    fn create_keys_barretenberg<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: <T::State as MpcState>::PartyID,
        circuit: GenericUltraCircuitBuilder<C, U>,
        crs: &ProverCrs<C>,
        driver: &mut U,
    ) -> HonkProofResult<(Self, VerifyingKeyBarretenberg<C>)>;

    fn populate_trace<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        &mut self,
        id: <T::State as MpcState>::PartyID,
        builder: &mut GenericUltraCircuitBuilder<C, U>,
        driver: &mut U,
        is_structured: bool,
    );

    fn get_public_inputs(&self) -> Vec<C::ScalarField>;

    fn new(circuit_size: usize, num_public_inputs: usize, final_active_wire_idx: usize) -> Self;
}

impl<T: NoirUltraHonkProver<C>, C: HonkCurve<TranscriptFieldType>> ProvingKeyTrait<T, C>
    for ProvingKey<T, C>
{
    // We ignore the TraceStructure for now (it is None in barretenberg for UltraHonk)
    fn create<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: <T::State as MpcState>::PartyID,
        mut circuit: GenericUltraCircuitBuilder<C, U>,
        driver: &mut U,
    ) -> HonkProofResult<Self> {
        tracing::trace!("ProvingKey create");

        assert!(
            circuit.circuit_finalized,
            "the circuit must be finalized before creating the proving key"
        );

        let dyadic_circuit_size = circuit.compute_dyadic_size();

        // Complete the public inputs execution trace block from builder.public_inputs
        circuit.blocks.compute_offsets(false);

        // Find index of last non-trivial wire value in the trace
        let mut final_active_wire_idx = 0;
        for block in circuit.blocks.get() {
            if !block.is_empty() {
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
        proving_key.polynomials.precomputed.lagrange_first_mut()[0] = C::ScalarField::one();
        proving_key.polynomials.precomputed.lagrange_last_mut()[final_active_wire_idx] =
            C::ScalarField::one();

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
        for var_idx in block.wires[Self::PUBLIC_INPUT_WIRE_INDEX]
            .iter()
            .take(proving_key.num_public_inputs as usize)
            .cloned()
        {
            let var = U::get_public(&circuit.get_variable(var_idx as usize))
                .ok_or(HonkProofError::ExpectedPublicWitness)?;
            proving_key.public_inputs.push(var);
        }

        Ok(proving_key)
    }

    fn create_keys<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
        P: Pairing<G1Affine = C::Affine, G1 = C>,
    >(
        id: <T::State as MpcState>::PartyID,
        circuit: GenericUltraCircuitBuilder<C, U>,
        prover_crs: &ProverCrs<C>,
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
            *des = C::Affine::from(comm);
        }

        // Create and return the VerifyingKey instance
        let vk = VerifyingKey {
            crs: verifier_crs,
            inner_vk: VerifyingKeyBarretenberg {
                log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
                num_public_inputs: pk.num_public_inputs as u64,
                pub_inputs_offset: pk.pub_inputs_offset as u64,
                commitments,
            },
        };

        Ok((pk, vk))
    }

    fn create_keys_barretenberg<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        id: <T::State as MpcState>::PartyID,
        circuit: GenericUltraCircuitBuilder<C, U>,
        crs: &ProverCrs<C>,
        driver: &mut U,
    ) -> HonkProofResult<(Self, VerifyingKeyBarretenberg<C>)> {
        let pk = ProvingKey::create(id, circuit, driver)?;
        let circuit_size = pk.circuit_size;

        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(pk.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), crs)?;
            *des = C::Affine::from(comm);
        }

        // Create and return the VerifyingKey instance
        let vk = VerifyingKeyBarretenberg {
            log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
            num_public_inputs: pk.num_public_inputs as u64,
            pub_inputs_offset: pk.pub_inputs_offset as u64,
            commitments,
        };
        Ok((pk, vk))
    }

    fn get_public_inputs(&self) -> Vec<C::ScalarField> {
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
            memory_records_shared: BTreeMap::new(),
            active_region_data: ActiveRegionData::new(),
        }
    }

    fn populate_trace<
        U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
    >(
        &mut self,
        id: <T::State as MpcState>::PartyID,
        builder: &mut GenericUltraCircuitBuilder<C, U>,
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
}
