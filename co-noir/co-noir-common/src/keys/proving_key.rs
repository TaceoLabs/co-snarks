use crate::crs::ProverCrs;
use crate::keys::plain_proving_key::PlainProvingKey;
use crate::keys::types::ActiveRegionData;
use crate::keys::verification_key::VerifyingKey;
use crate::keys::verification_key::VerifyingKeyBarretenberg;
use crate::mpc::rep3::Rep3UltraHonkDriver;
use crate::mpc::shamir::ShamirUltraHonkDriver;
use crate::polynomials::entities::Polynomials;
use crate::polynomials::entities::PrecomputedEntities;
use crate::polynomials::entities::ProverWitnessEntities;
use crate::polynomials::polynomial::Polynomial;
use crate::utils::Utils;
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use eyre::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::marker::PhantomData;

use crate::mpc::NoirUltraHonkProver;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ProvingKey<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub circuit_size: u32,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub public_inputs: Vec<P::ScalarField>,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<T::ArithmeticShare, P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub memory_records_shared: BTreeMap<u32, T::ArithmeticShare>,
    pub final_active_wire_idx: usize,
    pub active_region_data: ActiveRegionData,
    pub phantom: PhantomData<T>,
}

pub type Rep3ProvingKey<P> = ProvingKey<Rep3UltraHonkDriver, P>;
pub type ShamirProvingKey<P> = ProvingKey<ShamirUltraHonkDriver, P>;

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> ProvingKey<T, C> {
    pub const PUBLIC_INPUT_WIRE_INDEX: usize = ProverWitnessEntities::<T::ArithmeticShare>::W_R;

    pub fn from_plain_key_and_shares(
        plain_key: &PlainProvingKey<C>,
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
            eyre::bail!("Share length is not 6 times circuit size");
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
            memory_records_shared: BTreeMap::new(),
            active_region_data,
        })
    }

    pub fn create_vk<P: Pairing<G1Affine = C::Affine, G1 = C>>(
        &self,
        prover_crs: &ProverCrs<C>,
        verifier_crs: P::G2Affine,
    ) -> Result<VerifyingKey<P>> {
        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(self.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), prover_crs)?;
            *des = C::Affine::from(comm);
        }
        Ok(VerifyingKey {
            crs: verifier_crs,
            inner_vk: VerifyingKeyBarretenberg {
                log_circuit_size: Utils::get_msb64(self.circuit_size as u64) as u64,
                num_public_inputs: self.num_public_inputs as u64,
                pub_inputs_offset: self.pub_inputs_offset as u64,
                commitments,
            },
        })
    }
}
