use crate::prelude::GenericUltraCircuitBuilder;
use crate::types::poseidon2::Poseidon2CT;
use crate::types::types::CycleScalar;
use crate::types::{
    poseidon2::{FieldHashCT, FieldSpongeCT},
    types::FieldCT,
};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;
use std::{collections::BTreeMap, ops::Index};
use {crate::prelude::HonkCurve, crate::HonkProofError, crate::HonkProofResult};

pub type TranscriptFieldType = ark_bn254::Fr;
pub type Poseidon2Sponge =
    FieldSpongeCT<TranscriptFieldType, 4, 3, Poseidon2CT<TranscriptFieldType, 4, 5>>;

pub trait TranscriptHasherCT<P: Pairing> {
    fn hash<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        buffer: Vec<FieldCT<P::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> FieldCT<P::ScalarField>;
}

impl<P: Pairing, const T: usize, const R: usize, H: FieldHashCT<P, T> + Default>
    TranscriptHasherCT<P> for FieldSpongeCT<P, T, R, H>
{
    fn hash<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        buffer: Vec<FieldCT<P::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> FieldCT<P::ScalarField> {
        Self::hash_fixed_length::<1, WT>(&buffer, builder, driver)[0]
    }
}

pub struct TranscriptCT<P, H>
where
    P: Pairing,
    H: TranscriptHasherCT<P>,
{
    proof_data: Vec<FieldCT<P::ScalarField>>,
    manifest: TranscriptManifest,
    num_frs_written: usize, // the number of bb::frs written to proof_data by the prover or the verifier
    num_frs_read: usize,    // the number of bb::frs read from proof_data by the verifier
    round_number: usize,
    is_first_challenge: bool,
    current_round_data: Vec<FieldCT<P::ScalarField>>,
    previous_challenge: FieldCT<P::ScalarField>,
    phantom_data: std::marker::PhantomData<H>,
}

impl<P, H> Default for TranscriptCT<P, H>
where
    P: Pairing,
    H: TranscriptHasherCT<P>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P, H> TranscriptCT<P, H>
where
    P: Pairing,
    H: TranscriptHasherCT<P>,
{
    pub fn new() -> Self {
        Self {
            proof_data: Default::default(),
            manifest: Default::default(),
            num_frs_written: 0,
            num_frs_read: 0,
            round_number: 0,
            is_first_challenge: true,
            current_round_data: Default::default(),
            previous_challenge: Default::default(),
            phantom_data: Default::default(),
        }
    }

    pub fn new_verifier(proof: Vec<FieldCT<P::ScalarField>>) -> Self {
        Self {
            proof_data: proof,
            manifest: Default::default(),
            num_frs_written: 0,
            num_frs_read: 0,
            round_number: 0,
            is_first_challenge: true,
            current_round_data: Default::default(),
            previous_challenge: Default::default(),
            phantom_data: Default::default(),
        }
    }

    #[expect(dead_code)]
    pub(crate) fn print(&self) {
        self.manifest.print();
    }

    #[expect(dead_code)]
    pub(crate) fn get_manifest(&self) -> &TranscriptManifest {
        &self.manifest
    }

    fn consume_prover_elements(&mut self, label: String, elements: &[FieldCT<P::ScalarField>]) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data.extend(elements);
        self.num_frs_written += len;
    }

    fn receive_n_from_prover(
        &mut self,
        label: String,
        n: usize,
    ) -> HonkProofResult<Vec<FieldCT<P::ScalarField>>> {
        if self.num_frs_read + n > self.proof_data.len() {
            return Err(HonkProofError::ProofTooSmall);
        }
        let elements = self.proof_data[self.num_frs_read..self.num_frs_read + n].to_owned();
        self.num_frs_read += n;

        self.consume_prover_elements(label, &elements);
        Ok(elements)
    }

    // pub(super) fn receive_u64_from_prover(&mut self, label: String) -> HonkProofResult<u64> {
    //     let element = self.receive_n_from_prover(label, 1)?[0];
    //     let r = element.into_bigint();
    //     Ok(r.as_ref().first().unwrap().to_owned())
    // }

    // pub(super) fn receive_fr_from_prover<Q: HonkCurve<P::ScalarField>>(
    //     &mut self,
    //     label: String,
    // ) -> HonkProofResult<FieldCT<P::ScalarField>> {
    //     let elements = self.receive_n_from_prover(label, Q::NUM_SCALARFIELD_ELEMENTS)?;

    //     Ok(&elements)
    // }

    // pub(super) fn receive_point_from_prover<Q: HonkCurve<P::ScalarField>>(
    //     &mut self,
    //     label: String,
    // ) -> HonkProofResult<P::G1Affine> {
    //     let elements = self.receive_n_from_prover(label, Q::NUM_BASEFIELD_ELEMENTS * 2)?;

    //     let coords = elements
    //         .chunks_exact(Q::NUM_BASEFIELD_ELEMENTS)
    //         .collect::<Vec<_>>();

    //     let x = coords[0];
    //     let y = coords[1];

    //     let res = if x.is_zero() && y.is_zero() {
    //         P::G1Affine::zero()
    //     } else {
    //         P::g1_affine_from_xy(x, y)
    //     };

    //     Ok(res)
    // }

    // pub(super) fn receive_fr_vec_from_verifier<Q: HonkCurve<P::ScalarField>>(
    //     &mut self,
    //     label: String,
    //     n: usize,
    // ) -> HonkProofResult<Vec<P::ScalarField>> {
    //     let elements = self.receive_n_from_prover(label, Q::NUM_SCALARFIELD_ELEMENTS * n)?;

    //     let elements = elements.chunks_exact(Q::NUM_SCALARFIELD_ELEMENTS).collect();
    //     Ok(elements)
    // }

    // pub(super) fn receive_fr_array_from_verifier<
    //     Q: HonkCurve<P::ScalarField>,
    //     const SIZE: usize,
    // >(
    //     &mut self,
    //     label: String,
    // ) -> HonkProofResult<[P::ScalarField; SIZE]> {
    //     let mut res: [P::ScalarField; SIZE] = [P::ScalarField::zero(); SIZE];
    //     let elements = self.receive_n_from_prover(label, Q::NUM_SCALARFIELD_ELEMENTS * SIZE)?;

    //     for (src, des) in elements
    //         .chunks_exact(Q::NUM_SCALARFIELD_ELEMENTS)
    //         .zip(res.iter_mut())
    //     {
    //         let el = src;
    //         *des = el;
    //     }
    //     Ok(res)
    // }

    fn split_challenge<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        challenge: FieldCT<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> std::io::Result<[FieldCT<P::ScalarField>; 2]> {
        // use existing field-splitting code in cycle_scalar
        let scalar = CycleScalar::from_field_ct(challenge, builder, driver)?;
        scalar.lo.create_range_constraint::<P, WT>(
            CycleScalar::<P::ScalarField>::LO_BITS,
            builder,
            driver,
        )?;
        scalar.hi.create_range_constraint(
            CycleScalar::<P::ScalarField>::HI_BITS,
            builder,
            driver,
        )?;
        Ok([scalar.lo, scalar.hi])
    }

    fn get_next_duplex_challenge_buffer<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        num_challenges: usize,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> std::io::Result<[FieldCT<P::ScalarField>; 2]> {
        // challenges need at least 110 bits in them to match the presumed security parameter of the BN254 curve.
        assert!(num_challenges <= 2);
        // Prevent challenge generation if this is the first challenge we're generating,
        // AND nothing was sent by the prover.
        if self.is_first_challenge {
            assert!(!self.current_round_data.is_empty());
        }
        // concatenate the previous challenge (if this is not the first challenge) with the current round data.
        // AZTEC TODO(Adrian): Do we want to use a domain separator as the initial challenge buffer?
        // We could be cheeky and use the hash of the manifest as domain separator, which would prevent us from having
        // to domain separate all the data. (See https://safe-hash.dev)

        let mut full_buffer = Vec::new();
        std::mem::swap(&mut full_buffer, &mut self.current_round_data);

        if self.is_first_challenge {
            // Update is_first_challenge for the future
            self.is_first_challenge = false;
        } else {
            // if not the first challenge, we can use the previous_challenge
            full_buffer.insert(0, self.previous_challenge);
        }

        // Hash the full buffer with poseidon2, which is believed to be a collision resistant hash function and a random
        // oracle, removing the need to pre-hash to compress and then hash with a random oracle, as we previously did
        // with Pedersen and Blake3s.
        let new_challenge = H::hash(full_buffer, builder, driver);
        let new_challenges = Self::split_challenge(new_challenge, builder, driver)?;

        // update previous challenge buffer for next time we call this function
        self.previous_challenge = new_challenge;
        Ok(new_challenges)
    }

    pub fn get_challenge<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        label: String,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> std::io::Result<FieldCT<P::ScalarField>> {
        self.manifest.add_challenge(self.round_number, &[label]);
        let challenge = self.get_next_duplex_challenge_buffer(1, builder, driver)?[0];
        let res = &challenge;
        self.round_number += 1;
        Ok(*res)
    }

    pub fn get_challenges<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        labels: &[String],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> std::io::Result<Vec<FieldCT<P::ScalarField>>> {
        let num_challenges = labels.len();
        self.manifest.add_challenge(self.round_number, labels);

        let mut res = Vec::with_capacity(num_challenges);
        for _ in 0..num_challenges >> 1 {
            let challenge_buffer = self.get_next_duplex_challenge_buffer(2, builder, driver)?;
            res.push(challenge_buffer[0]);
            res.push(challenge_buffer[1]);
        }
        if num_challenges & 1 == 1 {
            let challenge_buffer = self.get_next_duplex_challenge_buffer(1, builder, driver)?;
            res.push(challenge_buffer[0]);
        }

        self.round_number += 1;
        Ok(res.to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub(crate) struct RoundData {
    challenge_label: Vec<String>,
    entries: Vec<(String, usize)>,
}

impl RoundData {
    pub(crate) fn print(&self) {
        for label in self.challenge_label.iter() {
            println!("\tchallenge: {}", label);
        }
        for entry in self.entries.iter() {
            println!("\telement ({}): {}", entry.1, entry.0);
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TranscriptManifest {
    manifest: BTreeMap<usize, RoundData>,
}

impl TranscriptManifest {
    pub(crate) fn print(&self) {
        for round in self.manifest.iter() {
            println!("Round: {}", round.0);
            round.1.print();
        }
    }

    pub(crate) fn add_challenge(&mut self, round: usize, labels: &[String]) {
        self.manifest
            .entry(round)
            .or_default()
            .challenge_label
            .extend_from_slice(labels);
    }

    pub(crate) fn add_entry(&mut self, round: usize, element_label: String, element_size: usize) {
        self.manifest
            .entry(round)
            .or_default()
            .entries
            .push((element_label, element_size));
    }

    #[expect(dead_code)]
    pub(crate) fn size(&self) -> usize {
        self.manifest.len()
    }
}

impl Index<usize> for TranscriptManifest {
    type Output = RoundData;

    fn index(&self, index: usize) -> &Self::Output {
        &self.manifest[&index]
    }
}
