// This will be used again but with not yet existing data types

#![expect(unused)]
use crate::types::big_field::BigField;
use crate::types::big_field::NUM_LIMB_BITS;
use crate::types::big_group::BigGroup;
use crate::types::field_ct::CycleScalarCT;
use crate::types::field_ct::FieldCT;
use crate::types::poseidon2::FieldHashCT;
use crate::types::poseidon2::Poseidon2CT;
use crate::{prelude::GenericUltraCircuitBuilder, types::poseidon2::FieldSpongeCT};
use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::PrimeGroup;
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_poly::domain::general::GeneralElements;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::HonkProofError;
use co_noir_common::honk_proof::HonkProofResult;
use num_bigint::BigUint;
use std::{collections::BTreeMap, ops::Index};

pub type Bn254G1 = <Bn254 as Pairing>::G1;
pub type TranscriptFieldType = ark_bn254::Fr;
pub(crate) type Poseidon2SpongeCT<C> =
    FieldSpongeCT<C, 4, 3, Poseidon2CT<<C as PrimeGroup>::ScalarField, 4, 5>>;

pub trait TranscriptHasherCT<P: CurveGroup> {
    fn hash<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        buffer: Vec<FieldCT<P::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<P::ScalarField>>;
}

impl<C: CurveGroup, const T: usize, const R: usize, H: FieldHashCT<C, T> + Default>
    TranscriptHasherCT<C> for FieldSpongeCT<C, T, R, H>
{
    fn hash<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        buffer: Vec<FieldCT<C::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<C::ScalarField>> {
        Self::hash_internal::<1, WT>(&buffer, builder, driver)
    }
}

pub struct TranscriptCT<P, H>
where
    P: CurveGroup,
    H: TranscriptHasherCT<P>,
{
    proof_data: Vec<FieldCT<P::ScalarField>>,
    manifest: TranscriptManifest,
    num_frs_written: usize, // the number of bb::frs written to proof_data by the prover or the verifier
    num_frs_read: usize,    // the number of bb::frs read from proof_data by the verifier
    round_number: usize,
    is_first_challenge: bool,
    current_round_data: Vec<FieldCT<P::ScalarField>>,
    independent_hash_buffer: Vec<FieldCT<P::ScalarField>>,
    previous_challenge: FieldCT<P::ScalarField>,
    phantom_data: std::marker::PhantomData<H>,
}

impl<P, H> Default for TranscriptCT<P, H>
where
    P: CurveGroup,
    H: TranscriptHasherCT<P>,
{
    fn default() -> Self {
        Self::new()
    }
}
impl<P, H> TranscriptCT<P, H>
where
    P: CurveGroup,
    H: TranscriptHasherCT<P>,
{
    pub fn new() -> Self {
        Self {
            num_frs_written: 0,
            num_frs_read: 0,
            round_number: 0,
            is_first_challenge: true,
            ..Default::default()
        }
    }
}

impl<P, H> TranscriptCT<P, H>
where
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasherCT<P>,
{
    pub fn new_verifier(proof: Vec<FieldCT<P::ScalarField>>) -> Self {
        Self {
            proof_data: proof,
            num_frs_written: 0,
            num_frs_read: 0,
            round_number: 0,
            is_first_challenge: true,
            ..Default::default()
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

    pub fn add_element_frs_to_hash_buffer(
        &mut self,
        label: String,
        elements: &[FieldCT<P::ScalarField>],
    ) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data.extend_from_slice(elements);
        self.num_frs_written += len;
    }

    fn add_element_frs_to_independent_hash_buffer(&mut self, elements: &[FieldCT<P::ScalarField>]) {
        self.independent_hash_buffer.extend_from_slice(elements);
    }

    pub fn add_point_to_independent_hash_buffer<
        WT: NoirWitnessExtensionProtocol<P::ScalarField>,
    >(
        &mut self,
        point: &BigGroup<P::ScalarField, WT>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        let shift: BigUint = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shift = FieldCT::from(P::ScalarField::from(shift));
        let mut elements = Self::convert_grumpkin_fr_to_bn254_frs(&point.x, builder, driver)?;
        elements.extend(Self::convert_grumpkin_fr_to_bn254_frs(
            &point.y, builder, driver,
        )?);
        self.add_element_frs_to_independent_hash_buffer(&elements);
        Ok(())
    }

    pub fn add_fr_to_independent_hash_buffer<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        element: &FieldCT<P::ScalarField>,
    ) {
        self.add_element_frs_to_independent_hash_buffer(std::slice::from_ref(element));
    }

    pub fn receive_n_from_prover(
        &mut self,
        label: String,
        n: usize,
    ) -> HonkProofResult<Vec<FieldCT<P::ScalarField>>> {
        if self.num_frs_read + n > self.proof_data.len() {
            return Err(HonkProofError::ProofTooSmall);
        }
        let elements = self.proof_data[self.num_frs_read..self.num_frs_read + n].to_owned();
        self.num_frs_read += n;

        self.add_element_frs_to_hash_buffer(label, &elements);
        Ok(elements)
    }

    pub fn receive_fr_from_prover(
        &mut self,
        label: String,
    ) -> HonkProofResult<FieldCT<P::ScalarField>> {
        let elements = self.receive_n_from_prover(label, P::NUM_SCALARFIELD_ELEMENTS)?;
        debug_assert!((elements.len() == 1));

        Ok(elements[0].clone())
    }

    pub fn receive_point_from_prover<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        label: String,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> HonkProofResult<BigGroup<P::ScalarField, WT>> {
        let mut elements = self.receive_n_from_prover(label, P::NUM_BASEFIELD_ELEMENTS * 2)?;
        debug_assert!(elements.len() == P::NUM_BASEFIELD_ELEMENTS * 2);

        let y = elements.split_off(P::NUM_BASEFIELD_ELEMENTS);
        let x = elements;

        debug_assert!(
            x.len() == 2 && y.len() == 2,
            "Expected 2 field elements per coordinate"
        );

        let [x_lo, x_hi] = x.try_into().unwrap();
        let [y_lo, y_hi] = y.try_into().unwrap();

        let sum = FieldCT::default()
            .add_two(&x_lo, &x_hi, builder, driver)
            .add_two(&y_lo, &y_hi, builder, driver);

        let x = BigField::from_slices(x_lo, x_hi, driver, builder)?;
        let y = BigField::from_slices(y_lo, y_hi, driver, builder)?;

        let mut result = BigGroup::new(x, y);

        let is_zero = sum.is_zero(builder, driver)?;
        result.set_is_infinity(is_zero);
        Ok(result)
    }

    pub fn send_point_to_verifier<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        label: String,
        point: &BigGroup<P::ScalarField, WT>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        let shift: BigUint = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shift = FieldCT::from(P::ScalarField::from(shift));
        let mut elements = Self::convert_grumpkin_fr_to_bn254_frs(&point.x, builder, driver)?;
        elements.extend(Self::convert_grumpkin_fr_to_bn254_frs(
            &point.y, builder, driver,
        )?);
        self.send_to_verifier(label, &elements.to_vec());
        Ok(())
    }

    fn send_to_verifier(&mut self, label: String, elements: &[FieldCT<P::ScalarField>]) {
        self.proof_data.extend_from_slice(elements);
        self.add_element_frs_to_hash_buffer(label, elements);
    }

    fn split_challenge<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        challenge: &FieldCT<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<[FieldCT<P::ScalarField>; 2]> {
        // use existing field-splitting code in cycle_scalar
        let scalar = CycleScalarCT::from_field_ct(challenge, builder, driver)?;
        scalar.lo.create_range_constraint::<P, WT>(
            CycleScalarCT::<P::ScalarField>::LO_BITS,
            builder,
            driver,
        )?;
        scalar.hi.create_range_constraint(
            CycleScalarCT::<P::ScalarField>::HI_BITS,
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
    ) -> eyre::Result<[FieldCT<P::ScalarField>; 2]> {
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
            full_buffer.insert(0, self.previous_challenge.clone());
        }

        // Hash the full buffer with poseidon2, which is believed to be a collision resistant hash function and a random
        // oracle, removing the need to pre-hash to compress and then hash with a random oracle, as we previously did
        // with Pedersen and Blake3s.
        let new_challenge = H::hash(full_buffer, builder, driver)?;
        let new_challenges = Self::split_challenge(&new_challenge, builder, driver)?;

        // update previous challenge buffer for next time we call this function
        self.previous_challenge = new_challenge;
        Ok(new_challenges)
    }

    pub fn get_challenge<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        label: String,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<P::ScalarField>> {
        self.manifest.add_challenge(self.round_number, &[label]);
        self.round_number += 1;
        Ok(self.get_next_duplex_challenge_buffer(1, builder, driver)?[0].clone())
    }

    pub fn get_challenges<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        labels: &[String],
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<P::ScalarField>>> {
        let num_challenges = labels.len();
        self.manifest.add_challenge(self.round_number, labels);

        let mut res = Vec::with_capacity(num_challenges);
        for _ in 0..num_challenges >> 1 {
            let challenge_buffer = self.get_next_duplex_challenge_buffer(2, builder, driver)?;
            res.push(challenge_buffer[0].clone()); // We don't need to convert here as we are in a fr-builder setting
            res.push(challenge_buffer[1].clone());
        }
        if num_challenges & 1 == 1 {
            let challenge_buffer = self.get_next_duplex_challenge_buffer(1, builder, driver)?;
            res.push(challenge_buffer[0].clone());
        }

        self.round_number += 1;
        Ok(res.to_owned())
    }

    pub fn hash_independent_buffer<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<P::ScalarField>> {
        H::hash(
            std::mem::take(&mut self.independent_hash_buffer),
            builder,
            driver,
        )
    }

    fn compute_round_challenge_pows<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &self,
        num_powers: usize,
        round_challenge: FieldCT<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<P::ScalarField>>> {
        let mut pows = Vec::with_capacity(num_powers);
        if num_powers > 0 {
            pows.push(round_challenge);
            for i in 1..num_powers {
                pows.push(pows[i - 1].multiply(&pows[i - 1], builder, driver)?);
            }
        }
        Ok(pows)
    }

    pub fn get_powers_of_challenge<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        &mut self,
        label: String,
        num_challenges: usize,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<P::ScalarField>>> {
        let challenge = self.get_challenge(label, builder, driver)?;
        self.compute_round_challenge_pows(num_challenges, challenge, builder, driver)
    }

    fn convert_grumpkin_fr_to_bn254_frs<WT: NoirWitnessExtensionProtocol<P::ScalarField>>(
        element: &BigField<P::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<P, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<P::ScalarField>>> {
        let shift: BigUint = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shift = FieldCT::from(P::ScalarField::from(shift));
        let mut elements = Vec::with_capacity(P::NUM_BASEFIELD_ELEMENTS);
        elements.push(
            element.binary_basis_limbs[1]
                .element
                .multiply(&shift, builder, driver)?
                .add(&element.binary_basis_limbs[0].element, builder, driver),
        );
        elements.push(
            element.binary_basis_limbs[3]
                .element
                .multiply(&shift, builder, driver)?
                .add(&element.binary_basis_limbs[2].element, builder, driver),
        );
        Ok(elements)
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
            println!("\tchallenge: {label}");
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
