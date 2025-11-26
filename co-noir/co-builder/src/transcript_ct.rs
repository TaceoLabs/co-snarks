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
        Self {
            proof_data: Vec::new(),
            manifest: Default::default(),
            num_frs_written: 0,
            num_frs_read: 0,
            round_number: 0,
            is_first_challenge: false,
            current_round_data: Default::default(),
            previous_challenge: Default::default(),
            phantom_data: Default::default(),
            independent_hash_buffer: Vec::new(),
        }
    }
}
impl<P, H> TranscriptCT<P, H>
where
    P: CurveGroup,
    H: TranscriptHasherCT<P>,
{
    pub fn new() -> Self {
        Self {
            is_first_challenge: true,
            ..Default::default()
        }
    }
}

impl<C, H> TranscriptCT<C, H>
where
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasherCT<C>,
{
    pub fn new_verifier(proof: Vec<FieldCT<C::ScalarField>>) -> Self {
        Self {
            proof_data: proof,
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
        elements: &[FieldCT<C::ScalarField>],
    ) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data.extend_from_slice(elements);
        self.num_frs_written += len;
    }

    fn add_element_frs_to_independent_hash_buffer(&mut self, elements: &[FieldCT<C::ScalarField>]) {
        self.independent_hash_buffer.extend_from_slice(elements);
    }

    pub fn add_point_to_independent_hash_buffer<
        WT: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        &mut self,
        point: &BigGroup<C::ScalarField, WT>,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        let shift: BigUint = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shift = FieldCT::from(C::ScalarField::from(shift));
        let mut elements = Self::convert_grumpkin_fr_to_bn254_frs(&point.x, builder, driver)?;
        elements.extend(Self::convert_grumpkin_fr_to_bn254_frs(
            &point.y, builder, driver,
        )?);
        self.add_element_frs_to_independent_hash_buffer(&elements);
        Ok(())
    }

    pub fn add_fr_to_independent_hash_buffer<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        element: &FieldCT<C::ScalarField>,
    ) {
        self.add_element_frs_to_independent_hash_buffer(std::slice::from_ref(element));
    }

    pub fn receive_n_from_prover(
        &mut self,
        label: String,
        n: usize,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
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
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let elements = self.receive_n_from_prover(label, C::NUM_SCALARFIELD_ELEMENTS)?;
        debug_assert!((elements.len() == 1));

        Ok(elements[0].clone())
    }

    pub fn receive_point_from_prover<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        label: String,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> HonkProofResult<BigGroup<C::ScalarField, WT>> {
        let mut elements = self.receive_n_from_prover(label, C::NUM_BASEFIELD_ELEMENTS * 2)?;
        debug_assert!(elements.len() == C::NUM_BASEFIELD_ELEMENTS * 2);

        let [x_lo, x_hi] = [&elements[0], &elements[1]];
        let [y_lo, y_hi] = [&elements[2], &elements[3]];

        let x = BigField::from_slices(x_lo, x_hi, driver, builder)?;
        let y = BigField::from_slices(y_lo, y_hi, driver, builder)?;
        let is_zero = FieldCT::check_point_at_infinity::<C, WT>(&elements, builder, driver)?;

        let mut result = BigGroup::new(x, y);

        result.set_point_at_infinity(is_zero, builder, driver);
        // Note that in the case of bn254 with Mega arithmetization, the check is delegated to ECCVM, see
        // `on_curve_check` in `ECCVMTranscriptRelationImpl`.
        result.validate_on_curve(builder, driver)?;
        Ok(result)
    }

    pub fn send_point_to_verifier<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        label: String,
        point: &BigGroup<C::ScalarField, WT>,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<()> {
        let shift: BigUint = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shift = FieldCT::from(C::ScalarField::from(shift));
        let mut elements = Self::convert_grumpkin_fr_to_bn254_frs(&point.x, builder, driver)?;
        elements.extend(Self::convert_grumpkin_fr_to_bn254_frs(
            &point.y, builder, driver,
        )?);
        self.send_to_verifier(label, &elements.to_vec());
        Ok(())
    }

    fn send_to_verifier(&mut self, label: String, elements: &[FieldCT<C::ScalarField>]) {
        self.proof_data.extend_from_slice(elements);
        self.add_element_frs_to_hash_buffer(label, elements);
    }

    fn split_challenge<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        challenge: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<[FieldCT<C::ScalarField>; 2]> {
        let lo = CycleScalarCT::<C::ScalarField>::MAX_BITS_PER_ENDOMORPHISM_SCALAR;
        challenge.split_unique(lo, builder, driver)
    }

    fn get_next_duplex_challenge_buffer<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        num_challenges: usize,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<[FieldCT<C::ScalarField>; 2]> {
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

    pub fn get_challenge<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        label: String,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<C::ScalarField>> {
        self.manifest.add_challenge(self.round_number, &[label]);
        self.round_number += 1;
        Ok(self.get_next_duplex_challenge_buffer(1, builder, driver)?[0].clone())
    }

    pub fn get_challenges<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        labels: &[String],
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<C::ScalarField>>> {
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

    pub fn hash_independent_buffer<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<FieldCT<C::ScalarField>> {
        H::hash(
            std::mem::take(&mut self.independent_hash_buffer),
            builder,
            driver,
        )
    }

    fn compute_round_challenge_pows<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &self,
        num_powers: usize,
        round_challenge: FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<C::ScalarField>>> {
        let mut pows = Vec::with_capacity(num_powers);
        if num_powers > 0 {
            pows.push(round_challenge);
            for i in 1..num_powers {
                pows.push(pows[i - 1].multiply(&pows[i - 1], builder, driver)?);
            }
        }
        Ok(pows)
    }

    pub fn get_powers_of_challenge<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &mut self,
        label: String,
        num_challenges: usize,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<C::ScalarField>>> {
        let challenge = self.get_challenge(label, builder, driver)?;
        self.compute_round_challenge_pows(num_challenges, challenge, builder, driver)
    }

    fn convert_grumpkin_fr_to_bn254_frs<WT: NoirWitnessExtensionProtocol<C::ScalarField>>(
        element: &BigField<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, WT>,
        driver: &mut WT,
    ) -> eyre::Result<Vec<FieldCT<C::ScalarField>>> {
        let shift: BigUint = BigUint::from(1u64) << NUM_LIMB_BITS;
        let shift = FieldCT::from(C::ScalarField::from(shift));
        let mut elements = Vec::with_capacity(C::NUM_BASEFIELD_ELEMENTS);
        elements.push(
            element.binary_basis_limbs[0].element.add(
                &element.binary_basis_limbs[1]
                    .element
                    .multiply(&shift, builder, driver)?,
                builder,
                driver,
            ),
        );
        elements.push(
            element.binary_basis_limbs[2].element.add(
                &element.binary_basis_limbs[3]
                    .element
                    .multiply(&shift, builder, driver)?,
                builder,
                driver,
            ),
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
