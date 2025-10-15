use crate::honk_curve::HonkCurve;
use crate::honk_proof::TranscriptFieldType;
use crate::mpc::NoirUltraHonkProver;
use crate::sponge_hasher::{FieldHash, FieldSponge};
use crate::sponge_hasher_mpc::{FieldHashRep3, FieldSpongeRep3};
use crate::transcript::{Transcript, TranscriptHasher, TranscriptManifest};
use ark_ec::AffineRepr;
use ark_ff::{One, PrimeField, Zero};
use mpc_core::MpcState;
use mpc_core::gadgets::poseidon2::Poseidon2;
use mpc_net::Network;
use noir_types::HonkProof;
use num_bigint::BigUint;
use std::any::TypeId;

pub type Poseidon2SpongeRep3<U> =
    FieldSpongeRep3<U, ark_bn254::G1Projective, 4, 3, Poseidon2<TranscriptFieldType, 4, 5>>;

impl<
    F: PrimeField,
    U: NoirUltraHonkProver<C>,
    C: HonkCurve<F>,
    const T: usize,
    const R: usize,
    H: FieldHashRep3<U, C, T> + FieldHash<F, T> + Default,
> TranscriptHasher<F, U, C> for FieldSpongeRep3<U, C, T, R, H>
{
    fn hash(buffer: Vec<F>) -> F {
        FieldSponge::<F, T, R, H>::hash_fixed_length::<1>(&buffer)[0]
    }
    fn hash_rep3<N: Network>(
        buffer: Vec<<U as NoirUltraHonkProver<C>>::ArithmeticShare>,
        net: &N,
        mpc_state: &mut U::State,
    ) -> eyre::Result<<U as NoirUltraHonkProver<C>>::ArithmeticShare> {
        let res =
            FieldSpongeRep3::<U, C, T, R, H>::hash_fixed_length::<1, N>(&buffer, net, mpc_state)?
                [0];
        Ok(res)
    }
}

pub enum TranscriptRef<'a, F, T, C, H>
where
    F: PrimeField,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<F>,
    H: TranscriptHasher<F, T, C>,
{
    Plain(&'a mut Transcript<F, H, T, C>),
    Rep3(&'a mut TranscriptRep3<F, T, C, H>),
}

impl<'a, F, T, C, H> TranscriptRef<'a, F, T, C, H>
where
    F: PrimeField,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<F>,
    H: TranscriptHasher<F, T, C>,
{
    pub fn get_proof(self) -> (Option<HonkProof<F>>, Option<Vec<T::ArithmeticShare>>) {
        match self {
            TranscriptRef::Plain(transcript) => (Some(transcript.get_proof_ref()), None),
            TranscriptRef::Rep3(transcript_rep3) => (None, Some(transcript_rep3.get_proof())),
        }
    }
}

pub struct TranscriptRep3<F, T, C, H>
where
    F: PrimeField,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<F>,
    H: TranscriptHasher<F, T, C>,
{
    proof_data_rep3: Vec<T::ArithmeticShare>,
    manifest: TranscriptManifest,
    num_frs_written: usize, // the number of bb::frs written to proof_data by the prover or the verifier
    round_number: usize,
    is_first_challenge: bool,
    current_round_data_shared: Vec<(Vec<T::ArithmeticShare>, usize)>, // We keep the order in which the elements are sent to the verifier in order to be able to process plain data in plain
    current_round_data_public: Vec<(Vec<F>, usize)>, // For the case that we only added public elements in between two challenges, we want to be able to compute the hash in plain
    current_round_data_points_shared: Vec<(T::PointShare, usize)>,
    current_idx: usize,
    previous_challenge: F,
    phantom_data: std::marker::PhantomData<(H, F)>,
}

impl<F, T, C, H> Default for TranscriptRep3<F, T, C, H>
where
    F: PrimeField,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<F>,
    H: TranscriptHasher<F, T, C>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, T, C, H> TranscriptRep3<F, T, C, H>
where
    F: PrimeField,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<F>,
    H: TranscriptHasher<F, T, C>,
{
    const CURVE_POINT_NUM_FRS: usize = 4;

    pub fn new() -> Self {
        if TypeId::of::<C>()
            != TypeId::of::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>()
        {
            panic!("Only BN254 is supported");
        }
        Self {
            num_frs_written: 0,
            round_number: 0,
            is_first_challenge: true,
            current_round_data_shared: Vec::new(),
            current_round_data_public: Vec::new(),
            current_round_data_points_shared: Vec::new(),
            current_idx: 0,
            previous_challenge: Default::default(),
            proof_data_rep3: Vec::new(),
            manifest: Default::default(),
            phantom_data: std::marker::PhantomData,
        }
    }

    pub fn get_proof(&self) -> Vec<T::ArithmeticShare> {
        self.proof_data_rep3.clone()
    }

    #[expect(dead_code)]
    pub(crate) fn print(&self) {
        self.manifest.print();
    }

    #[expect(dead_code)]
    pub(crate) fn get_manifest(&self) -> &TranscriptManifest {
        &self.manifest
    }

    fn add_element_frs_to_hash_buffer(&mut self, label: String, elements: &[F]) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data_public
            .push((elements.to_vec(), self.current_idx));
        self.current_idx += 1;
        self.num_frs_written += len;
    }

    fn add_element_frs_to_hash_buffer_shared(
        &mut self,
        label: String,
        elements: &[T::ArithmeticShare],
    ) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data_shared
            .push((elements.to_vec(), self.current_idx));
        self.current_idx += 1;
        self.num_frs_written += len;
    }

    fn convert_point<P: HonkCurve<F>>(element: P::Affine) -> Vec<F> {
        let (x, y) = if element.is_zero() {
            // we are at infinity
            (P::BaseField::zero(), P::BaseField::zero())
        } else {
            P::g1_affine_to_xy(&element)
        };

        let mut res = P::convert_basefield_into(&x);
        res.extend(P::convert_basefield_into(&y));

        res
    }

    // Adds an element to the transcript.
    // Serializes the element to frs and adds it to the current_round_data buffer. Does NOT add the element to the proof. This is used for elements which should be part of the transcript but are not in the final proof (e.g. circuit size)
    fn add_to_hash_buffer(&mut self, label: String, elements: &[F]) {
        self.add_element_frs_to_hash_buffer(label, elements);
    }

    fn send_to_verifier(&mut self, label: String, elements: &[F]) {
        self.add_element_frs_to_hash_buffer(label, elements);
    }

    fn send_to_verifier_shared(&mut self, label: String, elements: &[T::ArithmeticShare]) {
        self.add_element_frs_to_hash_buffer_shared(label, elements);
    }

    pub fn send_fr_to_verifier(&mut self, label: String, element: C::ScalarField) {
        let elements = C::convert_scalarfield_into(&element);
        self.send_to_verifier(label, &elements);
    }

    pub fn send_fr_to_verifier_shared(&mut self, label: String, element: T::ArithmeticShare) {
        self.send_to_verifier_shared(label, &[element]);
    }

    pub fn send_u64_to_verifier(&mut self, label: String, element: u64) {
        let el = F::from(element);
        self.send_to_verifier(label, &[el]);
    }

    pub fn add_u64_to_hash_buffer(&mut self, label: String, element: u64) {
        let el = F::from(element);
        self.add_to_hash_buffer(label, &[el]);
    }

    pub fn send_point_to_verifier(&mut self, label: String, element: C::Affine) {
        let elements = Self::convert_point::<C>(element);
        self.send_to_verifier(label, &elements);
    }

    pub fn send_point_to_verifier_shared(&mut self, label: String, element: T::PointShare) {
        // This is very hardcoded to bn254 where a point is split into 4 scalarfield elements and then sent to the verifier
        // Since we do the decomposition of curve points in a batched way once a challenge is requested, we add the manifest data here already
        let len = Self::CURVE_POINT_NUM_FRS;
        self.manifest.add_entry(self.round_number, label, len);
        self.num_frs_written += len;
        self.current_round_data_points_shared
            .push((element, self.current_idx));
        self.current_idx += 1;
    }

    pub fn send_fr_iter_to_verifier<'a, I: IntoIterator<Item = &'a C::ScalarField>>(
        &mut self,
        label: String,
        element: I,
    ) {
        let elements = element
            .into_iter()
            .flat_map(C::convert_scalarfield_into)
            .collect::<Vec<_>>();
        self.send_to_verifier(label, &elements);
    }

    pub fn send_fr_iter_to_verifier_shared(
        &mut self,
        label: String,
        elements: &[T::ArithmeticShare],
    ) {
        // Use copied() which is more efficient than cloning for Copy types
        self.send_to_verifier_shared(label, elements);
    }

    fn split_challenge(challenge: C::ScalarField) -> [C::ScalarField; 2] {
        // match the parameter used in stdlib, which is derived from cycle_scalar (is 128)
        const LO_BITS: usize = 128;
        let biguint: BigUint = challenge.into();

        let lower_mask = (BigUint::one() << LO_BITS) - BigUint::one();
        let lo = &biguint & lower_mask;
        let hi = biguint >> LO_BITS;

        let lo = C::ScalarField::from(lo);
        let hi = C::ScalarField::from(hi);

        [lo, hi]
    }

    fn get_next_duplex_challenge_buffer<N: Network>(
        &mut self,
        num_challenges: usize,
        net: &N,
        mpc_state: &mut T::State,
    ) -> eyre::Result<[C::ScalarField; 2]>
    where
        C: HonkCurve<F>,
    {
        // The MPC version of the transcript only supports BN254 for now but since it will be only used for non-ECCVM flavours at the moment this is fine.
        if TypeId::of::<C>()
            != TypeId::of::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>()
        {
            panic!("Only BN254 is supported");
        }

        // challenges need at least 110 bits in them to match the presumed security parameter of the BN254 curve.
        assert!(num_challenges <= 2);
        // Prevent challenge generation if this is the first challenge we're generating,
        // AND nothing was sent by the prover.
        if self.is_first_challenge {
            assert!(
                !self.current_round_data_shared.is_empty()
                    || !self.current_round_data_public.is_empty()
                    || !self.current_round_data_points_shared.is_empty(),
                "The prover did not send any data before the first challenge was requested. This is not intended behavior."
            );
        }
        // concatenate the previous challenge (if this is not the first challenge) with the current round data.
        // AZTEC TODO(Adrian): Do we want to use a domain separator as the initial challenge buffer?
        // We could be cheeky and use the hash of the manifest as domain separator, which would prevent us from having
        // to domain separate all the data. (See https://safe-hash.dev)

        if !self.current_round_data_public.is_empty() {
            if self.current_round_data_shared.is_empty() {
                if self.current_round_data_points_shared.is_empty() {
                    // If we only have public data, we can compute the hash in plain
                    let total_size = self
                        .current_round_data_public
                        .iter()
                        .map(|(v, _)| v.len())
                        .sum();
                    let mut full_buffer = Vec::with_capacity(total_size);
                    for (v, _) in &self.current_round_data_public {
                        full_buffer.extend_from_slice(v);
                    }
                    self.current_round_data_public.clear();
                    self.proof_data_rep3.extend(
                        T::promote_to_trivial_shares(
                            mpc_state.id(),
                            &full_buffer
                                .iter()
                                .map(|f| C::convert_destinationfield_to_scalarfield(f))
                                .collect::<Vec<_>>(),
                        )
                        .iter(),
                    );

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
                    let new_challenge = H::hash(full_buffer);
                    let new_challenges = Self::split_challenge(
                        C::convert_destinationfield_to_scalarfield(&new_challenge),
                    );

                    // update previous challenge buffer for next time we call this function
                    self.previous_challenge = new_challenge;
                    Ok(new_challenges)
                } else {
                    let point_data = T::pointshare_to_field_shares_many(
                        self.current_round_data_points_shared
                            .iter()
                            .map(|(p, _)| *p)
                            .collect::<Vec<_>>()
                            .as_slice(),
                        net,
                        mpc_state,
                    )?;
                    let total_size = self
                        .current_round_data_public
                        .iter()
                        .map(|(p, _)| p.len())
                        .sum();
                    let mut flattened_data = Vec::with_capacity(total_size);
                    for (p, _) in &self.current_round_data_public {
                        flattened_data.extend_from_slice(p);
                    }
                    let promoted_public_data = T::promote_to_trivial_shares(
                        mpc_state.id(),
                        &flattened_data
                            .iter()
                            .map(|f| C::convert_destinationfield_to_scalarfield(f))
                            .collect::<Vec<_>>(),
                    );
                    let capacity = self.current_round_data_shared.len()
                        + self.current_round_data_public.len()
                        + self.current_round_data_points_shared.len();
                    let mut indexed_data = Vec::with_capacity(capacity);
                    for (i, (_, idx)) in self.current_round_data_points_shared.iter().enumerate() {
                        // For each point share, get the corresponding 4 field shares
                        let start_idx = i * 4;
                        let end_idx = start_idx + 4;
                        if end_idx <= point_data.len() {
                            indexed_data.push((*idx, point_data[start_idx..end_idx].to_vec()));
                        }
                    }
                    let mut promoted_idx = 0;
                    for (data, idx) in &self.current_round_data_public {
                        let len = data.len();
                        let promoted_slice =
                            &promoted_public_data[promoted_idx..promoted_idx + len];
                        indexed_data.push((*idx, promoted_slice.to_vec()));
                        promoted_idx += len;
                    }
                    indexed_data.sort_by_key(|(idx, _)| *idx);
                    let mut full_buffer = Vec::with_capacity(capacity);
                    for (_, data) in indexed_data {
                        full_buffer.extend(data);
                    }
                    self.current_round_data_public.clear();
                    self.current_round_data_shared.clear();
                    self.current_round_data_points_shared.clear();
                    self.proof_data_rep3.extend(full_buffer.iter());

                    if self.is_first_challenge {
                        // Update is_first_challenge for the future
                        self.is_first_challenge = false;
                    } else {
                        // if not the first challenge, we can use the previous_challenge
                        full_buffer.insert(
                            0,
                            T::promote_to_trivial_share(
                                mpc_state.id(),
                                C::convert_destinationfield_to_scalarfield(
                                    &self.previous_challenge,
                                ),
                            ),
                        );
                    }

                    // Hash the full buffer with poseidon2, which is believed to be a collision resistant hash function and a random
                    // oracle, removing the need to pre-hash to compress and then hash with a random oracle, as we previously did
                    // with Pedersen and Blake3s.
                    let new_challenge = H::hash_rep3(full_buffer, net, mpc_state)?;
                    let opened_challenge = T::open_many(&[new_challenge], net, mpc_state)?[0];

                    let new_challenges = Self::split_challenge(opened_challenge);

                    // update previous challenge buffer for next time we call this function
                    self.previous_challenge = C::convert_scalarfield_into(&opened_challenge)[0];
                    Ok(new_challenges)
                }
            } else {
                let points = if !self.current_round_data_points_shared.is_empty() {
                    let res = T::pointshare_to_field_shares_many(
                        self.current_round_data_points_shared
                            .iter()
                            .map(|(p, _)| *p)
                            .collect::<Vec<_>>()
                            .as_slice(),
                        net,
                        mpc_state,
                    )?;
                    Some(res)
                } else {
                    None
                };
                let total_size = self
                    .current_round_data_public
                    .iter()
                    .map(|(p, _)| p.len())
                    .sum();
                let mut flattened_data = Vec::with_capacity(total_size);
                for (p, _) in &self.current_round_data_public {
                    flattened_data.extend_from_slice(p);
                }
                let promoted_public_data = T::promote_to_trivial_shares(
                    mpc_state.id(),
                    &flattened_data
                        .iter()
                        .map(|f| C::convert_destinationfield_to_scalarfield(f))
                        .collect::<Vec<_>>(),
                );
                let capacity = self.current_round_data_shared.len()
                    + self.current_round_data_public.len()
                    + self.current_round_data_points_shared.len();
                let mut indexed_data = Vec::with_capacity(capacity);
                for (data, idx) in &self.current_round_data_shared {
                    indexed_data.push((*idx, data.clone()));
                }
                if let Some(point_data) = &points {
                    for (i, (_, idx)) in self.current_round_data_points_shared.iter().enumerate() {
                        // For each point share, get the corresponding 4 field shares
                        let start_idx = i * 4;
                        let end_idx = start_idx + 4;
                        if end_idx <= point_data.len() {
                            indexed_data.push((*idx, point_data[start_idx..end_idx].to_vec()));
                        }
                    }
                }
                let mut promoted_idx = 0;
                for (data, idx) in &self.current_round_data_public {
                    let len = data.len();
                    let promoted_slice = &promoted_public_data[promoted_idx..promoted_idx + len];
                    indexed_data.push((*idx, promoted_slice.to_vec()));
                    promoted_idx += len;
                }
                indexed_data.sort_by_key(|(idx, _)| *idx);
                let mut full_buffer = Vec::with_capacity(capacity);
                for (_, data) in indexed_data {
                    full_buffer.extend(data);
                }
                self.current_round_data_public.clear();
                self.current_round_data_shared.clear();
                self.current_round_data_points_shared.clear();
                self.proof_data_rep3.extend(full_buffer.iter());

                if self.is_first_challenge {
                    // Update is_first_challenge for the future
                    self.is_first_challenge = false;
                } else {
                    // if not the first challenge, we can use the previous_challenge
                    full_buffer.insert(
                        0,
                        T::promote_to_trivial_share(
                            mpc_state.id(),
                            C::convert_destinationfield_to_scalarfield(&self.previous_challenge),
                        ),
                    );
                }

                // Hash the full buffer with poseidon2, which is believed to be a collision resistant hash function and a random
                // oracle, removing the need to pre-hash to compress and then hash with a random oracle, as we previously did
                // with Pedersen and Blake3s.
                let new_challenge = H::hash_rep3(full_buffer, net, mpc_state)?;
                let opened_challenge = T::open_many(&[new_challenge], net, mpc_state)?[0];

                let new_challenges = Self::split_challenge(opened_challenge);

                // update previous challenge buffer for next time we call this function
                self.previous_challenge = C::convert_scalarfield_into(&opened_challenge)[0];
                Ok(new_challenges)
            }
        } else {
            let points = if !self.current_round_data_points_shared.is_empty() {
                let res = T::pointshare_to_field_shares_many(
                    self.current_round_data_points_shared
                        .iter()
                        .map(|(p, _)| *p)
                        .collect::<Vec<_>>()
                        .as_slice(),
                    net,
                    mpc_state,
                )?;
                Some(res)
            } else {
                None
            };
            let capacity = self.current_round_data_shared.len()
                + self.current_round_data_public.len()
                + self.current_round_data_points_shared.len();
            let mut indexed_data = Vec::with_capacity(capacity);
            for (data, idx) in &self.current_round_data_shared {
                indexed_data.push((*idx, data.clone()));
            }
            if let Some(point_data) = &points {
                for (i, (_, idx)) in self.current_round_data_points_shared.iter().enumerate() {
                    // For each point share, get the corresponding 4 field shares
                    let start_idx = i * 4;
                    let end_idx = start_idx + 4;
                    if end_idx <= point_data.len() {
                        indexed_data.push((*idx, point_data[start_idx..end_idx].to_vec()));
                    }
                }
            }
            indexed_data.sort_by_key(|(idx, _)| *idx);
            let mut full_buffer = Vec::with_capacity(capacity);
            for (_, data) in indexed_data {
                full_buffer.extend(data);
            }
            self.current_round_data_public.clear();
            self.current_round_data_shared.clear();
            self.current_round_data_points_shared.clear();
            self.proof_data_rep3.extend(full_buffer.iter());

            if self.is_first_challenge {
                // Update is_first_challenge for the future
                self.is_first_challenge = false;
            } else {
                // if not the first challenge, we can use the previous_challenge
                full_buffer.insert(
                    0,
                    T::promote_to_trivial_share(
                        mpc_state.id(),
                        C::convert_destinationfield_to_scalarfield(&self.previous_challenge),
                    ),
                );
            }

            // Hash the full buffer with poseidon2, which is believed to be a collision resistant hash function and a random
            // oracle, removing the need to pre-hash to compress and then hash with a random oracle, as we previously did
            // with Pedersen and Blake3s.
            let new_challenge = H::hash_rep3(full_buffer, net, mpc_state)?;
            let opened_challenge = T::open_many(&[new_challenge], net, mpc_state)?[0];

            let new_challenges = Self::split_challenge(opened_challenge);

            // update previous challenge buffer for next time we call this function
            self.previous_challenge = C::convert_scalarfield_into(&opened_challenge)[0];
            Ok(new_challenges)
        }
    }

    pub fn get_challenge<N: Network>(
        &mut self,
        label: String,
        net: &N,
        mpc_state: &mut T::State,
    ) -> eyre::Result<C::ScalarField>
    where
        C: HonkCurve<F>,
    {
        self.manifest.add_challenge(self.round_number, &[label]);
        let res = self.get_next_duplex_challenge_buffer(1, net, mpc_state)?[0];
        // let res = C::convert_destinationfield_to_scalarfield(&challenge);
        self.round_number += 1;
        Ok(res)
    }

    pub fn get_challenges<N: Network>(
        &mut self,
        labels: &[String],
        net: &N,
        mpc_state: &mut T::State,
    ) -> eyre::Result<Vec<C::ScalarField>>
    where
        C: HonkCurve<F>,
    {
        let num_challenges = labels.len();
        self.manifest.add_challenge(self.round_number, labels);

        let mut res = Vec::with_capacity(num_challenges);
        for _ in 0..num_challenges >> 1 {
            let challenge_buffer = self.get_next_duplex_challenge_buffer(2, net, mpc_state)?;
            res.push(challenge_buffer[0]);
            res.push(challenge_buffer[1]);
        }
        if num_challenges & 1 == 1 {
            let challenge_buffer = self.get_next_duplex_challenge_buffer(1, net, mpc_state)?;
            res.push(challenge_buffer[0]);
        }

        self.round_number += 1;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::honk_proof::TranscriptFieldType;
    use crate::mpc::NoirUltraHonkProver;
    use crate::mpc::plain::PlainUltraHonkDriver;
    use crate::mpc::rep3::Rep3UltraHonkDriver;
    use crate::transcript::Poseidon2Sponge;
    use crate::transcript::Transcript;
    use crate::transcript_mpc::FieldSpongeRep3;
    use crate::transcript_mpc::TranscriptRep3;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use itertools::izip;
    use mpc_core::gadgets::poseidon2::Poseidon2;
    use mpc_core::protocols::rep3;
    use mpc_core::protocols::rep3::Rep3State;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_net::local::LocalNetwork;
    use std::thread;

    #[test]
    fn rep3_transcript_poseidon_plaindriver() {
        const VEC_SIZE: usize = 10;
        let mut thread_rng = rand::thread_rng();
        let mut rep3_transcript = TranscriptRep3::<
            TranscriptFieldType,
            PlainUltraHonkDriver,
            ark_bn254::G1Projective,
            FieldSpongeRep3<
                PlainUltraHonkDriver,
                ark_bn254::G1Projective,
                4,
                3,
                Poseidon2<TranscriptFieldType, 4, 5>,
            >,
        >::new();
        let mut plain_transcript = Transcript::<
            TranscriptFieldType,
            Poseidon2Sponge,
            PlainUltraHonkDriver,
            ark_bn254::G1Projective,
        >::new();

        let fr_vec = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut thread_rng))
            .collect::<Vec<_>>();
        let point_vec = (0..VEC_SIZE)
            .map(|_| ark_bn254::G1Projective::rand(&mut thread_rng).into_affine())
            .collect::<Vec<_>>();
        let u64_vec = (0..VEC_SIZE)
            .map(|_| rand::random::<u64>())
            .collect::<Vec<_>>();
        for ((i, f), p, u) in izip!(fr_vec.iter().enumerate(), point_vec.iter(), u64_vec.iter()) {
            if i % 3 == 0 {
                plain_transcript
                    .send_fr_to_verifier::<ark_bn254::G1Projective>(format!("fr_vec_{}", i), *f);
                rep3_transcript.send_fr_to_verifier_shared(
                    format!("fr_vec_{}", i),
                    <PlainUltraHonkDriver as NoirUltraHonkProver<ark_bn254::G1Projective>>::promote_to_trivial_share(0, *f),
                );
                plain_transcript.send_point_to_verifier::<ark_bn254::G1Projective>(
                    format!("point_vec_{}", i),
                    *p,
                );
                rep3_transcript
                    .send_point_to_verifier_shared(format!("point_vec_{}", i), (*p).into());
                plain_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                rep3_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
            } else if i % 3 == 1 {
                plain_transcript.send_point_to_verifier::<ark_bn254::G1Projective>(
                    format!("point_vec_{}", i),
                    *p,
                );
                rep3_transcript.send_point_to_verifier(format!("point_vec_{}", i), *p);
                plain_transcript
                    .send_fr_to_verifier::<ark_bn254::G1Projective>(format!("fr_vec_{}", i), *f);
                rep3_transcript.send_fr_to_verifier(format!("fr_vec_{}", i), *f);
                plain_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                rep3_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
            } else {
                plain_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                rep3_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                plain_transcript.send_point_to_verifier::<ark_bn254::G1Projective>(
                    format!("point_vec_{}", i),
                    *p,
                );
                rep3_transcript
                    .send_point_to_verifier_shared(format!("point_vec_{}", i), (*p).into());
                plain_transcript
                    .send_fr_to_verifier::<ark_bn254::G1Projective>(format!("fr_vec_{}", i), *f);
                rep3_transcript.send_fr_to_verifier_shared(
                    format!("fr_vec_{}", i),
                    <PlainUltraHonkDriver as NoirUltraHonkProver<ark_bn254::G1Projective>>::promote_to_trivial_share(0, *f),
                );
            }
            let rep3_challenge = rep3_transcript
                .get_challenge::<_>(format!("challenge{i}"), &(), &mut ())
                .unwrap();
            let plain_challenge =
                plain_transcript.get_challenge::<ark_bn254::G1Projective>(format!("challenge{i}"));
            assert_eq!(rep3_challenge, plain_challenge);
        }
        plain_transcript.send_fr_iter_to_verifier::<ark_bn254::G1Projective, _>(
            "fr_iter".to_string(),
            fr_vec.iter(),
        );
        rep3_transcript.send_fr_iter_to_verifier_shared("fr_iter".to_string(), &fr_vec);
        let rep3_challenge = rep3_transcript
            .get_challenge::<_>("challenge8".to_string(), &(), &mut ())
            .unwrap();
        let plain_challenge =
            plain_transcript.get_challenge::<ark_bn254::G1Projective>("challenge8".to_string());
        assert_eq!(rep3_challenge, plain_challenge);
    }

    #[test]
    fn rep3_transcript_poseidon_rep3() {
        const VEC_SIZE: usize = 10;
        let mut thread_rng = rand::thread_rng();
        let nets0 = LocalNetwork::new_3_parties();
        let mut threads = Vec::with_capacity(3);

        let fr_vec = (0..VEC_SIZE)
            .map(|_| ark_bn254::Fr::rand(&mut thread_rng))
            .collect::<Vec<_>>();
        let point_vec = (0..VEC_SIZE)
            .map(|_| ark_bn254::G1Projective::rand(&mut thread_rng))
            .collect::<Vec<_>>();
        let u64_vec = (0..VEC_SIZE)
            .map(|_| rand::random::<u64>())
            .collect::<Vec<_>>();

        let fr_vec_shares = rep3::share_field_elements(&fr_vec, &mut thread_rng);
        let point_vec_shares =
            rep3::share_curve_points::<ark_bn254::G1Projective, _>(&point_vec, &mut thread_rng);

        let mut plain_transcript = Transcript::<
            TranscriptFieldType,
            Poseidon2Sponge,
            Rep3UltraHonkDriver,
            ark_bn254::G1Projective,
        >::new();
        let mut plain_challenges = Vec::new();
        for ((i, f), p, u) in izip!(fr_vec.iter().enumerate(), point_vec.iter(), u64_vec.iter()) {
            if i % 4 == 0 {
                plain_transcript
                    .send_fr_to_verifier::<ark_bn254::G1Projective>(format!("fr_vec_{}", i), *f);
                plain_transcript.send_point_to_verifier::<ark_bn254::G1Projective>(
                    format!("point_vec_{}", i),
                    (*p).into(),
                );
                plain_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
            } else if i % 4 == 1 {
                plain_transcript.send_point_to_verifier::<ark_bn254::G1Projective>(
                    format!("point_vec_{}", i),
                    (*p).into(),
                );
                plain_transcript
                    .send_fr_to_verifier::<ark_bn254::G1Projective>(format!("fr_vec_{}", i), *f);
                plain_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
            } else {
                plain_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                plain_transcript.send_point_to_verifier::<ark_bn254::G1Projective>(
                    format!("point_vec_{}", i),
                    (*p).into(),
                );
                plain_transcript
                    .send_fr_to_verifier::<ark_bn254::G1Projective>(format!("fr_vec_{}", i), *f);
            }

            plain_challenges.push(
                plain_transcript.get_challenge::<ark_bn254::G1Projective>(format!("challenge{i}")),
            );
        }
        plain_transcript.send_fr_iter_to_verifier::<ark_bn254::G1Projective, _>(
            "fr_iter".to_string(),
            fr_vec.iter(),
        );
        plain_challenges.push(
            plain_transcript
                .get_challenge::<ark_bn254::G1Projective>("final_challenge".to_string()),
        );
        for (net0, f_shares, p_shares) in izip!(nets0.into_iter(), fr_vec_shares, point_vec_shares)
        {
            let u64_vec = u64_vec.clone();
            let fr_vec = fr_vec.clone();
            let point_vec = point_vec.clone();
            threads.push(thread::spawn(move || {
                let mut rep3_transcript = TranscriptRep3::<
                    TranscriptFieldType,
                    Rep3UltraHonkDriver,
                    ark_bn254::G1Projective,
                    FieldSpongeRep3<
                        Rep3UltraHonkDriver,
                        ark_bn254::G1Projective,
                        4,
                        3,
                        Poseidon2<TranscriptFieldType, 4, 5>,
                    >,
                >::new();
                let mut challenges = Vec::new();
                let mut state = Rep3State::new(&net0, A2BType::default()).unwrap();

                for ((i, f), p, u, f_plain, p_plain) in izip!(
                    f_shares.iter().enumerate(),
                    p_shares.iter(),
                    u64_vec.iter(),
                    fr_vec.iter(),
                    point_vec.iter()
                ) {
                    if i % 4 == 0 {
                        rep3_transcript.send_fr_to_verifier_shared(format!("fr_vec_{}", i), *f);
                        rep3_transcript
                            .send_point_to_verifier_shared(format!("point_vec_{}", i), *p);
                        rep3_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                    } else if i % 4 == 1 {
                        rep3_transcript
                            .send_point_to_verifier(format!("point_vec_{}", i), (*p_plain).into());
                        rep3_transcript.send_fr_to_verifier(format!("fr_vec_{}", i), *f_plain);
                        rep3_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                    } else if i % 4 == 2 {
                        rep3_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                        rep3_transcript
                            .send_point_to_verifier_shared(format!("point_vec_{}", i), *p);
                        rep3_transcript.send_fr_to_verifier_shared(format!("fr_vec_{}", i), *f);
                    } else {
                        rep3_transcript.send_u64_to_verifier(format!("u64_vec_{}", i), *u);
                        rep3_transcript
                            .send_point_to_verifier_shared(format!("point_vec_{}", i), *p);
                        rep3_transcript.send_fr_to_verifier(format!("fr_vec_{}", i), *f_plain);
                    }
                    let rep3_challenge = rep3_transcript
                        .get_challenge::<LocalNetwork>(format!("challenge{i}"), &net0, &mut state)
                        .unwrap();
                    challenges.push(rep3_challenge);
                }
                rep3_transcript.send_fr_iter_to_verifier_shared("fr_iter".to_string(), &f_shares);
                let rep3_challenge = rep3_transcript
                    .get_challenge::<LocalNetwork>("final_challenge".to_string(), &net0, &mut state)
                    .unwrap();
                challenges.push(rep3_challenge);
                challenges
            }));
        }
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let result = results[0].clone();
        for r in results.iter().skip(1) {
            assert_eq!(r, &result);
        }
        assert_eq!(result, plain_challenges);
    }
}
