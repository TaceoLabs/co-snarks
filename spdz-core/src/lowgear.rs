//! Low-Gear Preprocessing Adapter
//!
//! Bridges the Low-Gear offline phase output (`LowGearPrep<C>`) to our
//! `SpdzPreprocessing<F>` trait by converting between `ark_mpc::ScalarShare<C>`
//! and `SpdzPrimeFieldShare<F>`.

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_mpc_offline::structs::LowGearPrep;

use crate::preprocessing::SpdzPreprocessing;
use crate::types::SpdzPrimeFieldShare;

/// Convert an ark-mpc ScalarShare to our SpdzPrimeFieldShare.
fn convert_share<C: CurveGroup>(
    share: ark_mpc::algebra::ScalarShare<C>,
) -> SpdzPrimeFieldShare<C::ScalarField> {
    SpdzPrimeFieldShare::new(share.share().inner(), share.mac().inner())
}

/// Convert a batch of ark-mpc ScalarShares.
fn convert_shares<C: CurveGroup>(
    shares: Vec<ark_mpc::algebra::ScalarShare<C>>,
) -> Vec<SpdzPrimeFieldShare<C::ScalarField>> {
    shares.into_iter().map(convert_share::<C>).collect()
}

/// Low-Gear preprocessing adapted for our SpdzPreprocessing trait.
///
/// Wraps `LowGearPrep<C>` and converts types on the fly.
pub struct LowGearPreprocessing<C: CurveGroup> {
    inner: LowGearPrep<C>,
}

impl<C: CurveGroup> LowGearPreprocessing<C> {
    /// Create from a LowGearPrep result.
    pub fn new(prep: LowGearPrep<C>) -> Self {
        Self { inner: prep }
    }

    /// Access the inner LowGearPrep.
    pub fn inner(&self) -> &LowGearPrep<C> {
        &self.inner
    }
}

impl<C: CurveGroup> SpdzPreprocessing<C::ScalarField> for LowGearPreprocessing<C> {
    fn mac_key_share(&self) -> C::ScalarField {
        self.inner.params.mac_key_share.inner()
    }

    fn next_triple(
        &mut self,
    ) -> eyre::Result<(
        SpdzPrimeFieldShare<C::ScalarField>,
        SpdzPrimeFieldShare<C::ScalarField>,
        SpdzPrimeFieldShare<C::ScalarField>,
    )> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        let (a, b, c) = self.inner.next_triplet();
        Ok((convert_share::<C>(a), convert_share::<C>(b), convert_share::<C>(c)))
    }

    fn next_triple_batch(
        &mut self,
        n: usize,
    ) -> eyre::Result<(
        Vec<SpdzPrimeFieldShare<C::ScalarField>>,
        Vec<SpdzPrimeFieldShare<C::ScalarField>>,
        Vec<SpdzPrimeFieldShare<C::ScalarField>>,
    )> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        let (a, b, c) = self.inner.next_triplet_batch(n);
        Ok((convert_shares::<C>(a), convert_shares::<C>(b), convert_shares::<C>(c)))
    }

    fn next_shared_random(&mut self) -> eyre::Result<SpdzPrimeFieldShare<C::ScalarField>> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        Ok(convert_share::<C>(self.inner.next_shared_value()))
    }

    fn next_shared_random_batch(
        &mut self,
        n: usize,
    ) -> eyre::Result<Vec<SpdzPrimeFieldShare<C::ScalarField>>> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        Ok(convert_shares::<C>(self.inner.next_shared_value_batch(n)))
    }

    fn next_shared_bit(&mut self) -> eyre::Result<SpdzPrimeFieldShare<C::ScalarField>> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        Ok(convert_share::<C>(self.inner.next_shared_bit()))
    }

    fn next_shared_bit_batch(
        &mut self,
        n: usize,
    ) -> eyre::Result<Vec<SpdzPrimeFieldShare<C::ScalarField>>> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        Ok(convert_shares::<C>(self.inner.next_shared_bit_batch(n)))
    }

    fn next_input_mask(
        &mut self,
    ) -> eyre::Result<(C::ScalarField, SpdzPrimeFieldShare<C::ScalarField>)> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        let (val, share) = self.inner.next_local_input_mask();
        Ok((val.inner(), convert_share::<C>(share)))
    }

    fn next_counterparty_input_mask(
        &mut self,
    ) -> eyre::Result<SpdzPrimeFieldShare<C::ScalarField>> {
        use ark_mpc::offline_prep::PreprocessingPhase;
        Ok(convert_share::<C>(self.inner.next_counterparty_input_mask()))
    }
}
