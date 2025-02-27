use crate::prelude::HonkCurve;
use crate::transcript::TranscriptCT;
use crate::transcript::TranscriptFieldType;
use crate::transcript::TranscriptHasherCT;
use crate::types::types::AggregationState;
use crate::types::types::FieldCT;
use ark_ec::pairing::Pairing;

struct UltraRecursiveVerifierOutput<P: Pairing> {
    agg_obj: AggregationState<P::G1>,
    ipa_proof: Vec<FieldCT<P::ScalarField>>,
}

pub fn verify_proof<P: HonkCurve<TranscriptFieldType>, H: TranscriptHasherCT<P>>(
    proof: Vec<FieldCT<P::ScalarField>>,
    agg_obj: AggregationState<P::G1>,
) {
    let mut transcript = TranscriptCT::<P, H>::new_verifier(proof);
}
