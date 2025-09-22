use std::fmt::format;

use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_builder::{flavours::mega_flavour::MegaFlavour, mega_builder::MegaCircuitBuilder, polynomials::polynomial_flavours::WitnessEntitiesFlavour, prover_flavour::ProverFlavour, transcript::{TranscriptCT, TranscriptFieldType, TranscriptHasherCT}, types::{field_ct::FieldCT, goblin_types::GoblinElement}};
use co_ultrahonk::key;
use common::{honk_curve::HonkCurve, honk_proof::HonkProofResult, mpc::NoirUltraHonkProver, transcript::{Transcript, TranscriptHasher}};
use itertools::{izip, Itertools};
use mpc_net::Network;
use ark_ff::Field;
use ark_ff::AdditiveGroup;
use rayon::vec;

use crate::{prover::co_protogalaxy_prover::{BATCHED_EXTENDED_LENGTH, CONST_PG_LOG_N, NUM_KEYS}, recursive_verifier::{oink_recursive_verifier::OinkRecursiveVerifier, recursive_decider_verification_key::RecursiveDeciderVerificationKey}};

pub(crate) const COMBINER_LENGTH: usize = BATCHED_EXTENDED_LENGTH - NUM_KEYS;
pub(crate) const NUM_FOLDED_ENTITIES: usize = MegaFlavour::WITNESS_ENTITIES_SIZE + MegaFlavour::PRECOMPUTED_ENTITIES_SIZE;

// TODO CESAR: Remove this cumbersome Generic bounds once the eccvm is generic over the witness extension protocol
pub struct ProtogalaxyRecursiveVerifier<'a,T, D, C, H, N>
where

        N: Network,
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<
                C,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<C>,
            >,
        H: TranscriptHasherCT<C>,

{
    pub phantom: std::marker::PhantomData<&'a (T, D, C, H, N)>,
}

// TODO CESAR: Remove these cumbersome Generic bounds once the eccvm is generic over the witness extension protocol
impl<'a, T, D, C, H, N> ProtogalaxyRecursiveVerifier<'a, T, D, C, H, N>
where

        N: Network,
        C: HonkCurve<TranscriptFieldType, ScalarField = TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<TranscriptFieldType>,
        D: NoirUltraHonkProver<
                C,
                ArithmeticShare = T::ArithmeticShare,
                PointShare = T::NativePointShare<C  >,
            >,
        H: TranscriptHasherCT<C>
{

    fn run_oink_verifier_on_one_incomplete_key(&self, verification_key: &mut RecursiveDeciderVerificationKey<C, T>, transcript: &mut TranscriptCT<C, H>, builder: &mut MegaCircuitBuilder<C, T, D>, driver: &mut T) -> HonkProofResult<()> {
        OinkRecursiveVerifier::<T, D, C, H, N>::verify(verification_key, transcript, builder, driver)
    }

    fn run_oink_verifier_on_each_incomplete_key(&self, keys_to_fold: &mut [RecursiveDeciderVerificationKey<C, T>; NUM_KEYS], transcript: &mut TranscriptCT<C, H>, builder: &mut MegaCircuitBuilder<C, T, D>, driver: &mut T) -> HonkProofResult<()> {
        let key = &mut keys_to_fold[0];
        if !key.is_accumulator {
            self.run_oink_verifier_on_one_incomplete_key(key, transcript, builder, driver)?;
            key.target_sum = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
            key.gate_challenges = vec![FieldCT::from_witness(C::ScalarField::ZERO.into(), builder); CONST_PG_LOG_N];
        } 

        for key in keys_to_fold.iter_mut().skip(1) {
            self.run_oink_verifier_on_one_incomplete_key(key, transcript, builder, driver)?;
        }
        Ok(())
    }

    fn verify_folding_proofs(&self, keys_to_fold: &mut [RecursiveDeciderVerificationKey<C, T>; NUM_KEYS], proof: Vec<FieldCT<C::ScalarField>>, builder: &mut MegaCircuitBuilder<C, T, D>, driver: &mut T,
    net: &N, state: &mut D::State
    ) -> HonkProofResult<()> {

        let one = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);

        let mut transcript = TranscriptCT::new_verifier(proof);
        self.run_oink_verifier_on_each_incomplete_key(keys_to_fold, &mut transcript, builder, driver)?;

        let accumulator = &keys_to_fold[0];

        let delta = transcript.get_challenge("delta".to_owned(), builder, driver)?;
        
        // TODO CESAR: Handle unwraps properly
        let deltas = std::iter::successors(Some(delta), |x| Some(x.multiply(&x, builder, driver).unwrap()))
            .take(CONST_PG_LOG_N)
            .collect::<Vec<_>>();

        let perturbator_coeffs = (1..CONST_PG_LOG_N + 1)
        //TODO CESAR: Handle unwraps properly
            .map(|idx| transcript.get_challenge(format!("perturbator_{idx}"), builder, driver).unwrap())
            .collect::<Vec<_>>();

        let perturbator_coeffs = [
            vec![accumulator.target_sum.clone()],
            perturbator_coeffs
        ].concat();

        let perturbator_challenge = transcript.get_challenge("perturbator_challenge".to_owned(), builder, driver)?;

        let perturbator_evaluation = self.evaluate_perturbator(&perturbator_challenge, &perturbator_coeffs, builder, driver)?;

        // TODO CESAR: Handle unwraps properly
        let combiner_quotient_evals = (0..COMBINER_LENGTH)
            .map(|idx| transcript.receive_fr_from_prover(format!("combiner_quotient_{idx}")).unwrap())
            .collect::<Vec<_>>();

        let combiner_challenge = transcript.get_challenge("combiner_quotient_challenge".to_owned(), builder, driver)?;

        // TODO CESAR: evaluate combiner polynomial at combiner_challenge
        let combiner_quotient_at_challenge = todo!();

        let vanishing_polynomial_at_challenge = combiner_challenge.sub(&one, builder, driver).multiply(&combiner_challenge, builder, driver)?;
    
        let lagranges = [
            one.sub(&combiner_challenge, builder, driver),
            combiner_challenge
        ];

        /*
        Fold the commitments
        Note: we use additional challenges to reduce the amount of elliptic curve work performed by the ECCVM

        For an accumulator commitment [P'] and an instance commitment [P] , we compute folded commitment [P''] where
        [P''] = L0(gamma).[P'] + L1(gamma).[P]
        For the size-2 case this becomes:
        P'' = (1 - gamma).[P'] + gamma.[P] = gamma.[P - P'] + [P']

        This requires a large number of size-1 scalar muls (about 53)
        The ECCVM can perform a size-k MSM in 32 + roundup((k/4)) rows, if each scalar multiplier is <128 bits
        i.e. number of ECCVM rows = 53 * 64 = painful

        To optimize, we generate challenges `c_i` for each commitment and evaluate the relation:

        [A] = \sum c_i.[P_i]
        [B] = \sum c_i.[P'_i]
        [C] = \sum c_i.[P''_i]
        and validate
        (1 - gamma).[A] + gamma.[B] == [C]


        This reduces the relation to 3 large MSMs where each commitment requires 3 size-128bit scalar multiplications
        For a flavor with 53 instance/witness commitments, this is 53 * 24 rows

        Note: there are more efficient ways to evaluate this relationship if one solely wants to reduce number of scalar
        muls, however we must also consider the number of ECCVM operations being executed, as each operation incurs a
        cost in the translator circuit Each ECCVM opcode produces 5 rows in the translator circuit, which is approx.
        equivalent to 9 ECCVM rows. Something to pay attention to
        */

        let accumulator_commitments = Vec::new();
        let instance_commitments = Vec::new();

        // TODO CESAR: Logic for instance commitments

        let [key_1, key_2, ..] = keys_to_fold;
        for (a, b) in izip!(key_1.witness_commitments.iter(), key_2.witness_commitments.iter()) {
            accumulator_commitments.push(a.clone());
            instance_commitments.push(b.clone());
        }

        let mut output_commitments = Vec::new();
        let lhs_scalar = one.sub(&combiner_challenge, builder, driver).get_value(builder, driver);
        let rhs_scalar = combiner_challenge.get_value(builder, driver);

        for (i, (accumulator_commitment, instance_commitment) )in izip!(accumulator_commitments.iter(), instance_commitments.iter()).enumerate() {
            let lhs = accumulator_commitment.get_value(builder, driver);
            let rhs = instance_commitment.get_value(builder, driver);

            let points = driver.scale_native_point_many(
                &[lhs, rhs],
                &[lhs_scalar, rhs_scalar]
            )?;

            let output = driver.add_native_points(lhs, rhs)?;
            let output_commitment = GoblinElement::from_witness(output, builder, driver)?;
            
            output_commitments.push(output_commitment.clone());

            // Add the output commitment to the transcript to ensure that they can't be spoofed
            transcript.add_point_to_hash_buffer(
                format!("new_accumulator_commitment_{}", i),
                &output_commitment,
            );
        }

        let labels = (0..NUM_FOLDED_ENTITIES).map(|i| format!("accumulator_combination_challenges_{i}")).collect_vec();
        let scalars = transcript.get_challenges(&labels, builder, driver)?;


        let accumulator_sum = GoblinElement::batch_mul(
            &accumulator_commitments,
            &scalars,
            builder,
            driver,
            net, 
            state,
        )?;

        let instance_sum = GoblinElement::batch_mul(
            &instance_commitments,
            &scalars,
            builder,
            driver,
            net, 
            state,
        )?;

        let output_sum = GoblinElement::batch_mul(
            &output_commitments,
            &scalars,
            builder,
            driver,
            net, 
            state,
        )?;

        let folded_sum = GoblinElement::batch_mul(
            &[accumulator_sum, instance_sum],
            &lagranges,
            builder,
            driver,
            net, 
            state,
        )?;

        output_sum.x.limbs[0].assert_equal(&folded_sum.x.limbs[0], builder, driver);
        output_sum.x.limbs[1].assert_equal(&folded_sum.x.limbs[1], builder, driver);
        output_sum.y.limbs[0].assert_equal(&folded_sum.y.limbs[0], builder, driver);
        output_sum.y.limbs[1].assert_equal(&folded_sum.y.limbs[1], builder, driver);

        // Compute next folding parameters
        accumulator.is_accumulator = true;
        accumulator.target_sum = lagranges[0].multiply(&perturbator_evaluation, builder, driver)?.add(
            &vanishing_polynomial_at_challenge.multiply(&combiner_quotient_at_challenge, builder, driver)?,
            builder, driver);

        accumulator.gate_challenges.iter_mut().zip(deltas).for_each(|(c, delta)| {
            let tmp = perturbator_challenge.multiply(&delta, builder, driver).expect("Failed to multiply perturbator challenge and delta");
            *c = c.add(&tmp, builder, driver);
        });

        Ok(())
    }

    fn evaluate_perturbator(
        &self,
        point: &FieldCT<C::ScalarField>,
        coeffs: &[FieldCT<C::ScalarField>],
        builder: &mut MegaCircuitBuilder<C, T, D>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let mut point_acc = FieldCT::from_witness(C::ScalarField::ONE.into(), builder);
        let mut result = FieldCT::from_witness(C::ScalarField::ZERO.into(), builder);
        for i in 0..=CONST_PG_LOG_N {
            result = coeffs[i].madd(&point_acc, &result, builder, driver)?;
            point_acc = point_acc.multiply(point, builder, driver)?;
        }

        Ok(result)
    }
}