// clang-format off
/*                                            )\   /|
*                                          .-/'-|_/ |
*                       __            __,-' (   / \/
*                   .-'"  "'-..__,-'""          -o.`-._
*                  /                                   '/
*          *--._ ./                                 _.--
*                |                              _.-'
*                :                           .-/
*                 \                       )_ /
*                  \                _)   / \(
*                    `.   /-.___.---'(  /   \\
*                     (  /   \\       \(     L\
*                      \(     L\       \\
*                       \\              \\
*                        L\              L\
*/
// clang-format on

use super::types::ProverMemory;
use crate::{
    co_decider::relations::databus_lookup_relation::BusData, key::proving_key::ProvingKey,
    mpc_prover_flavour::MPCProverFlavour,
};
use ark_ff::{One, Zero};
use co_builder::TranscriptFieldType;
use co_builder::polynomials::polynomial_flavours::PrecomputedEntitiesFlavour;
use co_builder::polynomials::polynomial_flavours::ProverWitnessEntitiesFlavour;

use co_builder::{
    HonkProofError, HonkProofResult,
    prelude::{ActiveRegionData, HonkCurve, NUM_MASKED_ROWS, Polynomial, ProverCrs},
    prover_flavour::Flavour,
};
use common::CoUtils;
use common::mpc::NoirUltraHonkProver;
use common::transcript::{Transcript, TranscriptHasher};
use itertools::izip;
use mpc_core::MpcState as _;
use mpc_net::Network;
use std::marker::PhantomData;
use ultrahonk::prelude::ZeroKnowledge;
pub(crate) struct CoOink<
    'a,
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
    L: MPCProverFlavour,
> {
    net: &'a N,
    state: &'a mut T::State,
    memory: ProverMemory<T, P, L>,
    phantom_data: PhantomData<(P, H, L)>,
    has_zk: ZeroKnowledge,
}

impl<
    'a,
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
    L: MPCProverFlavour,
> CoOink<'a, T, P, H, N, L>
{
    pub(crate) fn new(net: &'a N, state: &'a mut T::State, has_zk: ZeroKnowledge) -> Self {
        Self {
            net,
            state,
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
            has_zk,
        }
    }

    fn mask_polynomial(
        &mut self,
        polynomial: &mut Polynomial<T::ArithmeticShare>,
    ) -> HonkProofResult<()> {
        tracing::trace!("mask polynomial");

        let virtual_size = polynomial.coefficients.len();
        assert!(
            virtual_size >= NUM_MASKED_ROWS as usize,
            "Insufficient space for masking"
        );
        for i in (virtual_size - NUM_MASKED_ROWS as usize..virtual_size).rev() {
            polynomial.coefficients[i] = T::rand(self.net, self.state)?;
        }

        Ok(())
    }

    fn compute_w4_inner(&mut self, proving_key: &ProvingKey<T, P, L>, gate_idx: usize) {
        let target = &mut self.memory.w_4[gate_idx];

        let mul1 = T::mul_with_public(
            self.memory.challenges.eta_1,
            proving_key.polynomials.witness.w_l()[gate_idx],
        );
        let mul2 = T::mul_with_public(
            self.memory.challenges.eta_2,
            proving_key.polynomials.witness.w_r()[gate_idx],
        );
        let mul3 = T::mul_with_public(
            self.memory.challenges.eta_3,
            proving_key.polynomials.witness.w_o()[gate_idx],
        );
        // TACEO TODO add_assign?
        *target = T::add(*target, mul1);
        *target = T::add(*target, mul2);
        *target = T::add(*target, mul3);
    }

    fn compute_w4(&mut self, proving_key: &ProvingKey<T, P, L>) {
        tracing::trace!("compute w4");
        // The memory record values are computed at the indicated indices as
        // w4 = w3 * eta^3 + w2 * eta^2 + w1 * eta + read_write_flag;

        debug_assert_eq!(
            proving_key.polynomials.witness.w_l().len(),
            proving_key.polynomials.witness.w_r().len()
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.w_l().len(),
            proving_key.polynomials.witness.w_o().len()
        );
        self.memory.w_4 = proving_key.polynomials.witness.w_4().clone();
        self.memory.w_4.resize(
            proving_key.polynomials.witness.w_l().len(),
            T::ArithmeticShare::default(),
        );

        // Compute read record values
        for gate_idx in proving_key.memory_read_records.iter() {
            let gate_idx = *gate_idx as usize;
            self.compute_w4_inner(proving_key, gate_idx);
        }

        // Compute write record values
        for gate_idx in proving_key.memory_write_records.iter() {
            let gate_idx = *gate_idx as usize;
            self.compute_w4_inner(proving_key, gate_idx);
            let target = &mut self.memory.w_4[gate_idx];
            *target = T::add_with_public(P::ScalarField::one(), *target, self.state.id());
        }

        // This computes the values for cases where the type (r/w) of the record is a secret share of 0/1 and adds this share
        for (gate_idx, type_share) in proving_key.memory_records_shared.iter() {
            let gate_idx = *gate_idx as usize;
            self.compute_w4_inner(proving_key, gate_idx);
            let target = &mut self.memory.w_4[gate_idx];
            *target = T::add(*type_share, *target);
        }
    }

    fn compute_read_term(
        &mut self,
        proving_key: &ProvingKey<T, P, L>,
        i: usize,
    ) -> T::ArithmeticShare {
        tracing::trace!("compute read term");

        let gamma = self.memory.challenges.gamma;
        let eta_1 = self.memory.challenges.eta_1;
        let eta_2 = self.memory.challenges.eta_2;
        let eta_3 = self.memory.challenges.eta_3;
        let w_1 = proving_key.polynomials.witness.w_l()[i];
        let w_2 = proving_key.polynomials.witness.w_r()[i];
        let w_3 = proving_key.polynomials.witness.w_o()[i];
        let w_1_shift = proving_key.polynomials.witness.w_l().shifted()[i];
        let w_2_shift = proving_key.polynomials.witness.w_r().shifted()[i];
        let w_3_shift = proving_key.polynomials.witness.w_o().shifted()[i];
        let table_index = proving_key.polynomials.precomputed.q_o()[i];
        let negative_column_1_step_size = proving_key.polynomials.precomputed.q_r()[i];
        let negative_column_2_step_size = proving_key.polynomials.precomputed.q_m()[i];
        let negative_column_3_step_size = proving_key.polynomials.precomputed.q_c()[i];

        // The wire values for lookup gates are accumulators structured in such a way that the differences w_i -
        // step_size*w_i_shift result in values present in column i of a corresponding table. See the documentation in
        // method get_lookup_accumulators() in  for a detailed explanation.
        let id = self.state.id();

        let mul = T::mul_with_public(negative_column_1_step_size, w_1_shift);
        let add = T::add_with_public(gamma, mul, id);
        let derived_table_entry_1 = T::add(w_1, add);

        let mul = T::mul_with_public(negative_column_2_step_size, w_2_shift);
        let derived_table_entry_2 = T::add(w_2, mul);

        let mul = T::mul_with_public(negative_column_3_step_size, w_3_shift);
        let derived_table_entry_3 = T::add(w_3, mul);

        // (w_1 + \gamma q_2*w_1_shift) + η(w_2 + q_m*w_2_shift) + η₂(w_3 + q_c*w_3_shift) + η₃q_index.
        // deg 2 or 3
        // TACEO TODO add_assign?
        let mul = T::mul_with_public(eta_1, derived_table_entry_2);
        let res = T::add(derived_table_entry_1, mul);
        let mul = T::mul_with_public(eta_2, derived_table_entry_3);
        let res = T::add(res, mul);
        T::add_with_public(table_index * eta_3, res, id)
    }

    // Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term(&self, proving_key: &ProvingKey<T, P, L>, i: usize) -> P::ScalarField {
        tracing::trace!("compute write term");

        let gamma = &self.memory.challenges.gamma;
        let eta_1 = &self.memory.challenges.eta_1;
        let eta_2 = &self.memory.challenges.eta_2;
        let eta_3 = &self.memory.challenges.eta_3;
        let table_1 = &proving_key.polynomials.precomputed.table_1()[i];
        let table_2 = &proving_key.polynomials.precomputed.table_2()[i];
        let table_3 = &proving_key.polynomials.precomputed.table_3()[i];
        let table_4 = &proving_key.polynomials.precomputed.table_4()[i];

        *table_1 + gamma + *table_2 * eta_1 + *table_3 * eta_2 + *table_4 * eta_3
    }

    fn compute_read_term_databus(
        &self,
        proving_key: &ProvingKey<T, P, L>,
        i: usize,
    ) -> T::ArithmeticShare {
        tracing::trace!("compute read term databus");
        let party_id = self.state.id();

        // Bus value stored in w_1, index into bus column stored in w_2
        let w_1 = &proving_key.polynomials.witness.w_l()[i];
        let w_2 = &proving_key.polynomials.witness.w_r()[i];
        let gamma = &self.memory.challenges.gamma;
        let beta = &self.memory.challenges.beta;

        // Construct value + index*\beta + \gamma
        let mul = T::mul_with_public(*beta, *w_2);
        let add = T::add_with_public(*gamma, *w_1, party_id);
        T::add(mul, add)
    }

    /// Compute table_1 + gamma + table_2 * eta + table_3 * eta_2 + table_4 * eta_3
    fn compute_write_term_databus(
        &self,
        proving_key: &ProvingKey<T, P, L>,
        i: usize,
        bus_idx: BusData,
    ) -> T::ArithmeticShare {
        tracing::trace!("compute write term databus");
        let party_id = self.state.id();

        let value = match bus_idx {
            BusData::BusIdx0 => &proving_key.polynomials.witness.calldata()[i],
            BusData::BusIdx1 => &proving_key.polynomials.witness.secondary_calldata()[i],
            BusData::BusIdx2 => &proving_key.polynomials.witness.return_data()[i],
        };
        let id = &proving_key.polynomials.precomputed.databus_id()[i];
        let gamma = &self.memory.challenges.gamma;
        let beta = &self.memory.challenges.beta;
        // Construct value_i + idx_i*\beta + \gamma
        // degree 1
        T::add_with_public(*id * beta + gamma, *value, party_id)
    }

    fn compute_logderivative_inverses(
        &mut self,
        proving_key: &ProvingKey<T, P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("compute logderivative inverse");

        let id = self.state.id();

        debug_assert_eq!(
            proving_key.polynomials.precomputed.q_lookup().len(),
            proving_key.circuit_size as usize
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.lookup_read_tags().len(),
            proving_key.circuit_size as usize
        );
        self.memory
            .lookup_inverses
            .resize(proving_key.circuit_size as usize, Default::default());

        // const READ_TERMS: usize = 1;
        // const WRITE_TERMS: usize = 1;
        // // 1 + polynomial degree of this relation
        // const LENGTH: usize = 5; // both subrelations are degree 4

        let mut q_lookup_mul_read_tag = Vec::with_capacity(proving_key.circuit_size as usize);
        for (i, (q_lookup, lookup_read_tag)) in izip!(
            proving_key.polynomials.precomputed.q_lookup().iter(),
            proving_key.polynomials.witness.lookup_read_tags().iter(),
        )
        .enumerate()
        {
            // The following check cannot easily be done since lookup_read_tag is shared. We prepare q_lookup_mul_read_tag instead and multiply it later to self.memory.lookup_inverses.
            // if !(q_lookup.is_one() || lookup_read_tag.is_one()) {
            //     continue;
            // }
            debug_assert!(q_lookup.is_one() || q_lookup.is_zero());
            let mul =
                T::mul_with_public(P::ScalarField::one() - q_lookup, lookup_read_tag.to_owned());
            q_lookup_mul_read_tag.push(T::add_with_public(
                q_lookup.to_owned(),
                mul,
                self.state.id(),
            ));

            // READ_TERMS and WRITE_TERMS are 1, so we skip the loop
            let read_term = self.compute_read_term(proving_key, i);
            let write_term = self.compute_write_term(proving_key, i);
            self.memory.lookup_inverses[i] = T::mul_with_public(write_term, read_term);
        }

        if L::FLAVOUR == Flavour::Ultra {
            // Compute inverse polynomial I in place by inverting the product at each row
            // NOTE regarding leaking: As these entries consist of nonzero values with high probability (compare compute_read and compute_write functions, there we have a challenge as an additive term), we do not have zeros and can not leak zeroes here.
            CoUtils::batch_invert_leaking_zeros::<T, P, N>(
                self.memory.lookup_inverses.as_mut(),
                self.net,
                self.state,
            )?;
            // Finally invert
            self.memory.lookup_inverses = Polynomial::new(T::mul_many(
                self.memory.lookup_inverses.as_ref(),
                &q_lookup_mul_read_tag,
                self.net,
                self.state,
            )?);
        } else if L::FLAVOUR == Flavour::Mega {
            // We batch all inverese rounds
            debug_assert_eq!(
                proving_key.polynomials.precomputed.q_busread().len(),
                proving_key.circuit_size as usize
            );
            debug_assert_eq!(
                proving_key.polynomials.precomputed.q_l().len(),
                proving_key.circuit_size as usize
            );
            debug_assert_eq!(
                proving_key.polynomials.precomputed.q_r().len(),
                proving_key.circuit_size as usize
            );
            debug_assert_eq!(
                proving_key.polynomials.precomputed.q_o().len(),
                proving_key.circuit_size as usize
            );
            debug_assert_eq!(
                proving_key.polynomials.witness.calldata_read_counts().len(),
                proving_key.circuit_size as usize
            );
            debug_assert_eq!(
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_counts()
                    .len(),
                proving_key.circuit_size as usize
            );
            debug_assert_eq!(
                proving_key
                    .polynomials
                    .witness
                    .return_data_read_counts()
                    .len(),
                proving_key.circuit_size as usize
            );

            let mut bus_idx_0_indices =
                Vec::with_capacity(proving_key.polynomials.witness.calldata_read_counts().len());
            let mut bus_idx_1_indices = Vec::with_capacity(
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_counts()
                    .len(),
            );
            let mut bus_idx_2_indices = Vec::with_capacity(
                proving_key
                    .polynomials
                    .witness
                    .return_data_read_counts()
                    .len(),
            );
            let mut to_compare_0 =
                Vec::with_capacity(proving_key.polynomials.precomputed.q_busread().len());
            let mut to_compare_1 =
                Vec::with_capacity(proving_key.polynomials.precomputed.q_busread().len());
            let mut to_compare_2 =
                Vec::with_capacity(proving_key.polynomials.precomputed.q_busread().len());

            for (i, (wire_0, wire_1, wire_2)) in izip!(
                proving_key.polynomials.precomputed.q_l().iter(),
                proving_key.polynomials.precomputed.q_r().iter(),
                proving_key.polynomials.precomputed.q_o().iter(),
            )
            .enumerate()
            {
                // Determine if the present row contains a databus operation
                let q_busread = &proving_key.polynomials.precomputed.q_busread()[i];

                //TODO: is it worth to do this?
                if !(q_busread.is_one() && wire_0.is_one()) {
                    to_compare_0.push(proving_key.polynomials.witness.calldata_read_counts()[i]);
                    bus_idx_0_indices.push(i);
                }
                if !(q_busread.is_one() && wire_1.is_one()) {
                    to_compare_1.push(
                        proving_key
                            .polynomials
                            .witness
                            .secondary_calldata_read_counts()[i],
                    );
                    bus_idx_1_indices.push(i);
                }
                if !(q_busread.is_one() && wire_2.is_one()) {
                    to_compare_2.push(proving_key.polynomials.witness.return_data_read_counts()[i]);
                    bus_idx_2_indices.push(i);
                }
            }

            let size_0 = to_compare_0.len();
            let size_1 = to_compare_1.len();
            let size_2 = to_compare_2.len();
            let mut batch = Vec::with_capacity(size_0 + size_1 + size_2);
            batch.extend(to_compare_0);
            batch.extend(to_compare_1);
            batch.extend(to_compare_2);
            // we do the second part of the if condition only for those values where the is_read is not already set
            let public_one_promoted = T::promote_to_trivial_share(id, P::ScalarField::one());
            let is_zero = T::is_zero_many::<N>(&batch, self.net, self.state)?;
            let mut idx_0_compared =
                vec![
                    public_one_promoted;
                    proving_key.polynomials.witness.calldata_read_counts().len()
                ];
            let mut idx_1_compared = vec![
                public_one_promoted;
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_counts()
                    .len()
            ];
            let mut idx_2_compared = vec![
                public_one_promoted;
                proving_key
                    .polynomials
                    .witness
                    .return_data_read_counts()
                    .len()
            ];
            for (cmp, idx) in izip!(is_zero[..size_0].iter(), bus_idx_0_indices.iter()) {
                idx_0_compared[*idx] = T::sub(public_one_promoted, *cmp);
            }
            for (cmp, idx) in izip!(
                is_zero[size_0..size_0 + size_1].iter(),
                bus_idx_1_indices.iter()
            ) {
                idx_1_compared[*idx] = T::sub(public_one_promoted, *cmp);
            }
            for (cmp, idx) in izip!(is_zero[size_0 + size_1..].iter(), bus_idx_2_indices.iter()) {
                idx_2_compared[*idx] = T::sub(public_one_promoted, *cmp);
            }

            let (read, write_0, write_1, write_2) =
                self.compute_logderivative_inverses_databus_all(proving_key);
            let first_mul_size = q_lookup_mul_read_tag.len();
            let second_mul_size = read.len();

            let mut lhs = Vec::with_capacity(first_mul_size + 3 * second_mul_size);
            let mut rhs = Vec::with_capacity(lhs.len());

            lhs.extend_from_slice(&read);
            lhs.extend_from_slice(&read);
            lhs.extend_from_slice(&read);

            rhs.extend(write_0);
            rhs.extend(write_1);
            rhs.extend(write_2);

            let mut mul = T::mul_many(&lhs, &rhs, self.net, self.state)?;
            mul.extend_from_slice(self.memory.lookup_inverses.as_ref());

            // Compute inverse polynomial I in place by inverting the product at each row
            // NOTE regarding leaking: As these entries consist of nonzero values with high probability (compare compute_read and compute_write functions, there we have a challenge as an additive term), we do not have zeros and can not leak zeroes here.
            CoUtils::batch_invert_leaking_zeros::<T, P, N>(&mut mul, self.net, self.state)?;

            // Multiply the mul vec with q_lookup_mul_read_tag and the arithmetized is_zero||(q_busread==1 && wire==1) results

            let mut mul_with = Vec::with_capacity(mul.len());
            mul_with.extend(idx_0_compared);
            mul_with.extend(idx_1_compared);
            mul_with.extend(idx_2_compared);
            mul_with.extend(q_lookup_mul_read_tag);

            let mul = T::mul_many(&mul, &mul_with, self.net, self.state)?;
            let mut mul = mul.chunks_exact(mul.len() / 4);

            debug_assert_eq!(
                proving_key.polynomials.witness.calldata_read_counts().len(),
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_counts()
                    .len()
            );
            debug_assert_eq!(
                proving_key.polynomials.witness.calldata_read_counts().len(),
                proving_key
                    .polynomials
                    .witness
                    .return_data_read_counts()
                    .len()
            );

            self.memory.calldata_inverses =
                Polynomial::new(mul.next().expect("Must work").to_vec());
            self.memory.secondary_calldata_inverses =
                Polynomial::new(mul.next().expect("Must work").to_vec());
            self.memory.return_data_inverses =
                Polynomial::new(mul.next().expect("Must work").to_vec());
            self.memory.lookup_inverses = Polynomial::new(mul.next().expect("Must work").to_vec());
            debug_assert!(
                mul.next().is_none(),
                "There should be no more elements in the iterator"
            );
        }
        Ok(())
    }

    #[expect(clippy::type_complexity)]
    fn compute_logderivative_inverses_databus_all(
        &mut self,
        proving_key: &ProvingKey<T, P, L>,
    ) -> (
        Vec<T::ArithmeticShare>,
        Vec<T::ArithmeticShare>,
        Vec<T::ArithmeticShare>,
        Vec<T::ArithmeticShare>,
    ) {
        tracing::trace!("compute logderivative inverse for Databus");

        self.memory
            .calldata_inverses
            .resize(proving_key.circuit_size as usize, Default::default());
        self.memory
            .secondary_calldata_inverses
            .resize(proving_key.circuit_size as usize, Default::default());
        self.memory
            .return_data_inverses
            .resize(proving_key.circuit_size as usize, Default::default());

        let mut read = Vec::with_capacity(proving_key.polynomials.precomputed.q_busread().len());
        let mut write_1 = Vec::with_capacity(proving_key.polynomials.precomputed.q_busread().len());
        let mut write_2 = Vec::with_capacity(proving_key.polynomials.precomputed.q_busread().len());
        let mut write_3 = Vec::with_capacity(proving_key.polynomials.precomputed.q_busread().len());

        // we compute all the read and write terms for each bus_idx and later multiply them with the right vector of 0s/1s based on the original condition (see plain Oink implementation)
        for i in 0..proving_key.polynomials.precomputed.q_busread().len() {
            read.push(self.compute_read_term_databus(proving_key, i));
            write_1.push(self.compute_write_term_databus(proving_key, i, BusData::BusIdx0));
            write_2.push(self.compute_write_term_databus(proving_key, i, BusData::BusIdx1));
            write_3.push(self.compute_write_term_databus(proving_key, i, BusData::BusIdx2));
        }
        (read, write_1, write_2, write_3)
    }

    fn compute_public_input_delta(&self, proving_key: &ProvingKey<T, P, L>) -> P::ScalarField {
        tracing::trace!("compute public input delta");

        // Let m be the number of public inputs x₀,…, xₘ₋₁.
        // Recall that we broke the permutation σ⁰ by changing the mapping
        //  (i) -> (n+i)   to   (i) -> (-(i+1))   i.e. σ⁰ᵢ = −(i+1)
        //
        // Therefore, the term in the numerator with ID¹ᵢ = n+i does not cancel out with any term in the denominator.
        // Similarly, the denominator contains an extra σ⁰ᵢ = −(i+1) term that does not appear in the numerator.
        // We expect the values of W⁰ᵢ and W¹ᵢ to be equal to xᵢ.
        // The expected accumulated product would therefore be equal to

        //   ∏ᵢ (γ + W¹ᵢ + β⋅ID¹ᵢ)        ∏ᵢ (γ + xᵢ + β⋅(n+i) )
        //  -----------------------  =  ------------------------
        //   ∏ᵢ (γ + W⁰ᵢ + β⋅σ⁰ᵢ )        ∏ᵢ (γ + xᵢ - β⋅(i+1) )

        // At the start of the loop for each xᵢ where i = 0, 1, …, m-1,
        // we have
        //      numerator_acc   = γ + β⋅(n+i) = γ + β⋅n + β⋅i
        //      denominator_acc = γ - β⋅(1+i) = γ - β   - β⋅i
        // at the end of the loop, add and subtract β to each term respectively to
        // set the expected value for the start of iteration i+1.
        // Note: The public inputs may be offset from the 0th index of the wires, for example due to the inclusion of an
        // initial zero row or Goblin-stlye ECC op gates. Accordingly, the indices i in the above formulas are given by i =
        // [0, m-1] + offset, i.e. i = offset, 1 + offset, …, m - 1 + offset.

        let mut num = P::ScalarField::one();
        let mut denom = P::ScalarField::one();
        let mut num_acc = self.memory.challenges.gamma
            + self.memory.challenges.beta
                * P::ScalarField::from(
                    (proving_key.circuit_size + proving_key.pub_inputs_offset) as u64,
                );
        let mut denom_acc = self.memory.challenges.gamma
            - self.memory.challenges.beta
                * P::ScalarField::from((1 + proving_key.pub_inputs_offset) as u64);

        for x_i in proving_key.public_inputs.iter() {
            num *= num_acc + x_i;
            denom *= denom_acc + x_i;
            num_acc += self.memory.challenges.beta;
            denom_acc -= self.memory.challenges.beta;
        }
        num / denom
    }

    #[expect(clippy::too_many_arguments)]
    fn batched_grand_product_num_denom(
        net: &N,
        state: &mut T::State,
        shared1: &Polynomial<T::ArithmeticShare>,
        shared2: &Polynomial<T::ArithmeticShare>,
        pub1: &Polynomial<P::ScalarField>,
        pub2: &Polynomial<P::ScalarField>,
        beta: &P::ScalarField,
        gamma: &P::ScalarField,
        output_len: usize,
        active_region_data: &ActiveRegionData,
    ) -> HonkProofResult<Vec<T::ArithmeticShare>> {
        debug_assert!(shared1.len() >= output_len);
        debug_assert!(shared2.len() >= output_len);
        debug_assert!(pub1.len() >= output_len);
        debug_assert!(pub2.len() >= output_len);
        let has_active_ranges = active_region_data.size() > 0;

        // We drop the last element since it is not needed for the grand product
        let mut mul1 = Vec::with_capacity(output_len);
        let mut mul2 = Vec::with_capacity(output_len);

        for i in 0..output_len {
            let idx = if has_active_ranges {
                active_region_data.get_idx(i)
            } else {
                i
            };
            let id = state.id();
            let m1 = T::add_with_public(pub1[idx] * beta + gamma, shared1[idx], id);
            let m2 = T::add_with_public(pub2[idx] * beta + gamma, shared2[idx], id);
            mul1.push(m1);
            mul2.push(m2);
        }

        Ok(T::mul_many(&mul1, &mul2, net, state)?)
    }

    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    fn array_prod_mul(
        &mut self,
        inp: &[T::ArithmeticShare],
    ) -> HonkProofResult<Vec<T::ArithmeticShare>> {
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let len = inp.len();

        let r = (0..=len)
            .map(|_| T::rand(self.net, self.state))
            .collect::<Result<Vec<_>, _>>()?;
        let r_inv = T::inv_many(&r, self.net, self.state)?;
        let r_inv0 = vec![r_inv[0]; len];

        let mut unblind = T::mul_many(&r_inv0, &r[1..], self.net, self.state)?;

        let mul = T::mul_many(&r[..len], inp, self.net, self.state)?;
        let mut open = T::mul_open_many(&mul, &r_inv[1..], self.net, self.state)?;

        for i in 1..open.len() {
            open[i] = open[i] * open[i - 1];
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = T::mul_with_public(*open, *unblind);
        }
        Ok(unblind)
    }

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<T, P, L>) -> HonkProofResult<()> {
        tracing::trace!("compute grand product");

        let has_active_ranges = proving_key.active_region_data.size() > 0;

        // Barratenberg uses multithreading here

        // Set the domain over which the grand product must be computed. This may be less than the dyadic circuit size, e.g
        // the permutation grand product does not need to be computed beyond the index of the last active wire
        let domain_size = proving_key.final_active_wire_idx + 1;

        let active_domain_size = if has_active_ranges {
            proving_key.active_region_data.size()
        } else {
            domain_size
        };

        // In Barretenberg circuit size is taken from the q_c polynomial
        // Step (1)
        // Populate `numerator` and `denominator` with the algebra described by Relation

        // TACEO TODO could batch those 4 as well
        let denom1 = Self::batched_grand_product_num_denom(
            self.net,
            self.state,
            proving_key.polynomials.witness.w_l(),
            proving_key.polynomials.witness.w_r(),
            proving_key.polynomials.precomputed.sigma_1(),
            proving_key.polynomials.precomputed.sigma_2(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            active_domain_size - 1,
            &proving_key.active_region_data,
        )?;
        let denom2 = Self::batched_grand_product_num_denom(
            self.net,
            self.state,
            proving_key.polynomials.witness.w_o(),
            &self.memory.w_4,
            proving_key.polynomials.precomputed.sigma_3(),
            proving_key.polynomials.precomputed.sigma_4(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            active_domain_size - 1,
            &proving_key.active_region_data,
        )?;
        let num1 = Self::batched_grand_product_num_denom(
            self.net,
            self.state,
            proving_key.polynomials.witness.w_l(),
            proving_key.polynomials.witness.w_r(),
            proving_key.polynomials.precomputed.id_1(),
            proving_key.polynomials.precomputed.id_2(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            active_domain_size - 1,
            &proving_key.active_region_data,
        )?;
        let num2 = Self::batched_grand_product_num_denom(
            self.net,
            self.state,
            proving_key.polynomials.witness.w_o(),
            &self.memory.w_4,
            proving_key.polynomials.precomputed.id_3(),
            proving_key.polynomials.precomputed.id_4(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            active_domain_size - 1,
            &proving_key.active_region_data,
        )?;

        // TACEO TODO could batch here as well
        let numerator = T::mul_many(&num1, &num2, self.net, self.state)?;
        let denominator = T::mul_many(&denom1, &denom2, self.net, self.state)?;

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.

        // TACEO TODO could batch here as well
        // Do the multiplications of num[i] * num[i-1] and den[i] * den[i-1] in constant rounds
        let numerator = self.array_prod_mul(&numerator)?;
        let mut denominator = self.array_prod_mul(&denominator)?;

        // invert denominator
        CoUtils::batch_invert::<T, P, N>(&mut denominator, self.net, self.state)?;

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        let mul = T::mul_many(&numerator, &denominator, self.net, self.state)?;

        self.memory.z_perm.resize(
            proving_key.circuit_size as usize,
            T::ArithmeticShare::default(),
        );
        self.memory.z_perm[1] = T::promote_to_trivial_share(self.state.id(), P::ScalarField::one());

        // Compute grand product values corresponding only to the active regions of the trace
        for (i, mul) in mul.into_iter().enumerate() {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i)
            } else {
                i
            };
            self.memory.z_perm[idx + 1] = mul
        }

        // Final step: If active/inactive regions have been specified, the value of the grand product in the inactive
        // regions have not yet been set. The polynomial takes an already computed constant value across each inactive
        // region (since no copy constraints are present there) equal to the value of the grand product at the first index
        // of the subsequent active region.
        if has_active_ranges {
            for i in 0..domain_size {
                for j in 0..proving_key.active_region_data.num_ranges() - 1 {
                    let previous_range_end = proving_key.active_region_data.get_range(j).1;
                    let next_range_start = proving_key.active_region_data.get_range(j + 1).0;
                    // Set the value of the polynomial if the index falls in an inactive region
                    if i >= previous_range_end && i < next_range_start {
                        self.memory.z_perm[i + 1] = self.memory.z_perm[next_range_start];
                    }
                }
            }
        }

        Ok(())
    }

    // Generate relation separators alphas for sumcheck/combiner computation
    fn generate_alphas_round(&mut self, transcript: &mut Transcript<TranscriptFieldType, H>) {
        tracing::trace!("generate alpha round");

        L::get_alpha_challenges::<_, _, P>(transcript, &mut self.memory.challenges.alphas);
    }

    // Add circuit size public input size and public inputs to transcript
    fn execute_preamble_round(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing preamble round");

        transcript
            .add_u64_to_hash_buffer("CIRCUIT_SIZE".to_string(), proving_key.circuit_size as u64);
        transcript.add_u64_to_hash_buffer(
            "PUBLIC_INPUT_SIZE".to_string(),
            proving_key.num_public_inputs as u64,
        );
        transcript.add_u64_to_hash_buffer(
            "PUB_INPUTS_OFFSET".to_string(),
            proving_key.pub_inputs_offset as u64,
        );

        if proving_key.num_public_inputs as usize != proving_key.public_inputs.len() {
            return Err(HonkProofError::CorruptedWitness(
                proving_key.public_inputs.len(),
            ));
        }

        for (i, public_input) in proving_key.public_inputs.iter().enumerate() {
            // transcript.add_scalar(*public_input);
            transcript.send_fr_to_verifier::<P>(format!("PUBLIC_INPUT_{i}"), *public_input);
        }
        Ok(())
    }

    // Compute first three wire commitments
    fn execute_wire_commitments_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, P, L>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            self.mask_polynomial(proving_key.polynomials.witness.w_l_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.w_r_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.w_o_mut())?;
            if L::FLAVOUR == Flavour::Mega {
                self.mask_polynomial(proving_key.polynomials.witness.calldata_mut())?;
                self.mask_polynomial(proving_key.polynomials.witness.calldata_read_counts_mut())?;
                self.mask_polynomial(proving_key.polynomials.witness.calldata_read_tags_mut())?;
                self.mask_polynomial(proving_key.polynomials.witness.secondary_calldata_mut())?;
                self.mask_polynomial(
                    proving_key
                        .polynomials
                        .witness
                        .secondary_calldata_read_counts_mut(),
                )?;
                self.mask_polynomial(
                    proving_key
                        .polynomials
                        .witness
                        .secondary_calldata_read_tags_mut(),
                )?;
                self.mask_polynomial(proving_key.polynomials.witness.return_data_mut())?;
                self.mask_polynomial(
                    proving_key
                        .polynomials
                        .witness
                        .return_data_read_counts_mut(),
                )?;
                self.mask_polynomial(proving_key.polynomials.witness.return_data_read_tags_mut())?;
            }
        };

        let w_l = CoUtils::commit::<T, P>(proving_key.polynomials.witness.w_l().as_ref(), crs);
        let w_r = CoUtils::commit::<T, P>(proving_key.polynomials.witness.w_r().as_ref(), crs);
        let w_o = CoUtils::commit::<T, P>(proving_key.polynomials.witness.w_o().as_ref(), crs);

        if L::FLAVOUR == Flavour::Ultra {
            let open = T::open_point_many(&[w_l, w_r, w_o], self.net, self.state)?;

            transcript.send_point_to_verifier::<P>("W_L".to_string(), open[0].into());
            transcript.send_point_to_verifier::<P>("W_R".to_string(), open[1].into());
            transcript.send_point_to_verifier::<P>("W_O".to_string(), open[2].into());
        } else if L::FLAVOUR == Flavour::Mega {
            // Commit to Goblin ECC op wires.
            // To avoid possible issues with the current work on the merge protocol, they are not
            // masked in MegaZKFlavor
            let ecc_op_wire_1 = CoUtils::commit::<T, P>(
                proving_key.polynomials.witness.ecc_op_wire_1().as_ref(),
                crs,
            );
            let ecc_op_wire_2 = CoUtils::commit::<T, P>(
                proving_key.polynomials.witness.ecc_op_wire_2().as_ref(),
                crs,
            );
            let ecc_op_wire_3 = CoUtils::commit::<T, P>(
                proving_key.polynomials.witness.ecc_op_wire_3().as_ref(),
                crs,
            );
            let ecc_op_wire_4 = CoUtils::commit::<T, P>(
                proving_key.polynomials.witness.ecc_op_wire_4().as_ref(),
                crs,
            );
            let calldata =
                CoUtils::commit::<T, P>(proving_key.polynomials.witness.calldata().as_ref(), crs);
            let calldata_read_counts = CoUtils::commit::<T, P>(
                proving_key
                    .polynomials
                    .witness
                    .calldata_read_counts()
                    .as_ref(),
                crs,
            );
            let calldata_read_tags = CoUtils::commit::<T, P>(
                proving_key
                    .polynomials
                    .witness
                    .calldata_read_tags()
                    .as_ref(),
                crs,
            );
            let secondary_calldata = CoUtils::commit::<T, P>(
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata()
                    .as_ref(),
                crs,
            );
            let secondary_calldata_read_counts = CoUtils::commit::<T, P>(
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_counts()
                    .as_ref(),
                crs,
            );
            let secondary_calldata_read_tags = CoUtils::commit::<T, P>(
                proving_key
                    .polynomials
                    .witness
                    .secondary_calldata_read_tags()
                    .as_ref(),
                crs,
            );
            let return_data = CoUtils::commit::<T, P>(
                proving_key.polynomials.witness.return_data().as_ref(),
                crs,
            );
            let return_data_read_counts = CoUtils::commit::<T, P>(
                proving_key
                    .polynomials
                    .witness
                    .return_data_read_counts()
                    .as_ref(),
                crs,
            );
            let return_data_read_tags = CoUtils::commit::<T, P>(
                proving_key
                    .polynomials
                    .witness
                    .return_data_read_tags()
                    .as_ref(),
                crs,
            );

            let open = T::open_point_many(
                &[
                    w_l,
                    w_r,
                    w_o,
                    ecc_op_wire_1,
                    ecc_op_wire_2,
                    ecc_op_wire_3,
                    ecc_op_wire_4,
                    calldata,
                    calldata_read_counts,
                    calldata_read_tags,
                    secondary_calldata,
                    secondary_calldata_read_counts,
                    secondary_calldata_read_tags,
                    return_data,
                    return_data_read_counts,
                    return_data_read_tags,
                ],
                self.net,
                self.state,
            )?;

            transcript.send_point_to_verifier::<P>("W_L".to_string(), open[0].into());
            transcript.send_point_to_verifier::<P>("W_R".to_string(), open[1].into());
            transcript.send_point_to_verifier::<P>("W_O".to_string(), open[2].into());
            transcript.send_point_to_verifier::<P>("ECC_OP_WIRE_1".to_string(), open[3].into());
            transcript.send_point_to_verifier::<P>("ECC_OP_WIRE_2".to_string(), open[4].into());
            transcript.send_point_to_verifier::<P>("ECC_OP_WIRE_3".to_string(), open[5].into());
            transcript.send_point_to_verifier::<P>("ECC_OP_WIRE_4".to_string(), open[6].into());
            transcript.send_point_to_verifier::<P>("CALLDATA".to_string(), open[7].into());
            transcript
                .send_point_to_verifier::<P>("CALLDATA_READ_COUNTS".to_string(), open[8].into());
            transcript
                .send_point_to_verifier::<P>("CALLDATA_READ_TAGS".to_string(), open[9].into());
            transcript
                .send_point_to_verifier::<P>("SECONDARY_CALLDATA".to_string(), open[10].into());
            transcript.send_point_to_verifier::<P>(
                "SECONDARY_CALLDATA_READ_COUNTS".to_string(),
                open[11].into(),
            );
            transcript.send_point_to_verifier::<P>(
                "SECONDARY_CALLDATA_READ_TAGS".to_string(),
                open[12].into(),
            );
            transcript.send_point_to_verifier::<P>("RETURN_DATA".to_string(), open[13].into());
            transcript.send_point_to_verifier::<P>(
                "RETURN_DATA_READ_COUNTS".to_string(),
                open[14].into(),
            );
            transcript
                .send_point_to_verifier::<P>("RETURN_DATA_READ_TAGS".to_string(), open[15].into());
        }

        Ok(())
    }

    // Compute sorted list accumulator and commitment
    fn execute_sorted_list_accumulator_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, P, L>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing sorted list accumulator round");

        let challs = transcript.get_challenges::<P>(&[
            "eta".to_string(),
            "eta_two".to_string(),
            "eta_three".to_string(),
        ]);
        self.memory.challenges.eta_1 = challs[0];
        self.memory.challenges.eta_2 = challs[1];
        self.memory.challenges.eta_3 = challs[2];
        self.compute_w4(proving_key);

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            self.mask_polynomial(proving_key.polynomials.witness.lookup_read_counts_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.lookup_read_tags_mut())?;
            // we do std::mem::take here to avoid borrowing issues with self
            let mut w_4_tmp = std::mem::take(&mut self.memory.w_4);
            self.mask_polynomial(&mut w_4_tmp)?;
            std::mem::swap(&mut self.memory.w_4, &mut w_4_tmp);
        };

        // Commit to lookup argument polynomials and the finalized (i.e. with memory records) fourth wire polynomial
        let lookup_read_counts = CoUtils::commit::<T, P>(
            proving_key
                .polynomials
                .witness
                .lookup_read_counts()
                .as_ref(),
            crs,
        );
        let lookup_read_tags = CoUtils::commit::<T, P>(
            proving_key.polynomials.witness.lookup_read_tags().as_ref(),
            crs,
        );
        let w_4 = CoUtils::commit::<T, P>(self.memory.w_4.as_ref(), crs);
        let opened = T::open_point_many(
            &[lookup_read_counts, lookup_read_tags, w_4],
            self.net,
            self.state,
        )?;

        transcript.send_point_to_verifier::<P>("LOOKUP_READ_COUNTS".to_string(), opened[0].into());
        transcript.send_point_to_verifier::<P>("LOOKUP_READ_TAGS".to_string(), opened[1].into());
        transcript.send_point_to_verifier::<P>("W_4".to_string(), opened[2].into());

        Ok(())
    }

    // Fiat-Shamir: beta & gamma
    fn execute_log_derivative_inverse_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, P, L>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing log derivative inverse round");

        let challs = transcript.get_challenges::<P>(&["beta".to_string(), "gamma".to_string()]);
        self.memory.challenges.beta = challs[0];
        self.memory.challenges.gamma = challs[1];

        self.compute_logderivative_inverses(proving_key)?;

        // We moved the commiting and opening of the lookup inverses to be at the same time as z_perm

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute grand product(s) and commitments.
    fn execute_grand_product_computation_round(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, P, L>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing grand product computation round");

        self.memory.public_input_delta = self.compute_public_input_delta(proving_key);
        self.compute_grand_product(proving_key)?;

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            // we do std::mem::take here to avoid borrowing issues with self
            let mut lookup_inverses_mut = std::mem::take(&mut self.memory.lookup_inverses);
            self.mask_polynomial(&mut lookup_inverses_mut)?;
            std::mem::swap(&mut self.memory.lookup_inverses, &mut lookup_inverses_mut);
            let mut z_perm_mut = std::mem::take(&mut self.memory.z_perm);
            self.mask_polynomial(&mut z_perm_mut)?;
            std::mem::swap(&mut self.memory.z_perm, &mut z_perm_mut);
        };

        // This is from the previous round, but we open it here with z_perm
        let lookup_inverses = CoUtils::commit::<T, P>(self.memory.lookup_inverses.as_ref(), crs);

        let z_perm = CoUtils::commit::<T, P>(self.memory.z_perm.as_ref(), crs);

        if L::FLAVOUR == Flavour::Ultra {
            let open = T::open_point_many(&[lookup_inverses, z_perm], self.net, self.state)?;

            transcript.send_point_to_verifier::<P>("LOOKUP_INVERSES".to_string(), open[0].into());
            transcript.send_point_to_verifier::<P>("Z_PERM".to_string(), open[1].into());
        } else if L::FLAVOUR == Flavour::Mega {
            if self.has_zk == ZeroKnowledge::Yes {
                let mut calldata_inverses_mut = std::mem::take(&mut self.memory.calldata_inverses);
                self.mask_polynomial(&mut calldata_inverses_mut)?;
                std::mem::swap(
                    &mut self.memory.calldata_inverses,
                    &mut calldata_inverses_mut,
                );
                let mut secondary_calldata_inverses_mut =
                    std::mem::take(&mut self.memory.secondary_calldata_inverses);
                self.mask_polynomial(&mut secondary_calldata_inverses_mut)?;
                std::mem::swap(
                    &mut self.memory.secondary_calldata_inverses,
                    &mut secondary_calldata_inverses_mut,
                );
                let mut return_data_inverses_mut =
                    std::mem::take(&mut self.memory.return_data_inverses);
                self.mask_polynomial(&mut return_data_inverses_mut)?;
                std::mem::swap(
                    &mut self.memory.return_data_inverses,
                    &mut return_data_inverses_mut,
                );
            }
            let calldata_inverses =
                CoUtils::commit::<T, P>(self.memory.calldata_inverses.as_ref(), crs);
            let secondary_calldata_inverses =
                CoUtils::commit::<T, P>(self.memory.secondary_calldata_inverses.as_ref(), crs);
            let return_data_inverses =
                CoUtils::commit::<T, P>(self.memory.return_data_inverses.as_ref(), crs);
            let open = T::open_point_many(
                &[
                    lookup_inverses,
                    z_perm,
                    calldata_inverses,
                    secondary_calldata_inverses,
                    return_data_inverses,
                ],
                self.net,
                self.state,
            )?;
            transcript.send_point_to_verifier::<P>("LOOKUP_INVERSES".to_string(), open[0].into());
            transcript.send_point_to_verifier::<P>("CALLDATA_INVERSES".to_string(), open[2].into());
            transcript.send_point_to_verifier::<P>(
                "SECONDARY_CALLDATA_INVERSES".to_string(),
                open[3].into(),
            );
            transcript
                .send_point_to_verifier::<P>("RETURN_DATA_INVERSES".to_string(), open[4].into());
            transcript.send_point_to_verifier::<P>("Z_PERM".to_string(), open[1].into());
        }

        Ok(())
    }

    pub(crate) fn prove(
        mut self,
        proving_key: &mut ProvingKey<T, P, L>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<P>,
    ) -> HonkProofResult<ProverMemory<T, P, L>> {
        tracing::trace!("Oink prove");

        // Add circuit size public input size and public inputs to transcript
        Self::execute_preamble_round(transcript, proving_key)?;
        // Compute first three wire commitments
        self.execute_wire_commitments_round(transcript, proving_key, crs)?;
        // Compute sorted list accumulator and commitment
        self.execute_sorted_list_accumulator_round(transcript, proving_key, crs)?;

        // Fiat-Shamir: beta & gamma
        self.execute_log_derivative_inverse_round(transcript, proving_key)?;
        // Compute grand product(s) and commitments.
        self.execute_grand_product_computation_round(transcript, proving_key, crs)?;

        // Generate relation separators alphas for sumcheck/combiner computation
        self.generate_alphas_round(transcript);

        Ok(self.memory)
    }
}
