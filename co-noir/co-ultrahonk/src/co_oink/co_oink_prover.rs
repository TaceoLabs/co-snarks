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
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use co_noir_common::{
    CoUtils,
    constants::PERMUTATION_ARGUMENT_VALUE_SEPARATOR,
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, HonkProofResult, TranscriptFieldType},
    keys::{
        proving_key::ProvingKey, types::ActiveRegionData,
        verification_key::VerifyingKeyBarretenberg,
    },
    mpc::NoirUltraHonkProver,
    polynomials::polynomial::{NUM_MASKED_ROWS, Polynomial},
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use itertools::izip;
use mpc_core::MpcState as _;
use mpc_net::Network;
use std::marker::PhantomData;
use ultrahonk::NUM_ALPHAS;

pub(crate) struct CoOink<
    'a,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
> {
    net: &'a N,
    state: &'a mut T::State,
    memory: ProverMemory<T, C>,
    phantom_data: PhantomData<C>,
    phantom_hasher: PhantomData<H>,
    has_zk: ZeroKnowledge,
}

impl<
    'a,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
> CoOink<'a, T, C, H, N>
{
    fn field_to_hex<F: PrimeField>(value: &F) -> String {
        let mut bytes = value.into_bigint().to_bytes_be();
        let byte_len = (F::MODULUS_BIT_SIZE as usize).div_ceil(8);
        if bytes.len() < byte_len {
            let mut padded = vec![0u8; byte_len - bytes.len()];
            padded.extend_from_slice(&bytes);
            bytes = padded;
        }
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("0x{hex}")
    }

    fn print_point_hex(label: &str, point: &C::Affine) {
        if point.is_zero() {
            println!("{label}: INF");
            return;
        }
        let (x, y) = C::g1_affine_to_xy(point);
        println!(
            "{label}: x={} y={}",
            Self::field_to_hex(&x),
            Self::field_to_hex(&y)
        );
    }

    pub(crate) fn new(net: &'a N, state: &'a mut T::State, has_zk: ZeroKnowledge) -> Self {
        Self {
            net,
            state,
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
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

    fn compute_w4_inner(&mut self, proving_key: &ProvingKey<T, C>, gate_idx: usize) {
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

    fn add_ram_rom_memory_records_to_wire_4(&mut self, proving_key: &ProvingKey<T, C>) {
        tracing::trace!("add_ram_rom_memory_records_to_wire_4");
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
            *target = T::add_with_public(C::ScalarField::one(), *target, self.state.id());
        }

        // This computes the values for cases where the type (r/w) of the record is a secret share of 0/1 and adds this share
        for (gate_idx, type_share) in proving_key.memory_records_shared.iter() {
            let gate_idx = *gate_idx as usize;
            self.compute_w4_inner(proving_key, gate_idx);
            let target = &mut self.memory.w_4[gate_idx];
            *target = T::add(*type_share, *target);
        }
    }

    fn compute_lookup_term(
        &mut self,
        proving_key: &ProvingKey<T, C>,
        i: usize,
    ) -> T::ArithmeticShare {
        tracing::trace!("compute lookup term");

        let gamma = self.memory.challenges.gamma;
        let beta = self.memory.challenges.beta;
        let beta_sqr = self.memory.challenges.beta_sqr;
        let beta_cube = self.memory.challenges.beta_cube;

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

        let table_index_entry = beta_cube * table_index;

        // (w_1 + \gamma + q_2*w_1_shift) + β(w_2 + q_m*w_2_shift) + β²(w_3 + q_c*w_3_shift) + β³q_index.
        // deg 2 or 3
        let mul = T::mul_with_public(beta, derived_table_entry_2);
        let res = T::add(derived_table_entry_1, mul);
        let mul = T::mul_with_public(beta_sqr, derived_table_entry_3);
        let res = T::add(res, mul);
        T::add_with_public(table_index_entry, res, id)
    }

    // Compute table_1 + gamma + table_2 * beta + table_3 * beta^2 + table_4 * beta^3
    fn compute_table_term(&self, proving_key: &ProvingKey<T, C>, i: usize) -> C::ScalarField {
        tracing::trace!("compute table term");

        let gamma = &self.memory.challenges.gamma;
        let beta = self.memory.challenges.beta;
        let beta_sqr = self.memory.challenges.beta_sqr;
        let beta_cube = self.memory.challenges.beta_cube;
        let table_1 = &proving_key.polynomials.precomputed.table_1()[i];
        let table_2 = &proving_key.polynomials.precomputed.table_2()[i];
        let table_3 = &proving_key.polynomials.precomputed.table_3()[i];
        let table_4 = &proving_key.polynomials.precomputed.table_4()[i];

        *table_1 + gamma + *table_2 * beta + *table_3 * beta_sqr + *table_4 * beta_cube
    }

    fn compute_logderivative_inverses(
        &mut self,
        proving_key: &ProvingKey<T, C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("compute logderivative inverse");

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
                T::mul_with_public(C::ScalarField::one() - q_lookup, lookup_read_tag.to_owned());
            q_lookup_mul_read_tag.push(T::add_with_public(
                q_lookup.to_owned(),
                mul,
                self.state.id(),
            ));

            // READ_TERMS and WRITE_TERMS are 1, so we skip the loop
            let read_term = self.compute_lookup_term(proving_key, i);
            let write_term = self.compute_table_term(proving_key, i);
            self.memory.lookup_inverses[i] = T::mul_with_public(write_term, read_term);
        }
        self.memory.lookup_inverses = Polynomial::new(T::mul_many(
            self.memory.lookup_inverses.as_ref(),
            &q_lookup_mul_read_tag,
            self.net,
            self.state,
        )?);

        // Compute inverse polynomial I in place by inverting the product at each row
        // Note: zeroes are ignored as they are not used anyway
        CoUtils::batch_invert_leaking_zeros::<T, C, N>(
            self.memory.lookup_inverses.as_mut(),
            self.net,
            self.state,
        )?;
        Ok(())
    }

    fn compute_public_input_delta(&self, proving_key: &ProvingKey<T, C>) -> C::ScalarField {
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

        let mut num = C::ScalarField::one();
        let mut denom = C::ScalarField::one();
        let separator = PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
        let mut num_acc = self.memory.challenges.gamma
            + self.memory.challenges.beta
                * C::ScalarField::from((separator + proving_key.pub_inputs_offset) as u64);
        let mut denom_acc = self.memory.challenges.gamma
            - self.memory.challenges.beta
                * C::ScalarField::from((1 + proving_key.pub_inputs_offset) as u64);

        for (i, x_i) in proving_key.public_inputs.iter().enumerate() {
            num *= num_acc + x_i;
            denom *= denom_acc + x_i;

            if i < proving_key.public_inputs.len() - 1 {
                num_acc += self.memory.challenges.beta;
                denom_acc -= self.memory.challenges.beta;
            }
        }
        num / denom
    }

    #[expect(clippy::too_many_arguments)]
    fn batched_grand_product_num_denom(
        net: &N,
        state: &mut T::State,
        shared1: &Polynomial<T::ArithmeticShare>,
        shared2: &Polynomial<T::ArithmeticShare>,
        pub1: &Polynomial<C::ScalarField>,
        pub2: &Polynomial<C::ScalarField>,
        beta: &C::ScalarField,
        gamma: &C::ScalarField,
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

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<T, C>) -> HonkProofResult<()> {
        tracing::trace!("compute grand product");

        let has_active_ranges = proving_key.active_region_data.size() > 0;

        // Barretenberg uses multithreading here

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
        let numerator = CoUtils::array_prod_mul::<T, C, N>(self.net, self.state, &numerator)?;
        let mut denominator =
            CoUtils::array_prod_mul::<T, C, N>(self.net, self.state, &denominator)?;

        // invert denominator
        CoUtils::batch_invert::<T, C, N>(&mut denominator, self.net, self.state)?;

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        let mul = T::mul_many(&numerator, &denominator, self.net, self.state)?;

        self.memory.z_perm.resize(
            proving_key.circuit_size as usize,
            T::ArithmeticShare::default(),
        );
        self.memory.z_perm[1] = T::promote_to_trivial_share(self.state.id(), C::ScalarField::one());

        // Compute grand product values corresponding only to the active regions of the trace
        for (i, mul) in mul.into_iter().enumerate() {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i + 1)
            } else {
                i + 1
            };
            self.memory.z_perm[idx] = mul
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
                        self.memory.z_perm[i] = self.memory.z_perm[next_range_start];
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    // Generate relation separators alphas for sumcheck/combiner computation
    fn generate_alphas_round(&mut self, transcript: &mut Transcript<TranscriptFieldType, H>) {
        tracing::trace!("generate alpha round");

        let alpha = transcript.get_challenge::<C>("alpha".to_string());
        let mut alpha_powers = [C::ScalarField::one(); NUM_ALPHAS];
        alpha_powers[0] = alpha;
        for i in 1..NUM_ALPHAS {
            alpha_powers[i] = alpha_powers[i - 1] * alpha;
        }
        self.memory.challenges.alphas.copy_from_slice(&alpha_powers);
    }

    // Add circuit size public input size and public inputs to transcript
    fn send_vk_hash_and_public_inputs(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, C>,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing preamble round");

        let vk_hash = verifying_key.hash_with_origin_tagging::<H>("", transcript);
        transcript.add_fr_to_hash_buffer::<C>("VK_HASH".to_string(), vk_hash);

        if proving_key.num_public_inputs as usize != proving_key.public_inputs.len() {
            return Err(HonkProofError::CorruptedWitness(
                proving_key.public_inputs.len(),
            ));
        }

        for (i, public_input) in proving_key.public_inputs.iter().enumerate() {
            // transcript.add_scalar(*public_input);
            transcript.send_fr_to_verifier::<C>(format!("PUBLIC_INPUT_{i}"), *public_input);
        }
        Ok(())
    }

    // Compute first three wire commitments
    fn commit_to_wires(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, C>,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            self.mask_polynomial(proving_key.polynomials.witness.w_l_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.w_r_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.w_o_mut())?;
        };

        let w_l = CoUtils::commit::<T, C>(proving_key.polynomials.witness.w_l().as_ref(), crs);
        let w_r = CoUtils::commit::<T, C>(proving_key.polynomials.witness.w_r().as_ref(), crs);
        let w_o = CoUtils::commit::<T, C>(proving_key.polynomials.witness.w_o().as_ref(), crs);
        let open = T::open_point_many(&[w_l, w_r, w_o], self.net, self.state)?;

        let w_l: C::Affine = open[0].into();
        let w_r: C::Affine = open[1].into();
        let w_o: C::Affine = open[2].into();
        Self::print_point_hex("W_L", &w_l);
        Self::print_point_hex("W_R", &w_r);
        Self::print_point_hex("W_O", &w_o);
        transcript.send_point_to_verifier::<C>("W_L".to_string(), w_l);
        transcript.send_point_to_verifier::<C>("W_R".to_string(), w_r);
        transcript.send_point_to_verifier::<C>("W_O".to_string(), w_o);

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute sorted witness-table accumulator and commit to the resulting polynomials.
    fn commit_to_lookup_counts_and_w4(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, C>,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing sorted list accumulator round");

        let eta = transcript.get_challenge::<C>("eta".to_string());
        self.memory.challenges.eta_1 = eta;
        self.memory.challenges.eta_2 = eta * eta;
        self.memory.challenges.eta_3 = eta * eta * eta;

        self.add_ram_rom_memory_records_to_wire_4(proving_key);

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
        let lookup_read_counts = CoUtils::commit::<T, C>(
            proving_key
                .polynomials
                .witness
                .lookup_read_counts()
                .as_ref(),
            crs,
        );
        let lookup_read_tags = CoUtils::commit::<T, C>(
            proving_key.polynomials.witness.lookup_read_tags().as_ref(),
            crs,
        );
        let w_4 = CoUtils::commit::<T, C>(self.memory.w_4.as_ref(), crs);

        let opened = T::open_point_many(
            &[lookup_read_counts, lookup_read_tags, w_4],
            self.net,
            self.state,
        )?;

        let lookup_read_counts: C::Affine = opened[0].into();
        let lookup_read_tags: C::Affine = opened[1].into();
        let w_4: C::Affine = opened[2].into();

        Self::print_point_hex("LOOKUP_READ_COUNTS", &lookup_read_counts);
        Self::print_point_hex("LOOKUP_READ_TAGS", &lookup_read_tags);
        Self::print_point_hex("W_4", &w_4);

        transcript
            .send_point_to_verifier::<C>("LOOKUP_READ_COUNTS".to_string(), lookup_read_counts);
        transcript.send_point_to_verifier::<C>("LOOKUP_READ_TAGS".to_string(), lookup_read_tags);
        transcript.send_point_to_verifier::<C>("W_4".to_string(), w_4);

        Ok(())
    }

    // Compute log derivative inverse polynomial and its commitment, if required
    fn commit_to_logderiv_inverses(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("commit_to_logderiv_inverses");

        let [beta, gamma] = transcript
            .get_challenges::<C>(&["beta".to_string(), "gamma".to_string()])
            .try_into()
            .unwrap();
        self.memory.challenges.beta = beta;
        self.memory.challenges.beta_sqr = beta * beta;
        self.memory.challenges.beta_cube = beta * beta * beta;
        self.memory.challenges.gamma = gamma;

        // Compute the inverses used in log-derivative lookup relations
        self.compute_logderivative_inverses(proving_key)?;

        // We moved the commiting and opening of the lookup inverses to be at the same time as z_perm

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute the permutation grand product polynomial and commit to it.
    fn commit_to_z_perm(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, C>,
        crs: &ProverCrs<C>,
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
        let lookup_inverses = CoUtils::commit::<T, C>(self.memory.lookup_inverses.as_ref(), crs);

        let z_perm = CoUtils::commit::<T, C>(self.memory.z_perm.as_ref(), crs);

        let open = T::open_point_many(&[lookup_inverses, z_perm], self.net, self.state)?;

        let lookup_inverses: C::Affine = open[0].into();
        let z_perm: C::Affine = open[1].into();
        Self::print_point_hex("LOOKUP_INVERSES", &lookup_inverses);
        Self::print_point_hex("Z_PERM", &z_perm);
        transcript.send_point_to_verifier::<C>("LOOKUP_INVERSES".to_string(), lookup_inverses);
        transcript.send_point_to_verifier::<C>("Z_PERM".to_string(), z_perm);
        Ok(())
    }

    pub(crate) fn prove(
        mut self,
        proving_key: &mut ProvingKey<T, C>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<C>,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<ProverMemory<T, C>> {
        tracing::trace!("Oink prove");
        println!("Starting proof generation");

        // Add circuit size public input size and public inputs to transcript
        Self::send_vk_hash_and_public_inputs(transcript, proving_key, verifying_key)?;
        // Compute first three wire commitments
        self.commit_to_wires(transcript, proving_key, crs)?;
        // Compute sorted list accumulator and commitment
        self.commit_to_lookup_counts_and_w4(transcript, proving_key, crs)?;

        // Fiat-Shamir: beta & gamma
        self.commit_to_logderiv_inverses(transcript, proving_key)?;
        // Compute grand product(s) and commitments.
        self.commit_to_z_perm(transcript, proving_key, crs)?;

        // Generate relation separators alphas for sumcheck/combiner computation
        self.generate_alphas_round(transcript);

        Ok(self.memory)
    }
}
