use crate::types::big_group::BigGroup;
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_ec::CurveGroup;
use ark_ff::{One, PrimeField};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;

/**
 * @brief Given two lists of points that need to be multiplied by scalars, create a new list of length +1 with original
 * points masked, but the same scalar product sum
 * @details Add +1G, +2G, +4G etc to the original points and adds a new point 2ⁿ⋅G and scalar x to the lists. By
 * doubling the point every time, we ensure that no +-1 combination of 6 sequential elements run into edgecases, unless
 * the points are deliberately constructed to trigger it.
 */
#[allow(clippy::type_complexity)]
pub(crate) fn mask_points<
    F: PrimeField,
    P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    T: NoirWitnessExtensionProtocol<F>,
>(
    points: &mut [BigGroup<F, T>],
    scalars: &[FieldCT<F>],
    masking_scalar: &FieldCT<F>,
    builder: &mut GenericUltraCircuitBuilder<P, T>,
    driver: &mut T,
) -> eyre::Result<(Vec<BigGroup<F, T>>, Vec<FieldCT<F>>)> {
    let mut masked_points = Vec::new();
    let mut masked_scalars = Vec::new();

    debug_assert!(points.len() == scalars.len());

    // Get the offset generator G_offset in native and in-circuit form
    let native_offset_generator =
        BigGroup::<F, T>::precomputed_native_table_offset_generator::<P>()?;
    let mut offset_generator_element =
        BigGroup::from_witness(&native_offset_generator, driver, builder)?;

    // Compute initial point to be added: (δ)⋅G_offset
    let mut running_point =
        offset_generator_element.scalar_mul(masking_scalar, 128, builder, driver)?;

    // Start the running scalar at 1
    let mut running_scalar = FieldCT::from(F::ONE);
    let mut last_scalar = FieldCT::from(F::ZERO);

    // For each point and scalar
    for (point, scalar) in points.iter_mut().zip(scalars.iter()) {
        masked_scalars.push(scalar.clone());

        // Convert point into point + 2ⁱ⋅G_offset
        masked_points.push(point.add(&mut running_point, builder, driver)?);

        // Add 2ⁱ⋅scalar_i to the last scalar
        let tmp = scalar.multiply(&running_scalar, builder, driver)?;
        last_scalar.add_assign(&tmp, builder, driver);

        // Double the running scalar and point for next iteration
        running_scalar.add_assign(&running_scalar.clone(), builder, driver);

        // Double the running point
        running_point = running_point.dbl(builder, driver)?;
    }

    // Add a scalar -(<(1,2,4,...,2ⁿ⁻¹ ),(scalar₀,...,scalarₙ₋₁)> / 2ⁿ)
    let n = points.len();
    let two_power_n = F::from(BigUint::one() << n);
    let two_power_n_inv = two_power_n.inverse().expect("Scalar inversion failed");
    last_scalar = last_scalar.multiply(&FieldCT::from(two_power_n_inv), builder, driver)?;
    masked_scalars.push(last_scalar.neg());

    // Add in-circuit 2ⁿ.(δ.G_offset) to points
    masked_points.push(running_point);

    Ok((masked_points, masked_scalars))
}

/**
 * @brief Replace all pairs (∞, scalar) by the pair (one, 0) where one is a fixed generator of the curve
 * @details This is a step in enabling our our multiscalar multiplication algorithms to hande points at infinity.
 */
// TACEO TODO: Batch FieldCT ops
#[allow(clippy::type_complexity)]
pub(crate) fn handle_points_at_infinity<
    F: PrimeField,
    P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    T: NoirWitnessExtensionProtocol<F>,
>(
    points: &[BigGroup<F, T>],
    scalars: &[FieldCT<F>],
    builder: &mut GenericUltraCircuitBuilder<P, T>,
    driver: &mut T,
) -> eyre::Result<(Vec<BigGroup<F, T>>, Vec<FieldCT<F>>)> {
    let one = BigGroup::one();
    let mut new_points = Vec::new();
    let mut new_scalars = Vec::new();

    for (point, scalar) in points.iter().zip(scalars.iter()) {
        let is_infinity = &point.is_infinity;

        if is_infinity.is_constant() && is_infinity.get_value(driver) == F::ONE.into() {
            // if point is at infinity and a circuit constant we can just skip.
            continue;
        }

        if scalar.is_constant() && scalar.get_value(builder, driver) == P::ScalarField::ZERO.into()
        {
            // if scalar is zero and a circuit constant we can just skip.
            continue;
        }

        let point = point.conditional_select(&one, is_infinity, builder, driver)?;

        // No normalize
        let updated_scalar = FieldCT::conditional_assign_internal(
            is_infinity,
            &FieldCT::from(F::ZERO),
            scalar,
            builder,
            driver,
        )?;

        new_points.push(point);
        new_scalars.push(updated_scalar);

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1002): if both point and scalar are constant,
        // don't bother adding constraints
    }

    Ok((new_points, new_scalars))
}
