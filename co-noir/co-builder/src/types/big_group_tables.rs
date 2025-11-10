use crate::types::big_group::{BigGroup, ChainAddAccumulator};
use std::array;
use std::cmp::max;

use crate::types::big_field::BigField;
use crate::types::rom_ram::TwinRomTable;
use crate::{types::field_ct::FieldCT, ultra_builder::GenericUltraCircuitBuilder};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use num_bigint::BigUint;

use super::field_ct::BoolCT;

pub struct LookupTablePlookup<const SIZE: usize, F: PrimeField, T: NoirWitnessExtensionProtocol<F>>
{
    element_table: [BigGroup<F, T>; SIZE],
    coordinates: [TwinRomTable<F>; 5],
    limb_max: [BigUint; 8],
}

impl<const SIZE: usize, F: PrimeField, T: NoirWitnessExtensionProtocol<F>>
    LookupTablePlookup<SIZE, F, T>
{
    pub fn new<const LENGTH: usize, P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        inputs: &mut [BigGroup<F, T>; LENGTH],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        debug_assert_eq!(1 << LENGTH, SIZE);
        let mut element_table = array::from_fn(|_| BigGroup::default());

        if LENGTH == 2 {
            let (a0, a1) =
                inputs[1]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[0], builder, driver)?;
            element_table[0] = a0;
            element_table[1] = a1;
        } else if LENGTH == 3 {
            let (mut r0, mut r1) =
                inputs[1]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[0], builder, driver)?;
            let (t0, t1) = inputs[2].checked_unconditional_add_sub(&mut r0, builder, driver)?;
            let (t2, t3) = inputs[2].checked_unconditional_add_sub(&mut r1, builder, driver)?;

            element_table[0] = t0;
            element_table[1] = t2;
            element_table[2] = t3;
            element_table[3] = t1;
        } else if LENGTH == 4 {
            let (mut t0, mut t1) =
                inputs[1]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[0], builder, driver)?;
            let (mut t2, mut t3) =
                inputs[3]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[2], builder, driver)?;

            let (f0, f3) = t2.checked_unconditional_add_sub(&mut t0, builder, driver)?;
            let (f1, f2) = t2.checked_unconditional_add_sub(&mut t1, builder, driver)?;
            let (f4, f7) = t3.checked_unconditional_add_sub(&mut t0, builder, driver)?;
            let (f5, f6) = t3.checked_unconditional_add_sub(&mut t1, builder, driver)?;

            element_table[0] = f0;
            element_table[1] = f1;
            element_table[2] = f2;
            element_table[3] = f3;
            element_table[4] = f4;
            element_table[5] = f5;
            element_table[6] = f6;
            element_table[7] = f7;
        } else if LENGTH == 5 {
            let (mut a0, mut a1) =
                inputs[1]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[0], builder, driver)?;
            let (mut t2, mut t3) =
                inputs[3]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[2], builder, driver)?;

            let (mut e0, mut e3) =
                inputs[4].checked_unconditional_add_sub(&mut t2, builder, driver)?;
            let (mut e1, mut e2) =
                inputs[4].checked_unconditional_add_sub(&mut t3, builder, driver)?;

            let (f0, f3) = e0.checked_unconditional_add_sub(&mut a0, builder, driver)?;
            let (f1, f2) = e0.checked_unconditional_add_sub(&mut a1, builder, driver)?;
            let (f4, f7) = e1.checked_unconditional_add_sub(&mut a0, builder, driver)?;
            let (f5, f6) = e1.checked_unconditional_add_sub(&mut a1, builder, driver)?;
            let (f8, f11) = e2.checked_unconditional_add_sub(&mut a0, builder, driver)?;
            let (f9, f10) = e2.checked_unconditional_add_sub(&mut a1, builder, driver)?;
            let (f12, f15) = e3.checked_unconditional_add_sub(&mut a0, builder, driver)?;
            let (f13, f14) = e3.checked_unconditional_add_sub(&mut a1, builder, driver)?;

            element_table[0] = f0;
            element_table[1] = f1;
            element_table[2] = f2;
            element_table[3] = f3;
            element_table[4] = f4;
            element_table[5] = f5;
            element_table[6] = f6;
            element_table[7] = f7;
            element_table[8] = f8;
            element_table[9] = f9;
            element_table[10] = f10;
            element_table[11] = f11;
            element_table[12] = f12;
            element_table[13] = f13;
            element_table[14] = f14;
            element_table[15] = f15;
        } else if LENGTH == 6 {
            // 44 adds! Only use this if it saves us adding another table to a multi-scalar-multiplication

            let (mut a0, mut a1) =
                inputs[1]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[0], builder, driver)?;
            let (mut e0, mut e1) =
                inputs[4]
                    .clone()
                    .checked_unconditional_add_sub(&mut inputs[3], builder, driver)?;
            let (mut c0, mut c3) =
                inputs[2].checked_unconditional_add_sub(&mut a0, builder, driver)?;
            let (mut c1, mut c2) =
                inputs[2].checked_unconditional_add_sub(&mut a1, builder, driver)?;

            let (mut f0, mut f3) =
                inputs[5].checked_unconditional_add_sub(&mut e0, builder, driver)?;
            let (mut f1, mut f2) =
                inputs[5].checked_unconditional_add_sub(&mut e1, builder, driver)?;

            let (r0, r7) = f0.checked_unconditional_add_sub(&mut c0, builder, driver)?;
            let (r1, r6) = f0.checked_unconditional_add_sub(&mut c1, builder, driver)?;
            let (r2, r5) = f0.checked_unconditional_add_sub(&mut c2, builder, driver)?;
            let (r3, r4) = f0.checked_unconditional_add_sub(&mut c3, builder, driver)?;

            let (s0, s7) = f1.checked_unconditional_add_sub(&mut c0, builder, driver)?;
            let (s1, s6) = f1.checked_unconditional_add_sub(&mut c1, builder, driver)?;
            let (s2, s5) = f1.checked_unconditional_add_sub(&mut c2, builder, driver)?;
            let (s3, s4) = f1.checked_unconditional_add_sub(&mut c3, builder, driver)?;

            let (u0, u7) = f2.checked_unconditional_add_sub(&mut c0, builder, driver)?;
            let (u1, u6) = f2.checked_unconditional_add_sub(&mut c1, builder, driver)?;
            let (u2, u5) = f2.checked_unconditional_add_sub(&mut c2, builder, driver)?;
            let (u3, u4) = f2.checked_unconditional_add_sub(&mut c3, builder, driver)?;

            let (w0, w7) = f3.checked_unconditional_add_sub(&mut c0, builder, driver)?;
            let (w1, w6) = f3.checked_unconditional_add_sub(&mut c1, builder, driver)?;
            let (w2, w5) = f3.checked_unconditional_add_sub(&mut c2, builder, driver)?;
            let (w3, w4) = f3.checked_unconditional_add_sub(&mut c3, builder, driver)?;

            element_table[0] = r0;
            element_table[1] = r1;
            element_table[2] = r2;
            element_table[3] = r3;
            element_table[4] = r4;
            element_table[5] = r5;
            element_table[6] = r6;
            element_table[7] = r7;

            element_table[8] = s0;
            element_table[9] = s1;
            element_table[10] = s2;
            element_table[11] = s3;
            element_table[12] = s4;
            element_table[13] = s5;
            element_table[14] = s6;
            element_table[15] = s7;

            element_table[16] = u0;
            element_table[17] = u1;
            element_table[18] = u2;
            element_table[19] = u3;
            element_table[20] = u4;
            element_table[21] = u5;
            element_table[22] = u6;
            element_table[23] = u7;

            element_table[24] = w0;
            element_table[25] = w1;
            element_table[26] = w2;
            element_table[27] = w3;
            element_table[28] = w4;
            element_table[29] = w5;
            element_table[30] = w6;
            element_table[31] = w7;
        }

        for i in 0..SIZE / 2 {
            element_table[i + SIZE / 2] = element_table[SIZE / 2 - 1 - i].neg(builder, driver)?;
        }

        let mut limb_max = array::from_fn(|_| BigUint::from(0u64));
        let coordinates = Self::create_group_element_rom_tables(&element_table, &mut limb_max)?;

        Ok(LookupTablePlookup {
            element_table,
            coordinates,
            limb_max,
        })
    }

    /**
     * @brief Constructs a ROM table to look up linear combinations of group elements
     *
     * @tparam C
     * @tparam Fq
     * @tparam Fr
     * @tparam G
     * @tparam num_elements
     * @tparam typename
     * @param rom_data the ROM table we are writing into
     * @param limb_max the maximum size of each limb in the ROM table.
     *
     * @details When reading a group element *out* of the ROM table, we must know the maximum value of each coordinate's
     * limbs. We take this value to be the maximum of the maximum values of the input limbs into the table!
     * @return std::array<twin_rom_table<C>, 5>
     **/
    fn create_group_element_rom_tables(
        rom_data: &[BigGroup<F, T>],
        limb_max: &mut [BigUint; 8],
    ) -> eyre::Result<[TwinRomTable<F>; 5]> {
        let num_elements = rom_data.len();

        let mut x_lo_limbs = Vec::with_capacity(num_elements);
        let mut x_hi_limbs = Vec::with_capacity(num_elements);
        let mut y_lo_limbs = Vec::with_capacity(num_elements);
        let mut y_hi_limbs = Vec::with_capacity(num_elements);
        let mut prime_limbs = Vec::with_capacity(num_elements);

        for i in 0..num_elements {
            for j in 0..4 {
                limb_max[j] = max(
                    limb_max[j].clone(),
                    rom_data[i].x.binary_basis_limbs[j].maximum_value.clone(),
                );
                limb_max[j + 4] = max(
                    limb_max[j + 4].clone(),
                    rom_data[i].y.binary_basis_limbs[j].maximum_value.clone(),
                );
            }

            x_lo_limbs.push([
                rom_data[i].x.binary_basis_limbs[0].element.clone(),
                rom_data[i].x.binary_basis_limbs[1].element.clone(),
            ]);
            x_hi_limbs.push([
                rom_data[i].x.binary_basis_limbs[2].element.clone(),
                rom_data[i].x.binary_basis_limbs[3].element.clone(),
            ]);
            y_lo_limbs.push([
                rom_data[i].y.binary_basis_limbs[0].element.clone(),
                rom_data[i].y.binary_basis_limbs[1].element.clone(),
            ]);
            y_hi_limbs.push([
                rom_data[i].y.binary_basis_limbs[2].element.clone(),
                rom_data[i].y.binary_basis_limbs[3].element.clone(),
            ]);
            prime_limbs.push([
                rom_data[i].x.prime_basis_limb.clone(),
                rom_data[i].y.prime_basis_limb.clone(),
            ]);
        }

        let output_tables = [
            TwinRomTable::new(x_lo_limbs),
            TwinRomTable::new(x_hi_limbs),
            TwinRomTable::new(y_lo_limbs),
            TwinRomTable::new(y_hi_limbs),
            TwinRomTable::new(prime_limbs),
        ];

        Ok(output_tables)
    }

    fn read_group_element_rom_tables<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        tables: &mut [TwinRomTable<F>; 5],
        index: &FieldCT<F>,
        limb_max: &[BigUint; 8],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigGroup<F, T>> {
        let xlo = tables[0].get(index, builder, driver)?;
        let xhi = tables[1].get(index, builder, driver)?;
        let ylo = tables[2].get(index, builder, driver)?;
        let yhi = tables[3].get(index, builder, driver)?;
        let xyprime = tables[4].get(index, builder, driver)?;

        // We assign maximum_value of each limb here, so we can use the unsafe API from element construction
        let mut x_fq = BigField::unsafe_construct_from_limbs(
            &xlo[0],
            &xlo[1],
            &xhi[0],
            &xhi[1],
            &xyprime[0],
            false,
        );
        let mut y_fq = BigField::unsafe_construct_from_limbs(
            &ylo[0],
            &ylo[1],
            &yhi[0],
            &yhi[1],
            &xyprime[1],
            false,
        );

        for j in 0..4 {
            x_fq.binary_basis_limbs[j].maximum_value = limb_max[j].clone();
            y_fq.binary_basis_limbs[j].maximum_value = limb_max[j + 4].clone();
        }

        Ok(BigGroup::new(x_fq, y_fq))
    }

    pub(crate) fn get<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &mut self,
        bits: &[BoolCT<F, T>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<BigGroup<F, T>> {
        assert_eq!(bits.len(), SIZE.ilog2() as usize);
        let mut accumulators = Vec::new();
        for (i, bit) in bits.iter().enumerate() {
            accumulators.push(FieldCT::from(F::from(1u64 << i)).multiply(
                &bit.to_field_ct(driver),
                builder,
                driver,
            )?);
        }

        let index = FieldCT::accumulate(&accumulators, builder, driver)?;
        println!(
            "LookupTablePlookup::get: index = {:?}",
            index.get_value(builder, driver)
        );
        Self::read_group_element_rom_tables(
            &mut self.coordinates,
            &index,
            &self.limb_max,
            builder,
            driver,
        )
    }
}

pub struct BatchLookupTablePlookup<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> {
    num_points: usize,
    num_sixes: usize,
    num_fives: usize,
    has_quad: bool,
    has_triple: bool,
    has_twin: bool,
    has_singleton: bool,

    six_tables: Vec<LookupTablePlookup<64, F, T>>,
    five_tables: Vec<LookupTablePlookup<32, F, T>>,
    quad_tables: Vec<LookupTablePlookup<16, F, T>>,
    triple_tables: Vec<LookupTablePlookup<8, F, T>>,
    twin_tables: Vec<LookupTablePlookup<4, F, T>>,
    singletons: Vec<BigGroup<F, T>>,
}

impl<F: PrimeField, T: NoirWitnessExtensionProtocol<F>> BatchLookupTablePlookup<F, T> {
    pub fn new<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        points: &[BigGroup<F, T>],
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<Self> {
        let num_points = points.len();
        let mut num_sixes = 0;
        let mut num_fives = num_points / 5;

        // size-6 table is expensive and only benefits us if creating them reduces the number of total tables
        if num_points == 1 {
            num_fives = 0;
            num_sixes = 0;
        } else if num_fives * 5 == (num_points - 1) {
            // last 6 points to be added as one 6-table
            num_fives -= 1;
            num_sixes = 1;
        } else if num_fives * 5 == (num_points - 2) && num_fives >= 2 {
            // last 12 points to be added as two 6-tables
            num_fives -= 2;
            num_sixes = 2;
        } else if num_fives * 5 == (num_points - 3) && num_fives >= 3 {
            // last 18 points to be added as three 6-tables
            num_fives -= 3;
            num_sixes = 3;
        }
        // Calculate remaining points after allocating fives and sixes tables
        let mut remaining_points = num_points - (num_fives * 5 + num_sixes * 6);

        // Allocate one quad table if required (and update remaining points)
        let has_quad = (remaining_points >= 4) && (num_points >= 4);
        if has_quad {
            remaining_points -= 4;
        }

        // Allocate one triple table if required (and update remaining points)
        let has_triple = (remaining_points >= 3) && (num_points >= 3);
        if has_triple {
            remaining_points -= 3;
        }

        // Allocate one twin table if required (and update remaining points)
        let has_twin = (remaining_points >= 2) && (num_points >= 2);
        if has_twin {
            remaining_points -= 2;
        }

        // If there is anything remaining, allocate a singleton
        let has_singleton = (remaining_points != 0) && (num_points >= 1);

        // Sanity check
        assert_eq!(
            num_points,
            num_sixes * 6
                + num_fives * 5
                + if has_quad { 4 } else { 0 }
                + if has_triple { 3 } else { 0 }
                + if has_twin { 2 } else { 0 }
                + if has_singleton { 1 } else { 0 },
            "point allocation mismatch"
        );

        let mut offset = 0;
        let mut six_tables = Vec::new();
        for i in 0..num_sixes {
            let mut table_points = [
                points[offset + (6 * i)].clone(),
                points[offset + (6 * i) + 1].clone(),
                points[offset + (6 * i) + 2].clone(),
                points[offset + (6 * i) + 3].clone(),
                points[offset + (6 * i) + 4].clone(),
                points[offset + (6 * i) + 5].clone(),
            ];
            six_tables.push(LookupTablePlookup::<64, F, T>::new(
                &mut table_points,
                builder,
                driver,
            )?);
        }
        offset += 6 * num_sixes;

        let mut five_tables = Vec::new();
        for i in 0..num_fives {
            let mut table_points = [
                points[offset + (5 * i)].clone(),
                points[offset + (5 * i) + 1].clone(),
                points[offset + (5 * i) + 2].clone(),
                points[offset + (5 * i) + 3].clone(),
                points[offset + (5 * i) + 4].clone(),
            ];
            five_tables.push(LookupTablePlookup::<32, F, T>::new(
                &mut table_points,
                builder,
                driver,
            )?);
        }
        offset += 5 * num_fives;

        let mut quad_tables = Vec::new();
        if has_quad {
            let mut table_points = [
                points[offset].clone(),
                points[offset + 1].clone(),
                points[offset + 2].clone(),
                points[offset + 3].clone(),
            ];
            quad_tables.push(LookupTablePlookup::<16, F, T>::new(
                &mut table_points,
                builder,
                driver,
            )?);
            offset += 4;
        }

        let mut triple_tables = Vec::new();
        if has_triple {
            let mut table_points = [
                points[offset].clone(),
                points[offset + 1].clone(),
                points[offset + 2].clone(),
            ];
            triple_tables.push(LookupTablePlookup::<8, F, T>::new(
                &mut table_points,
                builder,
                driver,
            )?);
            offset += 3;
        }

        let mut twin_tables = Vec::new();
        if has_twin {
            let mut table_points = [points[offset].clone(), points[offset + 1].clone()];
            twin_tables.push(LookupTablePlookup::<4, F, T>::new(
                &mut table_points,
                builder,
                driver,
            )?);
            offset += 2;
        }

        let mut singletons = Vec::new();
        if has_singleton {
            singletons.push(points[points.len() - 1].clone());
        }

        Ok(BatchLookupTablePlookup {
            num_points,
            num_sixes,
            num_fives,
            has_quad,
            has_triple,
            has_twin,
            has_singleton,
            six_tables,
            five_tables,
            quad_tables,
            triple_tables,
            twin_tables,
            singletons,
        })
    }

    pub(crate) fn get_initial_entry<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> BigGroup<F, T> {
        let mut add_accumulator = Vec::new();
        for six_table in &self.six_tables {
            add_accumulator.push(six_table.element_table[0].clone());
        }
        for five_table in &self.five_tables {
            add_accumulator.push(five_table.element_table[0].clone());
        }
        if self.has_quad {
            add_accumulator.push(self.quad_tables[0].element_table[0].clone());
        }
        if self.has_triple {
            add_accumulator.push(self.triple_tables[0].element_table[0].clone());
        }
        if self.has_twin {
            add_accumulator.push(self.twin_tables[0].element_table[0].clone());
        }
        if self.has_singleton {
            add_accumulator.push(self.singletons[0].clone());
        }

        add_accumulator
            .into_iter()
            .reduce(|mut acc, mut item| {
                acc.add(&mut item, builder, driver)
                    .expect("Addition of elements in batch lookup table failed")
            })
            .expect("At least one element should be present in batch lookup table")
    }

    pub(crate) fn get_chain_initial_entry<P: CurveGroup<ScalarField = F, BaseField: PrimeField>>(
        &self,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        {
            let mut add_accumulator = Vec::new();
            for six_table in &self.six_tables {
                add_accumulator.push(six_table.element_table[0].clone());
            }
            for five_table in &self.five_tables {
                add_accumulator.push(five_table.element_table[0].clone());
            }
            for quad_table in &self.quad_tables {
                add_accumulator.push(quad_table.element_table[0].clone());
            }
            if self.has_twin {
                add_accumulator.push(self.twin_tables[0].element_table[0].clone());
            }
            if self.has_triple {
                add_accumulator.push(self.triple_tables[0].element_table[0].clone());
            }
            if self.has_singleton {
                add_accumulator.push(self.singletons[0].clone());
            }

            if add_accumulator.len() >= 2 {
                let mut output = BigGroup::chain_add_start(
                    &mut add_accumulator[0].clone(),
                    &mut add_accumulator[1].clone(),
                    builder,
                    driver,
                )?;
                for acc in add_accumulator.iter_mut().skip(2) {
                    output = BigGroup::chain_add(acc, &mut output, builder, driver)?;
                }
                return Ok(output);
            }
            Ok(ChainAddAccumulator {
                x3_prev: add_accumulator[0].x.clone(),
                y3_prev: add_accumulator[0].y.clone(),
                is_element: true,
                x1_prev: Default::default(),
                y1_prev: Default::default(),
                lambda_prev: Default::default(),
            })
        }
    }

    pub(crate) fn get_chain_add_accumulator<
        P: CurveGroup<ScalarField = F, BaseField: PrimeField>,
    >(
        &mut self,
        naf_entries: &Vec<BoolCT<F, T>>,
        builder: &mut GenericUltraCircuitBuilder<P, T>,
        driver: &mut T,
    ) -> eyre::Result<ChainAddAccumulator<F>> {
        let mut round_accumulator = Vec::new();
        for i in 0..self.num_sixes {
            round_accumulator.push(self.six_tables[i].get(
                &[
                    naf_entries[6 * i].clone(),
                    naf_entries[6 * i + 1].clone(),
                    naf_entries[6 * i + 2].clone(),
                    naf_entries[6 * i + 3].clone(),
                    naf_entries[6 * i + 4].clone(),
                    naf_entries[6 * i + 5].clone(),
                ],
                builder,
                driver,
            )?);
        }
        let mut offset = 6 * self.num_sixes;
        for i in 0..self.num_fives {
            round_accumulator.push(self.five_tables[i].get(
                &[
                    naf_entries[5 * i].clone(),
                    naf_entries[5 * i + 1].clone(),
                    naf_entries[5 * i + 2].clone(),
                    naf_entries[5 * i + 3].clone(),
                    naf_entries[5 * i + 4].clone(),
                ],
                builder,
                driver,
            )?);
        }
        offset += 5 * self.num_fives;
        if self.has_quad {
            round_accumulator.push(self.quad_tables[0].get(
                &[
                    naf_entries[offset].clone(),
                    naf_entries[offset + 1].clone(),
                    naf_entries[offset + 2].clone(),
                    naf_entries[offset + 3].clone(),
                ],
                builder,
                driver,
            )?);
        }
        if self.has_triple {
            round_accumulator.push(self.triple_tables[0].get(
                &[
                    naf_entries[offset].clone(),
                    naf_entries[offset + 1].clone(),
                    naf_entries[offset + 2].clone(),
                ],
                builder,
                driver,
            )?);
        }
        if self.has_twin {
            round_accumulator.push(self.twin_tables[0].get(
                &[naf_entries[offset].clone(), naf_entries[offset + 1].clone()],
                builder,
                driver,
            )?);
        }
        if self.has_singleton {
            round_accumulator.push(self.singletons[0].conditional_negate(
                &naf_entries[self.num_points - 1],
                builder,
                driver,
            )?);
        }

        if round_accumulator.len() == 1 {
            return Ok(ChainAddAccumulator {
                x3_prev: round_accumulator[0].x.clone(),
                y3_prev: round_accumulator[0].y.clone(),
                is_element: true,
                x1_prev: Default::default(),
                y1_prev: Default::default(),
                lambda_prev: Default::default(),
            });
        } else if round_accumulator.len() == 2 {
            return BigGroup::chain_add_start(
                &mut round_accumulator[0].clone(),
                &mut round_accumulator[1].clone(),
                builder,
                driver,
            );
        }
        let mut output = BigGroup::chain_add_start(
            &mut round_accumulator[0].clone(),
            &mut round_accumulator[1].clone(),
            builder,
            driver,
        )?;

        for acc in round_accumulator.iter_mut().skip(2) {
            output = BigGroup::chain_add(acc, &mut output, builder, driver)?;
        }
        Ok(output)
    }
}
