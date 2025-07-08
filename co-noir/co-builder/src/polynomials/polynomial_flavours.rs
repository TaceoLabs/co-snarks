// proverwitnessentities and precomputed entities, also witnessentities

pub trait PrecomputedEntitiesFlavour<T: Default> {
    fn new() -> Self;
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a;
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a;
    fn into_iter(self) -> impl Iterator<Item = T>;
    fn get_table_polynomials(&self) -> &[T] {
        panic!("This should not be called with this Flavour");
    }
    fn get_selectors_mut(&mut self) -> &mut [T] {
        panic!("This should not be called with this Flavour");
    }
    fn get_sigmas_mut(&mut self) -> &mut [T] {
        panic!("This should not be called with this Flavour");
    }
    fn get_ids_mut(&mut self) -> &mut [T] {
        panic!("This should not be called with this Flavour");
    }
    fn get_table_polynomials_mut(&mut self) -> &mut [T] {
        panic!("This should not be called with this Flavour");
    }
    fn q_m(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_c(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_l(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_r(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_o(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_busread(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_arith(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_delta_range(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_elliptic(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_aux(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_lookup(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_poseidon2_external(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn q_poseidon2_internal(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_1(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_2(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_3(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn id_1(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn id_2(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn id_3(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn id_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn table_1(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn table_2(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn table_3(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn table_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lagrange_first(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lagrange_last(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lagrange_ecc_op(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn databus_id(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lagrange_first_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn lagrange_last_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn lagrange_ecc_op_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn databus_id_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_m_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_c_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_l_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_r_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_o_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_busread_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_arith_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_delta_range_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_elliptic_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_aux_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_lookup_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_poseidon2_external_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn q_poseidon2_internal_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn table_1_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn table_2_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn table_3_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn table_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_1_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_2_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_3_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn sigma_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn id_1_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn id_2_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn id_3_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn id_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
}

pub trait WitnessEntitiesFlavour<T: Default> {
    fn new() -> Self;

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a;
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a;
    fn into_iter(self) -> impl Iterator<Item = T>;
    fn to_be_shifted(&self) -> &[T] {
        panic!("This should not be called with this Flavour");
    }
    fn to_be_shifted_mut(&mut self) -> &mut [T] {
        panic!("This should not be called with this Flavour");
    }
    fn w_l(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_l_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_r(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_r_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_o(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_o_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn z_perm(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn z_perm_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_inverses(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_1(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_1_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_2(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_2_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_3(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_3_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_inverses(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_inverses(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_inverses(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
}

pub trait ShiftedWitnessEntitiesFlavour<T: Default> {
    fn new() -> Self;
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a;
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a;
    fn into_iter(self) -> impl Iterator<Item = T>;
    fn w_l(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_r(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_o(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn z_perm(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_l_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_r_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_o_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn z_perm_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
}
pub trait ProverWitnessEntitiesFlavour<T: Default> {
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a;
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a;
    fn into_iter(self) -> impl Iterator<Item = T>;
    fn into_wires(self) -> impl Iterator<Item = T>;
    fn get_wires(&self) -> &[T] {
        panic!("This should not be called with this Flavour");
    }
    fn get_wires_mut(&mut self) -> &mut [T] {
        panic!("This should not be called with this Flavour");
    }
    fn w_l(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_l_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_r(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_r_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_o(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn w_o_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn w_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_counts_and_tags(&self) -> &[T] {
        panic!("This should not be called with this Flavour");
    }
    fn lookup_read_counts_and_tags_mut(&mut self) -> &mut [T] {
        panic!("This should not be called with this Flavour");
    }
    fn calldata(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_1(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_1_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_2(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_2_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_3(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_3_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_4(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn ecc_op_wire_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_inverses(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_inverses(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn secondary_calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_counts(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_tags(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_inverses(&self) -> &T {
        panic!("This should not be called with this Flavour");
    }
    fn return_data_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with this Flavour");
    }
}
