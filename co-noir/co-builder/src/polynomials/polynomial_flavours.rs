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
    fn get_table_polynomials(&self) -> &[T];
    fn get_selectors_mut(&mut self) -> &mut [T];
    fn get_sigmas_mut(&mut self) -> &mut [T];
    fn get_ids_mut(&mut self) -> &mut [T];
    fn get_table_polynomials_mut(&mut self) -> &mut [T];
    fn q_m(&self) -> &T;
    fn q_c(&self) -> &T;
    fn q_l(&self) -> &T;
    fn q_r(&self) -> &T;
    fn q_o(&self) -> &T;
    fn q_4(&self) -> &T;
    fn q_busread(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn q_arith(&self) -> &T;
    fn q_delta_range(&self) -> &T;
    fn q_elliptic(&self) -> &T;
    fn q_aux(&self) -> &T;
    fn q_lookup(&self) -> &T;
    fn q_poseidon2_external(&self) -> &T;
    fn q_poseidon2_internal(&self) -> &T;
    fn sigma_1(&self) -> &T;
    fn sigma_2(&self) -> &T;
    fn sigma_3(&self) -> &T;
    fn sigma_4(&self) -> &T;
    fn id_1(&self) -> &T;
    fn id_2(&self) -> &T;
    fn id_3(&self) -> &T;
    fn id_4(&self) -> &T;
    fn table_1(&self) -> &T;
    fn table_2(&self) -> &T;
    fn table_3(&self) -> &T;
    fn table_4(&self) -> &T;
    fn lagrange_first(&self) -> &T;
    fn lagrange_last(&self) -> &T;
    fn lagrange_ecc_op(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn databus_id(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn lagrange_first_mut(&mut self) -> &mut T;
    fn lagrange_last_mut(&mut self) -> &mut T;
    fn lagrange_ecc_op_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn databus_id_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn q_m_mut(&mut self) -> &mut T;
    fn q_c_mut(&mut self) -> &mut T;
    fn q_l_mut(&mut self) -> &mut T;
    fn q_r_mut(&mut self) -> &mut T;
    fn q_o_mut(&mut self) -> &mut T;
    fn q_4_mut(&mut self) -> &mut T;
    fn q_busread_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn q_arith_mut(&mut self) -> &mut T;
    fn q_delta_range_mut(&mut self) -> &mut T;
    fn q_elliptic_mut(&mut self) -> &mut T;
    fn q_aux_mut(&mut self) -> &mut T;
    fn q_lookup_mut(&mut self) -> &mut T;
    fn q_poseidon2_external_mut(&mut self) -> &mut T;
    fn q_poseidon2_internal_mut(&mut self) -> &mut T;
    fn table_1_mut(&mut self) -> &mut T;
    fn table_2_mut(&mut self) -> &mut T;
    fn table_3_mut(&mut self) -> &mut T;
    fn table_4_mut(&mut self) -> &mut T;
    fn sigma_1_mut(&mut self) -> &mut T;
    fn sigma_2_mut(&mut self) -> &mut T;
    fn sigma_3_mut(&mut self) -> &mut T;
    fn sigma_4_mut(&mut self) -> &mut T;
    fn id_1_mut(&mut self) -> &mut T;
    fn id_2_mut(&mut self) -> &mut T;
    fn id_3_mut(&mut self) -> &mut T;
    fn id_4_mut(&mut self) -> &mut T;
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
    fn to_be_shifted(&self) -> &[T];
    fn to_be_shifted_mut(&mut self) -> &mut [T];
    fn w_l(&self) -> &T;
    fn w_l_mut(&mut self) -> &mut T;
    fn w_r(&self) -> &T;
    fn w_r_mut(&mut self) -> &mut T;
    fn w_o(&self) -> &T;
    fn w_o_mut(&mut self) -> &mut T;
    fn w_4(&self) -> &T;
    fn z_perm(&self) -> &T;
    fn w_4_mut(&mut self) -> &mut T;
    fn z_perm_mut(&mut self) -> &mut T;
    fn lookup_inverses_mut(&mut self) -> &mut T;
    fn lookup_inverses(&self) -> &T;
    fn lookup_read_counts(&self) -> &T;
    fn lookup_read_counts_mut(&mut self) -> &mut T;
    fn lookup_read_tags(&self) -> &T;
    fn lookup_read_tags_mut(&mut self) -> &mut T;
    fn calldata(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_1(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_1_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_2(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_2_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_3(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_3_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_4(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_counts(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_tags(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_inverses(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_counts(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_tags(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_inverses(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_counts(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_tags(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_inverses(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
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
    fn w_l(&self) -> &T;
    fn w_r(&self) -> &T;
    fn w_o(&self) -> &T;
    fn w_4(&self) -> &T;
    fn z_perm(&self) -> &T;
    fn w_l_mut(&mut self) -> &mut T;
    fn w_r_mut(&mut self) -> &mut T;
    fn w_o_mut(&mut self) -> &mut T;
    fn w_4_mut(&mut self) -> &mut T;
    fn z_perm_mut(&mut self) -> &mut T;
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
    fn get_wires(&self) -> &[T];
    fn get_wires_mut(&mut self) -> &mut [T];
    fn w_l(&self) -> &T;
    fn w_l_mut(&mut self) -> &mut T;
    fn w_r(&self) -> &T;
    fn w_r_mut(&mut self) -> &mut T;
    fn w_o(&self) -> &T;
    fn w_o_mut(&mut self) -> &mut T;
    fn w_4(&self) -> &T;
    fn lookup_read_counts(&self) -> &T;
    fn lookup_read_counts_mut(&mut self) -> &mut T;
    fn lookup_read_tags(&self) -> &T;
    fn lookup_read_tags_mut(&mut self) -> &mut T;
    fn lookup_read_counts_and_tags(&self) -> &[T];
    fn lookup_read_counts_and_tags_mut(&mut self) -> &mut [T];
    fn calldata(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_1(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_1_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_2(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_2_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_3(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_3_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_4(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn ecc_op_wire_4_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_counts(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_tags(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_inverses(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_counts(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_tags(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_inverses(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn secondary_calldata_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_counts(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_counts_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_tags(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_read_tags_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_inverses(&self) -> &T {
        panic!("This should not be called with the UltraFlavor");
    }
    fn return_data_inverses_mut(&mut self) -> &mut T {
        panic!("This should not be called with the UltraFlavor");
    }
}
