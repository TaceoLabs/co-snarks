// proverwitnessentities and precomputed entities, also witnessentities

pub trait PrecomputedEntitiesFlavour {
    type PrecomputedEntity<T: Default>: Default;

    fn new<T: Default>() -> Self::PrecomputedEntity<Vec<T>>;
    fn add<T: Default>(
        lhs: &mut Self::PrecomputedEntity<Vec<T>>,
        entity: Self::PrecomputedEntity<T>,
    );
    fn get_table_polynomials<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &[T];
    fn get_selectors_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T];
    fn get_sigmas_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T];
    fn get_ids_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T];
    fn get_table_polynomials_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut [T];
    fn q_m<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_c<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_l<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_r<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_o<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_busread<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_arith<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_delta_range<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_elliptic<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_aux<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_lookup<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_poseidon2_external<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn q_poseidon2_internal<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn sigma_1<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn sigma_2<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn sigma_3<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn sigma_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn id_1<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn id_2<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn id_3<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn id_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn table_1<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn table_2<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn table_3<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn table_4<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn lagrange_first<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn lagrange_last<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn lagrange_ecc_op<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn databus_id<T: Default>(poly: &Self::PrecomputedEntity<T>) -> &T;
    fn lagrange_first_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn lagrange_last_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn lagrange_ecc_op_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn databus_id_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_m_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_c_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_l_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_r_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_o_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_arith_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_delta_range_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_elliptic_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_aux_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_lookup_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_poseidon2_external_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn q_poseidon2_internal_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn table_1_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn table_2_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn table_3_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn table_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn sigma_1_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn sigma_2_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn sigma_3_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn sigma_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn id_1_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn id_2_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn id_3_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
    fn id_4_mut<T: Default>(poly: &mut Self::PrecomputedEntity<T>) -> &mut T;
}
pub trait WitnessEntitiesFlavour {
    type WitnessEntity<T: Default>: Default;

    fn new<T: Default>() -> Self::WitnessEntity<Vec<T>>;
    fn add<T: Default>(lhs: &mut Self::WitnessEntity<Vec<T>>, entity: Self::WitnessEntity<T>);
    fn to_be_shifted<T: Default>(poly: &Self::WitnessEntity<T>) -> &[T];
    fn to_be_shifted_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut [T];
    fn w_l<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn w_l_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn w_r<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn w_r_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn w_o<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn w_o_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn w_4<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn z_perm<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn w_4_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn z_perm_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn lookup_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn lookup_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn lookup_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn lookup_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn lookup_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn lookup_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn calldata<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn calldata_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn secondary_calldata<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn secondary_calldata_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn return_data<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn return_data_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_1<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn ecc_op_wire_1_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_2<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn ecc_op_wire_2_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_3<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn ecc_op_wire_3_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_4<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn ecc_op_wire_4_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn calldata_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn calldata_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn calldata_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn calldata_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn calldata_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn calldata_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn secondary_calldata_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn secondary_calldata_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn secondary_calldata_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn secondary_calldata_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn secondary_calldata_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn secondary_calldata_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn return_data_read_counts<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn return_data_read_counts_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn return_data_read_tags<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn return_data_read_tags_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
    fn return_data_inverses<T: Default>(poly: &Self::WitnessEntity<T>) -> &T;
    fn return_data_inverses_mut<T: Default>(poly: &mut Self::WitnessEntity<T>) -> &mut T;
}
pub trait ShiftedWitnessEntitiesFlavour {
    type ShiftedWitnessEntity<T: Default>: Default;
    fn new<T: Default>() -> Self::ShiftedWitnessEntity<Vec<T>>;
    fn add<T: Default>(
        lhs: &mut Self::ShiftedWitnessEntity<Vec<T>>,
        entity: Self::ShiftedWitnessEntity<T>,
    );
    // fn iter(&self) -> impl Iterator<Item = &T>;

    // fn iter_mut(&mut self) -> impl Iterator<Item = &mut T>;
    fn w_l<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T;
    fn w_r<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T;
    fn w_o<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T;
    fn w_4<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T;
    fn z_perm<T: Default>(poly: &Self::ShiftedWitnessEntity<T>) -> &T;
    fn w_l_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T;
    fn w_r_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T;
    fn w_o_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T;
    fn w_4_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T;
    fn z_perm_mut<T: Default>(poly: &mut Self::ShiftedWitnessEntity<T>) -> &mut T;
}
pub trait ProverWitnessEntitiesFlavour {
    type ProverWitnessEntity<T: Default>: Default;
    fn new<T: Default>() -> Self::ProverWitnessEntity<Vec<T>>;
    fn add<T: Default>(
        lhs: &mut Self::ProverWitnessEntity<Vec<T>>,
        entity: Self::ProverWitnessEntity<T>,
    );

    // fn iter<T:Default>(&self) -> impl Iterator<Item = &T>;
    //     fn iter_mut<T:Default>(&mut self) -> impl Iterator<Item = &mut T>;
    fn into_wires<T: Default>(poly: Self::ProverWitnessEntity<T>) -> impl Iterator<Item = T>;
    fn get_wires<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &[T];
    fn get_wires_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut [T];
    fn w_l<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn w_l_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn w_r<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn w_r_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn w_o<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn w_o_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn w_4<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn lookup_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn lookup_read_counts_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn lookup_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn lookup_read_tags_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn lookup_read_counts_and_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &[T];
    fn lookup_read_counts_and_tags_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut [T];
    fn calldata<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn calldata_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn secondary_calldata<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn secondary_calldata_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn return_data<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn return_data_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_1<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn ecc_op_wire_1_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_2<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn ecc_op_wire_2_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_3<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn ecc_op_wire_3_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn ecc_op_wire_4<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn ecc_op_wire_4_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn calldata_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn calldata_read_counts_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn calldata_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn calldata_read_tags_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn calldata_inverses<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn calldata_inverses_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn secondary_calldata_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn secondary_calldata_read_counts_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut T;
    fn secondary_calldata_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn secondary_calldata_read_tags_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut T;
    fn secondary_calldata_inverses<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn secondary_calldata_inverses_mut<T: Default>(
        poly: &mut Self::ProverWitnessEntity<T>,
    ) -> &mut T;
    fn return_data_read_counts<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn return_data_read_counts_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn return_data_read_tags<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn return_data_read_tags_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
    fn return_data_inverses<T: Default>(poly: &Self::ProverWitnessEntity<T>) -> &T;
    fn return_data_inverses_mut<T: Default>(poly: &mut Self::ProverWitnessEntity<T>) -> &mut T;
}
