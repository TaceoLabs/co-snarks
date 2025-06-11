use crate::prover_flavour::{Flavour, ProverFlavour};
use ark_ff::PrimeField;
use std::marker::PhantomData;

#[derive(Default, Clone)]
pub struct UltraFlavour<F: PrimeField> {
    phantom_data: PhantomData<F>,
}
impl<F: PrimeField> ProverFlavour for UltraFlavour<F> {
    const FLAVOUR: Flavour = Flavour::Ultra;
    const WITNESS_ENTITIES_SIZE: usize = 8;
    const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;
    const PRECOMPUTED_ENTITIES_SIZE: usize = 27;
    const NUM_ALL_ENTITIES: usize = Self::WITNESS_ENTITIES_SIZE
        + Self::PRECOMPUTED_ENTITIES_SIZE
        + Self::SHIFTED_WITNESS_ENTITIES_SIZE;
    const PROVER_WITNESS_ENTITIES_SIZE: usize = Self::WITNESS_ENTITIES_SIZE - 2;

    const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize = Self::MAX_PARTIAL_RELATION_LENGTH + 1;
    const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = Self::BATCHED_RELATION_PARTIAL_LENGTH + 1;

    //Precomputed Entities:
    /// column 0
    const Q_M: usize = 0;
    /// column 1
    const Q_C: usize = 1;
    /// column 2
    const Q_L: usize = 2;
    /// column 3
    const Q_R: usize = 3;
    /// column 4
    const Q_O: usize = 4;
    /// column 5
    const Q_4: usize = 5;
    const Q_BUSREAD: Option<usize> = None; //Not used in Ultra
    /// column 6
    const Q_LOOKUP: usize = 6;
    /// column 7
    const Q_ARITH: usize = 7;
    /// column 8
    const Q_DELTA_RANGE: usize = 8;
    /// column 9
    const Q_ELLIPTIC: usize = 9;
    /// column 10
    const Q_AUX: usize = 10;
    /// column 11
    const Q_POSEIDON2_EXTERNAL: usize = 11;
    /// column 12
    const Q_POSEIDON2_INTERNAL: usize = 12;
    /// column 13
    const SIGMA_1: usize = 13;
    /// column 14
    const SIGMA_2: usize = 14;
    /// column 15
    const SIGMA_3: usize = 15;
    /// column 16
    const SIGMA_4: usize = 16;
    /// column 17
    const ID_1: usize = 17;
    /// column 18
    const ID_2: usize = 18;
    /// column 19
    const ID_3: usize = 19;
    /// column 20
    const ID_4: usize = 20;
    /// column 21
    const TABLE_1: usize = 21;
    /// column 22
    const TABLE_2: usize = 22;
    /// column 23
    const TABLE_3: usize = 23;
    /// column 24
    const TABLE_4: usize = 24;
    /// column 25
    const LAGRANGE_FIRST: usize = 25;
    /// column 26
    const LAGRANGE_LAST: usize = 26;
    const LAGRANGE_ECC_OP: Option<usize> = None; //Not used in Ultra
    const DATABUS_ID: Option<usize> = None; //Not used in Ultra

    // Witness entities:
    /// column 0
    const W_L: usize = 0;
    /// column 1
    const W_R: usize = 1;
    /// column 2
    const W_O: usize = 2;
    /// column 3 (computed by prover)
    const W_4: usize = 3;
    /// column 4 (computed by prover)
    // const Z_PERM: usize = 4;
    // /// column 5 (computed by prover);
    // const LOOKUP_INVERSES: usize = 5;
    /// column 6
    const LOOKUP_READ_COUNTS: usize = 4;
    /// column 7
    const LOOKUP_READ_TAGS: usize = 5;
    const ECC_OP_WIRE_1: Option<usize> = None;
    const ECC_OP_WIRE_2: Option<usize> = None;
    const ECC_OP_WIRE_3: Option<usize> = None;
    const ECC_OP_WIRE_4: Option<usize> = None;
    const CALLDATA: Option<usize> = None;
    const CALLDATA_READ_COUNTS: Option<usize> = None;
    const CALLDATA_READ_TAGS: Option<usize> = None;
    const CALLDATA_INVERSES: Option<usize> = None;
    const SECONDARY_CALLDATA: Option<usize> = None;
    const SECONDARY_CALLDATA_READ_COUNTS: Option<usize> = None;
    const SECONDARY_CALLDATA_READ_TAGS: Option<usize> = None;
    const SECONDARY_CALLDATA_INVERSES: Option<usize> = None;
    const RETURN_DATA: Option<usize> = None;
    const RETURN_DATA_READ_COUNTS: Option<usize> = None;
    const RETURN_DATA_READ_TAGS: Option<usize> = None;
    const RETURN_DATA_INVERSES: Option<usize> = None;
}
