use ark_ff::PrimeField;

#[derive(Clone, Debug)]
pub struct Poseidon2Params<F: PrimeField, const T: usize, const D: u64> {
    pub(crate) rounds_f_beginning: usize,
    pub(crate) rounds_f_end: usize,
    pub(crate) rounds_p: usize,
    pub mat_internal_diag_m_1: [F; T], // The diagonal of the internal matrix, each element taken minus 1 for more efficient implementations
    pub(crate) round_constants_external: Vec<[F; T]>,
    pub(crate) round_constants_internal: Vec<F>,
}

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2Params<F, T, D> {
    pub(crate) fn new(
        rounds_f: usize,
        rounds_p: usize,
        mat_internal_diag_m_1: [F; T],
        round_constants_external: Vec<[F; T]>,
        round_constants_internal: Vec<F>,
    ) -> Self {
        assert!(T == 2 || T == 3 || ((T <= 24) && (T % 4 == 0)));
        assert!(D % 2 == 1);
        assert_eq!(rounds_f % 2, 0);
        assert_eq!(round_constants_external.len(), rounds_f);
        assert_eq!(round_constants_internal.len(), rounds_p);
        let rounds_f_beginning = rounds_f / 2;
        let rounds_f_end = rounds_f / 2;

        Self {
            rounds_f_beginning,
            rounds_f_end,
            rounds_p,
            mat_internal_diag_m_1,
            round_constants_external,
            round_constants_internal,
        }
    }
}
