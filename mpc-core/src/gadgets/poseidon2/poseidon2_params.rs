use ark_ff::PrimeField;

/// A parameter set containing the parameters for the Poseidon2 permutation.
#[derive(Clone, Debug)]
pub struct Poseidon2Params<F: PrimeField, const T: usize, const D: u64> {
    /// The amount of external rounds at the beginning of the permutation.
    pub rounds_f_beginning: usize,
    /// The amount of external rounds at the end of the permutation.
    pub rounds_f_end: usize,
    /// The amount of internal rounds.
    pub rounds_p: usize,
    /// The diagonal of t x t matrix of the internal permutation. Each element is taken minus 1 for more efficient implementations.
    pub mat_internal_diag_m_1: &'static [F; T],
    /// The round constants of the external rounds.
    pub round_constants_external: &'static Vec<[F; T]>,
    /// The round constants of the internal rounds.
    pub round_constants_internal: &'static Vec<F>,
}

impl<F: PrimeField, const T: usize, const D: u64> Poseidon2Params<F, T, D> {
    pub(crate) fn new(
        rounds_f: usize,
        rounds_p: usize,
        mat_internal_diag_m_1: &'static [F; T],
        round_constants_external: &'static Vec<[F; T]>,
        round_constants_internal: &'static Vec<F>,
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
