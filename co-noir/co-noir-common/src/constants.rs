use crate::{
    mpc::{NoirUltraHonkProver, plain::PlainUltraHonkDriver},
    polynomials::entities::{
        PRECOMPUTED_ENTITIES_SIZE, ProverWitnessEntities, WITNESS_ENTITIES_SIZE,
    },
    types::Bn254G1,
};

/// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
/// AZTEC TODO(<https://github.com/AztecProtocol/barretenberg/issues/1046>): Remove the need for const sized proofs
pub const CONST_PROOF_SIZE_LOG_N: usize = 28;
// For ZK Flavors: the number of the commitments required by Libra and SmallSubgroupIPA.
pub const NUM_LIBRA_COMMITMENTS: usize = 3;
pub const NUM_SMALL_IPA_EVALUATIONS: usize = 4;
// Upper bound on the number of claims produced GeminiProver:
// - Each fold polynomial is opened at two points, the number of resulting claims is bounded by 2*CONST_PROOF_SIZE_LOG_N
// - The interleaving trick needed for Translator adds 2 extra claims
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
pub const NUM_GEMINI_CLAIMS: usize = 2 * CONST_PROOF_SIZE_LOG_N + 2;
// The interleaving trick needed for Translator adds 2 extra claims to Gemini fold claims
// TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
pub const NUM_INTERLEAVING_CLAIMS: u32 = 2;

pub const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;

pub const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = MAX_PARTIAL_RELATION_LENGTH + 1;
pub const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = BATCHED_RELATION_PARTIAL_LENGTH + 1;

pub const NUM_ALL_ENTITIES: usize =
    WITNESS_ENTITIES_SIZE + PRECOMPUTED_ENTITIES_SIZE + SHIFTED_WITNESS_ENTITIES_SIZE;

pub const PUBLIC_INPUTS_SIZE: usize = 16;

pub const ULTRA_VERIFICATION_KEY_LENGTH: usize = PRECOMPUTED_ENTITIES_SIZE * 4 + 3;

pub const ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS: usize =
    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS + DECIDER_PROOF_LENGTH;

pub const DECIDER_PROOF_LENGTH: usize = (CONST_PROOF_SIZE_LOG_N * BATCHED_RELATION_PARTIAL_LENGTH ) +
            /* 3. NUM_ALL_ENTITIES sumcheck evaluations */ (NUM_ALL_ENTITIES ) +
            /* 4. virtual_log_n - 1 Gemini Fold commitments */ ((CONST_PROOF_SIZE_LOG_N - 1) * 4) +
            /* 5. virtual_log_n Gemini a evaluations */ (CONST_PROOF_SIZE_LOG_N ) +
            /* 6. Shplonk Q commitment */ (4) +
            /* 7. KZG W commitment */ (4);
pub const OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS: usize = WITNESS_ENTITIES_SIZE * 4;

pub const MOCK_PROOF_DYADIC_SIZE: usize = 1 << 6;

pub const NUM_WIRES: usize = 4;
pub const NUM_SELECTORS: usize = 14;

// Arbitrarily large constant (> size of the BN254 srs) used to ensure that the evaluations on the hypercube of the
// permutation argument polynomials (sigmas, ids) are unique, e.g. id[i][j] == id[m][n] iff (i == m && j == n)
pub const PERMUTATION_ARGUMENT_VALUE_SEPARATOR: u32 = 1 << 28;

pub const PAIRING_POINT_ACCUMULATOR_SIZE: u32 = 16;

pub const PUBLIC_INPUT_WIRE_INDEX: usize = ProverWitnessEntities::<
    <PlainUltraHonkDriver as NoirUltraHonkProver<Bn254G1>>::ArithmeticShare,
>::W_R;
