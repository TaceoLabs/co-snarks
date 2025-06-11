// This is just a temporary file and will be removed
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use co_builder::flavours::mega_flavour::MegaFlavour;
use co_builder::flavours::ultra_flavour::UltraFlavour;
use co_builder::prelude::ActiveRegionData;
use co_builder::prelude::CrsParser;
use co_builder::prelude::HonkRecursion;
use co_builder::prelude::Polynomial;
use co_builder::prelude::Polynomials;
use co_builder::prelude::PrecomputedEntities;
use co_builder::prelude::ProverWitnessEntities;
use co_builder::prelude::Serialize as FieldSerialize;
use co_builder::prelude::ZeroKnowledge;
use serde::Deserialize;
use serde::Serialize;
use sha3::Keccak256;
use ultrahonk::prelude::ProvingKey;
use ultrahonk::{
    prelude::{
        HonkProof, PlainAcvmSolver, Poseidon2Sponge, TranscriptFieldType, TranscriptHasher,
        UltraCircuitBuilder, UltraHonk,
    },
    Utils,
};

fn parse_proving_key_from_json(json_str: &str) -> Result<VeryUglyPk, serde_json::Error> {
    serde_json::from_str(json_str)
}

fn plain_test<H: TranscriptHasher<TranscriptFieldType>>(has_zk: ZeroKnowledge) {
    const CRS_PATH_G1: &str = "../co-builder/src/crs/bn254_g1.dat";
    const CRS_PATH_G2: &str = "../co-builder/src/crs/bn254_g2.dat";

    let path = "src/finalpk.json";
    let json_str = std::fs::read_to_string(path).expect("failed to read file");
    let proving_key: VeryUglyPk =
        parse_proving_key_from_json(&json_str).expect("failed to parse proving key from JSON");
    let real_pk: RealMegaProvingKey<ark_bn254::Fr> = RealMegaProvingKey::from_ugly(proving_key);

    let crs_size = real_pk.dyadic_circuit_size;
    let crs: co_builder::prelude::Crs<Bn254> =
        CrsParser::get_crs(CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk).unwrap();
    let (prover_crs, _verifier_crs) = crs.split();
    let mut pk = ProvingKey::<_, MegaFlavour<_>>::new(
        real_pk.circuit_size,
        real_pk.num_public_inputs,
        prover_crs.into(),
        real_pk.final_active_wire_idx,
    );
    pk.public_inputs = real_pk.public_inputs;
    pk.pub_inputs_offset = real_pk.pub_inputs_offset as u32;

    pk.active_region_data = ActiveRegionData {
        ranges: real_pk.ranges,
        idxs: real_pk.idxs,
        current_end: real_pk.current_end,
    };
    let mut precomp_polys: Vec<Polynomial<ark_bn254::Fr>> = Vec::new();
    for poly in real_pk.precomputed_polynomials {
        let new_poly: Polynomial<ark_bn254::Fr> = Polynomial { coefficients: poly };
        precomp_polys.push(new_poly);
    }
    let mut witness_polys: Vec<Polynomial<ark_bn254::Fr>> = Vec::new();
    for poly in real_pk.witness_polynomials[..4].to_vec() {
        // println!("Poly: {:?}", poly.len());
        let new_poly: Polynomial<ark_bn254::Fr> = Polynomial { coefficients: poly };
        witness_polys.push(new_poly);
    }
    for poly in real_pk.witness_polynomials[6..].to_vec() {
        let new_poly: Polynomial<ark_bn254::Fr> = Polynomial { coefficients: poly };
        // println!("Poly: {:?}", new_poly.len());
        witness_polys.push(new_poly);
    }
    // println!("Precomputed Polynomials: {}", precomp_polys.len());
    // println!("Witness Polynomials: {}", witness_polys.len());
    let precompentities = PrecomputedEntities::<
        Polynomial<ark_bn254::Fr>,
        ark_bn254::Fr,
        MegaFlavour<ark_bn254::Fr>,
    > {
        elements: precomp_polys.try_into().unwrap(),
        phantom_data: std::marker::PhantomData::<(ark_bn254::Fr, MegaFlavour<ark_bn254::Fr>)>,
    };

    let witness_entities = ProverWitnessEntities::<
        Polynomial<ark_bn254::Fr>,
        ark_bn254::Fr,
        MegaFlavour<ark_bn254::Fr>,
    > {
        elements: witness_polys.try_into().unwrap(),
        phantom_data: std::marker::PhantomData::<(ark_bn254::Fr, MegaFlavour<ark_bn254::Fr>)>,
    };
    let polys_together = Polynomials {
        witness: witness_entities,
        precomputed: precompentities,
    };
    pk.polynomials = polys_together;

    let (proof, public_inputs) = UltraHonk::<_, H, MegaFlavour<_>>::prove(pk, has_zk).unwrap();

    println!("Public Inputs: {:?}", public_inputs.len());
    println!("Proof: {:?}", proof.inner().len());
    // assert_eq!(public_inputs.len(), proof.inner().len());
    // let is_valid =
    //     UltraHonk::<_, H, UltraFlavour<_>>::verify(proof, &public_inputs, &verifying_key, has_zk)
    //         .unwrap();
    // assert!(is_valid);
}

#[test]
fn mega_tester_keccak256() {
    plain_test::<Keccak256>(ZeroKnowledge::No);
}

#[test]
fn mega_tester_poseidon() {
    plain_test::<Poseidon2Sponge>(ZeroKnowledge::No);
    // plain_test::<Poseidon2Sponge>(ZeroKnowledge::Yes);
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
struct RelationParameters<F: PrimeField> {
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub eta: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub eta_two: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub eta_three: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub beta: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub gamma: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub public_input_delta: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub lookup_grand_product_delta: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub beta_sqr: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub beta_cube: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub eccvm_set_permutation_delta: F,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub accumulated_result: [F; 4],
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub evaluation_input_x: [F; 5],
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub batching_challenge_v: [[F; 5]; 4],
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
struct RealMegaProvingKey<F: PrimeField> {
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub alpha: Vec<F>, // I think we dont need these as these are generated from the transcript during oink
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub relation_parameters: Vec<F>,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub target_sum: F,
    pub final_active_wire_idx: usize,
    pub dyadic_circuit_size: usize,
    pub overflow_size: usize,
    pub circuit_size: usize,
    pub log_circuit_size: usize,
    pub num_public_inputs: usize,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub precomputed_polynomials: Vec<Vec<F>>,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub witness_polynomials: Vec<Vec<F>>,
    // these two are the databus propagation data
    pub app_return_data_commitment_pub_input_key: usize,
    pub kernel_return_data_commitment_pub_input_key: usize,
    pub current_end: usize,
    pub pairing_inputs_public_input_key: usize,
    // these three are the active region data
    pub pub_inputs_offset: usize,
    pub ranges: Vec<(usize, usize)>,
    pub idxs: Vec<usize>,
    #[serde(
        serialize_with = "mpc_core::ark_se",
        deserialize_with = "mpc_core::ark_de"
    )]
    pub public_inputs: Vec<F>,
}

impl<F: PrimeField> RealMegaProvingKey<F>
where
    <F as std::str::FromStr>::Err: std::fmt::Debug,
{
    #[allow(dead_code)]
    pub fn from_ugly(pk: VeryUglyPk) -> Self {
        let alpha: Vec<_> = pk.Alpha.iter().map(|s| F::from_str(s).unwrap()).collect();
        let eta = F::from_str(&pk.Relationparameter1).unwrap();
        let eta_two = F::from_str(&pk.Relationparameter2).unwrap();
        let eta_three = F::from_str(&pk.Relationparameter3).unwrap();
        let beta = F::from_str(&pk.Relationparameter4).unwrap();
        let gamma = F::from_str(&pk.Relationparameter5).unwrap();
        let public_input_delta = F::from_str(&pk.Relationparameter6).unwrap();
        let lookup_grand_product_delta = F::from_str(&pk.Relationparameter7).unwrap();
        let beta_sqr = F::from_str(&pk.Relationparameterbeta_sqr).unwrap();
        let beta_cube = F::from_str(&pk.Relationparameterbeta_cube).unwrap();
        let eccvm_set_permutation_delta =
            F::from_str(&pk.Relationparametereccvm_set_permutation_delta).unwrap();
        let accumulated_result: [F; 4] = [
            F::from_str(&pk.Relationparameteraccumulated_result1).unwrap(),
            F::from_str(&pk.Relationparameteraccumulated_result2).unwrap(),
            F::from_str(&pk.Relationparameteraccumulated_result3).unwrap(),
            F::from_str(&pk.Relationparameteraccumulated_result4).unwrap(),
        ];
        let evaluation_input_x: [F; 5] = [
            F::from_str(&pk.Relationparameterevaluation_input_x1).unwrap(),
            F::from_str(&pk.Relationparameterevaluation_input_x2).unwrap(),
            F::from_str(&pk.Relationparameterevaluation_input_x3).unwrap(),
            F::from_str(&pk.Relationparameterevaluation_input_x4).unwrap(),
            F::from_str(&pk.Relationparameterevaluation_input_x5).unwrap(),
        ];
        let batching_challenge_v: [[F; 5]; 4] = [
            [
                F::from_str(&pk.Relationparameterbatching_challenge_v1[0]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v1[1]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v1[2]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v1[3]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v1[4]).unwrap(),
            ],
            [
                F::from_str(&pk.Relationparameterbatching_challenge_v2[0]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v2[1]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v2[2]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v2[3]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v2[4]).unwrap(),
            ],
            [
                F::from_str(&pk.Relationparameterbatching_challenge_v3[0]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v3[1]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v3[2]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v3[3]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v3[4]).unwrap(),
            ],
            [
                F::from_str(&pk.Relationparameterbatching_challenge_v4[0]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v4[1]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v4[2]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v4[3]).unwrap(),
                F::from_str(&pk.Relationparameterbatching_challenge_v4[4]).unwrap(),
            ],
        ];
        let relation_parameters = RelationParameters {
            eta,
            eta_two,
            eta_three,
            beta,
            gamma,
            public_input_delta,
            lookup_grand_product_delta,
            beta_sqr,
            beta_cube,
            eccvm_set_permutation_delta,
            accumulated_result,
            evaluation_input_x,
            batching_challenge_v,
        };
        let target_sum = F::from_str(&pk.target_sum).unwrap();
        let final_active_wire_idx = pk.final_active_wire_idx;
        let dyadic_circuit_size = pk.dyadic_circuit_size;
        let log_circuit_size = (pk.circuit_size as f64).log2() as usize;
        let overflow_size = pk.overflow_size;
        let circuit_size = pk.circuit_size;
        let num_public_inputs = pk.num_public_inputs;
        let app_return_data_commitment_pub_input_key = pk.app_return_data_commitment_pub_input_key;
        let kernel_return_data_commitment_pub_input_key =
            pk.kernel_return_data_commitment_pub_input_key;
        let current_end = pk.current_end;
        let pairing_inputs_public_input_key = pk.pairing_inputs_public_input_key;
        let pub_inputs_offset = pk.pub_inputs_offset;
        let ranges = pk.ranges;
        let public_inputs: Vec<F> = pk
            .public_inputs
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let idxs: Vec<usize> = (1..=98868).collect();
        let pre_poly_0 = pk
            .Precomputedpolynomial_0
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_1 = pk
            .Precomputedpolynomial_1
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_2 = pk
            .Precomputedpolynomial_2
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_3 = pk
            .Precomputedpolynomial_3
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_4 = pk
            .Precomputedpolynomial_4
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_5 = pk
            .Precomputedpolynomial_5
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_6 = pk
            .Precomputedpolynomial_6
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_7 = pk
            .Precomputedpolynomial_7
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_8 = pk
            .Precomputedpolynomial_8
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_9 = pk
            .Precomputedpolynomial_9
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_10 = pk
            .Precomputedpolynomial_10
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_11 = pk
            .Precomputedpolynomial_11
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_12 = pk
            .Precomputedpolynomial_12
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_13 = pk
            .Precomputedpolynomial_13
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_14 = pk
            .Precomputedpolynomial_14
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_15 = pk
            .Precomputedpolynomial_15
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_16 = pk
            .Precomputedpolynomial_16
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_17 = pk
            .Precomputedpolynomial_17
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_18 = pk
            .Precomputedpolynomial_18
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_19 = pk
            .Precomputedpolynomial_19
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_20 = pk
            .Precomputedpolynomial_20
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_21 = pk
            .Precomputedpolynomial_21
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_22 = pk
            .Precomputedpolynomial_22
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_23 = pk
            .Precomputedpolynomial_23
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_24 = pk
            .Precomputedpolynomial_24
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_25 = pk
            .Precomputedpolynomial_25
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_26 = pk
            .Precomputedpolynomial_26
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_27 = pk
            .Precomputedpolynomial_27
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_28 = pk
            .Precomputedpolynomial_28
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let pre_poly_29 = pk
            .Precomputedpolynomial_29
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let precomputed_polynomials = vec![
            pre_poly_0,
            pre_poly_1,
            pre_poly_2,
            pre_poly_3,
            pre_poly_4,
            pre_poly_5,
            pre_poly_6,
            pre_poly_7,
            pre_poly_8,
            pre_poly_9,
            pre_poly_10,
            pre_poly_11,
            pre_poly_12,
            pre_poly_13,
            pre_poly_14,
            pre_poly_15,
            pre_poly_16,
            pre_poly_17,
            pre_poly_18,
            pre_poly_19,
            pre_poly_20,
            pre_poly_21,
            pre_poly_22,
            pre_poly_23,
            pre_poly_24,
            pre_poly_25,
            pre_poly_26,
            pre_poly_27,
            pre_poly_28,
            pre_poly_29,
        ];
        let witness_poly_0 = pk
            .Witnesspolynomial_0
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_1 = pk
            .Witnesspolynomial_1
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_2 = pk
            .Witnesspolynomial_2
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_3 = pk
            .Witnesspolynomial_3
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_4 = pk
            .Witnesspolynomial_4
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_5 = pk
            .Witnesspolynomial_5
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_6 = pk
            .Witnesspolynomial_6
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_7 = pk
            .Witnesspolynomial_7
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_8 = pk
            .Witnesspolynomial_8
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_9 = pk
            .Witnesspolynomial_9
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_10 = pk
            .Witnesspolynomial_10
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_11 = pk
            .Witnesspolynomial_11
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_12 = pk
            .Witnesspolynomial_12
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_13 = pk
            .Witnesspolynomial_13
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_14 = pk
            .Witnesspolynomial_14
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_15 = pk
            .Witnesspolynomial_15
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_16 = pk
            .Witnesspolynomial_16
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_17 = pk
            .Witnesspolynomial_17
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_18 = pk
            .Witnesspolynomial_18
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_19 = pk
            .Witnesspolynomial_19
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_20 = pk
            .Witnesspolynomial_20
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_21 = pk
            .Witnesspolynomial_21
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_22 = pk
            .Witnesspolynomial_22
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_poly_23 = pk
            .Witnesspolynomial_23
            .iter()
            .map(|s| F::from_str(s).unwrap())
            .collect();
        let witness_polynomials = vec![
            witness_poly_0,
            witness_poly_1,
            witness_poly_2,
            witness_poly_3,
            witness_poly_4,
            witness_poly_5,
            witness_poly_6,
            witness_poly_7,
            witness_poly_8,
            witness_poly_9,
            witness_poly_10,
            witness_poly_11,
            witness_poly_12,
            witness_poly_13,
            witness_poly_14,
            witness_poly_15,
            witness_poly_16,
            witness_poly_17,
            witness_poly_18,
            witness_poly_19,
            witness_poly_20,
            witness_poly_21,
            witness_poly_22,
            witness_poly_23,
        ];
        RealMegaProvingKey {
            alpha,
            relation_parameters: vec![
                relation_parameters.eta,
                relation_parameters.eta_two,
                relation_parameters.eta_three,
                relation_parameters.beta,
                relation_parameters.gamma,
                relation_parameters.public_input_delta,
                relation_parameters.lookup_grand_product_delta,
                relation_parameters.beta_sqr,
                relation_parameters.beta_cube,
                relation_parameters.eccvm_set_permutation_delta,
            ],
            target_sum,
            final_active_wire_idx,
            dyadic_circuit_size,
            overflow_size,
            circuit_size,
            log_circuit_size,
            num_public_inputs,
            precomputed_polynomials,
            witness_polynomials,
            app_return_data_commitment_pub_input_key,
            kernel_return_data_commitment_pub_input_key,
            current_end,
            pairing_inputs_public_input_key,
            pub_inputs_offset,
            ranges,
            idxs: idxs.clone(),
            public_inputs,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
#[expect(non_snake_case)]
struct VeryUglyPk {
    Alpha: Vec<String>,

    Relationparameter1: String,

    Relationparameter2: String,

    Relationparameter3: String,

    Relationparameter4: String,

    Relationparameter5: String,

    Relationparameter6: String,

    Relationparameter7: String,

    Relationparameterbeta_sqr: String,

    Relationparameterbeta_cube: String,

    Relationparametereccvm_set_permutation_delta: String,

    Relationparameteraccumulated_result1: String,

    Relationparameteraccumulated_result2: String,

    Relationparameteraccumulated_result3: String,

    Relationparameteraccumulated_result4: String,

    Relationparameterevaluation_input_x1: String,

    Relationparameterevaluation_input_x2: String,

    Relationparameterevaluation_input_x3: String,

    Relationparameterevaluation_input_x4: String,

    Relationparameterevaluation_input_x5: String,

    Relationparameterbatching_challenge_v1: [String; 5],

    Relationparameterbatching_challenge_v2: [String; 5],

    Relationparameterbatching_challenge_v3: [String; 5],

    Relationparameterbatching_challenge_v4: [String; 5],

    target_sum: String,
    final_active_wire_idx: usize,
    dyadic_circuit_size: usize,
    overflow_size: usize,
    circuit_size: usize,
    num_public_inputs: usize,

    Precomputedpolynomial_0: Vec<String>,

    Precomputedpolynomial_1: Vec<String>,

    Precomputedpolynomial_2: Vec<String>,

    Precomputedpolynomial_3: Vec<String>,

    Precomputedpolynomial_4: Vec<String>,

    Precomputedpolynomial_5: Vec<String>,

    Precomputedpolynomial_6: Vec<String>,

    Precomputedpolynomial_7: Vec<String>,

    Precomputedpolynomial_8: Vec<String>,

    Precomputedpolynomial_9: Vec<String>,

    Precomputedpolynomial_10: Vec<String>,

    Precomputedpolynomial_11: Vec<String>,

    Precomputedpolynomial_12: Vec<String>,

    Precomputedpolynomial_13: Vec<String>,

    Precomputedpolynomial_14: Vec<String>,

    Precomputedpolynomial_15: Vec<String>,

    Precomputedpolynomial_16: Vec<String>,

    Precomputedpolynomial_17: Vec<String>,

    Precomputedpolynomial_18: Vec<String>,

    Precomputedpolynomial_19: Vec<String>,

    Precomputedpolynomial_20: Vec<String>,

    Precomputedpolynomial_21: Vec<String>,

    Precomputedpolynomial_22: Vec<String>,

    Precomputedpolynomial_23: Vec<String>,

    Precomputedpolynomial_24: Vec<String>,

    Precomputedpolynomial_25: Vec<String>,

    Precomputedpolynomial_26: Vec<String>,

    Precomputedpolynomial_27: Vec<String>,

    Precomputedpolynomial_28: Vec<String>,

    Precomputedpolynomial_29: Vec<String>,

    Witnesspolynomial_0: Vec<String>,

    Witnesspolynomial_1: Vec<String>,

    Witnesspolynomial_2: Vec<String>,

    Witnesspolynomial_3: Vec<String>,

    Witnesspolynomial_4: Vec<String>,

    Witnesspolynomial_5: Vec<String>,

    Witnesspolynomial_6: Vec<String>,

    Witnesspolynomial_7: Vec<String>,

    Witnesspolynomial_8: Vec<String>,

    Witnesspolynomial_9: Vec<String>,

    Witnesspolynomial_10: Vec<String>,

    Witnesspolynomial_11: Vec<String>,

    Witnesspolynomial_12: Vec<String>,

    Witnesspolynomial_13: Vec<String>,

    Witnesspolynomial_14: Vec<String>,

    Witnesspolynomial_15: Vec<String>,

    Witnesspolynomial_16: Vec<String>,

    Witnesspolynomial_17: Vec<String>,

    Witnesspolynomial_18: Vec<String>,

    Witnesspolynomial_19: Vec<String>,

    Witnesspolynomial_20: Vec<String>,

    Witnesspolynomial_21: Vec<String>,

    Witnesspolynomial_22: Vec<String>,

    Witnesspolynomial_23: Vec<String>,
    app_return_data_commitment_pub_input_key: usize,
    kernel_return_data_commitment_pub_input_key: usize,
    current_end: usize,
    pairing_inputs_public_input_key: usize,
    pub_inputs_offset: usize,

    ranges: Vec<(usize, usize)>,

    public_inputs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::{io::BufWriter, path};

    use super::*;
    fn parse_proving_key_from_json(json_str: &str) -> Result<VeryUglyPk, serde_json::Error> {
        serde_json::from_str(json_str)
    }
    #[test]
    fn testytesty() {
        let path = "src/finalpk.json";
        let json_str = std::fs::read_to_string(path).expect("failed to read file");
        let proving_key: VeryUglyPk =
            parse_proving_key_from_json(&json_str).expect("failed to parse proving key from JSON");
        println!(
            "Proving Key Witnesspolynomial_0: {:?}",
            proving_key.Witnesspolynomial_0
        );
        let real_pk: RealMegaProvingKey<ark_bn254::Fr> = RealMegaProvingKey::from_ugly(proving_key);
        let out = path::PathBuf::from("src/mega_proving_key");
        let out_file = BufWriter::new(std::fs::File::create(&out).unwrap());
        bincode::serialize_into(out_file, &real_pk).unwrap();
    }
}
