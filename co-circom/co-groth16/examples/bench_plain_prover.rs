//! Benchmark for the plain (non-MPC) co-groth16 prover, i.e. `CoGroth16::prove_inner`
//! instantiated with the [`PlainGroth16Driver`].
//!
//! The circuit is a chain of `n` squarings over BN254 (`x_{i+1} = x_i * x_i`), so every
//! R1CS row has exactly one non-zero entry in each of A, B and C. `n` is chosen such that
//! `num_constraints + num_instance_variables == 2^k`, which is exactly the FFT domain size
//! used by the prover. The matching gnark benchmark uses the same circuit and the same
//! domain size.
//!
//! Usage: `cargo run --release --example bench_plain_prover -- [k ...]` (default 16 18 20),
//! `REPS=<n>` controls the number of repetitions per size.

use std::hint::black_box;
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16 as ArkGroth16, prepare_verifying_key};
use ark_relations::gr1cs::predicate::polynomial_constraint::R1CS_PREDICATE_LABEL;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
    SynthesisMode,
};
use ark_relations::lc;
use co_circom_types::SharedWitness;
use co_groth16::{
    CircomReduction, ConstraintMatrices, Groth16, LibSnarkReduction, PlainGroth16Driver, R1CSToQAP,
};

/// `num_squarings` constraints of the form `x_{i+1} = x_i * x_i`. The last value is the
/// single public output, the initial value is the single private input.
#[derive(Clone)]
struct SquaringChain {
    num_squarings: usize,
    x: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquaringChain {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut val = self.x;
        let mut var = cs.new_witness_variable(|| val.ok_or(SynthesisError::AssignmentMissing))?;
        for i in 0..self.num_squarings {
            let next_val = val.map(|v| v * v);
            let next_var = if i + 1 == self.num_squarings {
                cs.new_input_variable(|| next_val.ok_or(SynthesisError::AssignmentMissing))?
            } else {
                cs.new_witness_variable(|| next_val.ok_or(SynthesisError::AssignmentMissing))?
            };
            cs.enforce_r1cs_constraint(|| lc!() + var, || lc!() + var, || lc!() + next_var)?;
            val = next_val;
            var = next_var;
        }
        Ok(())
    }
}

fn stats(mut times: Vec<Duration>) -> (Duration, Duration, Duration) {
    times.sort();
    let sum: Duration = times.iter().sum();
    let mean = sum / times.len() as u32;
    (times[0], times[times.len() / 2], mean)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() -> eyre::Result<()> {
    let ks: Vec<u32> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            vec![16, 18, 20]
        } else {
            args.iter().map(|s| s.parse().unwrap()).collect()
        }
    };
    let reps: usize = std::env::var("REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    println!("co-groth16 plain prover benchmark (BN254)");
    println!("rayon threads: {}", rayon::current_num_threads());
    println!("reps per size: {reps}");

    let mut rng = rand::thread_rng();

    for k in ks {
        let domain_size = 1usize << k;
        // num_instance_variables == 2 (the constant one + the public output), and the
        // prover's domain is next_pow2(num_constraints + num_instance_variables).
        let num_squarings = domain_size - 2;
        let x = Fr::rand(&mut rng);
        let circuit = SquaringChain {
            num_squarings,
            x: Some(x),
        };

        // ---- setup (not benchmarked) ----
        let start = Instant::now();
        let pkey = ArkGroth16::<Bn254>::generate_random_parameters_with_reduction(
            circuit.clone(),
            &mut rng,
        )?;
        let setup_time = start.elapsed();

        // ---- constraint matrices + full assignment ----
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: false,
        });
        circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        let cs = cs.into_inner().expect("single reference to cs");

        let num_constraints = cs.num_constraints();
        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();

        let mut matrices = cs.to_matrices()?;
        let mut abc = matrices
            .remove(R1CS_PREDICATE_LABEL)
            .expect("R1CS predicate exists");
        let c = abc.pop().unwrap();
        let b = abc.pop().unwrap();
        let a = abc.pop().unwrap();
        let matrices = ConstraintMatrices::<Fr> {
            num_instance_variables,
            num_witness_variables,
            num_constraints,
            a_num_non_zero: a.iter().map(|row| row.len()).sum(),
            b_num_non_zero: b.iter().map(|row| row.len()).sum(),
            c_num_non_zero: c.iter().map(|row| row.len()).sum(),
            a,
            b,
            c,
        };

        let public_inputs = cs.assignments.instance_assignment.clone();
        let witness_values = cs.assignments.witness_assignment.clone();
        assert_eq!(public_inputs.len(), num_instance_variables);
        assert_eq!(witness_values.len(), num_witness_variables);

        println!(
            "\n=== k = {k} | domain = {domain_size} | constraints = {num_constraints} | \
             instance vars = {num_instance_variables} | witness vars = {num_witness_variables} ==="
        );
        println!("arkworks setup (excluded): {:.1} ms", ms(setup_time));

        let shared_witness = SharedWitness {
            public_inputs: public_inputs.clone(),
            witness: witness_values.clone(),
        };

        // ---- correctness check ----
        let proof = Groth16::<Bn254>::plain_prove::<LibSnarkReduction>(
            &pkey,
            &matrices,
            shared_witness.clone(),
        )?;
        let pvk = prepare_verifying_key(&pkey.vk);
        let verified = ArkGroth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs[1..])?;
        println!("proof verifies (arkworks verifier): {verified}");
        assert!(verified, "proof does not verify");

        // ---- full prover ----
        let mut totals = Vec::with_capacity(reps);
        for _ in 0..reps {
            let witness = shared_witness.clone();
            let start = Instant::now();
            let proof =
                Groth16::<Bn254>::plain_prove::<LibSnarkReduction>(&pkey, &matrices, witness)?;
            totals.push(start.elapsed());
            black_box(proof);
        }
        let (min, med, mean) = stats(totals);
        println!(
            "plain_prove (LibSnarkReduction): min {:.1} ms | median {:.1} ms | mean {:.1} ms",
            ms(min),
            ms(med),
            ms(mean)
        );

        // ---- witness map (QAP / h) phase only, for the phase split ----
        let mut qap = Vec::with_capacity(reps);
        for _ in 0..reps {
            let start = Instant::now();
            let h = LibSnarkReduction::witness_map_from_matrices::<Bn254, PlainGroth16Driver>(
                &mut (),
                &matrices,
                &public_inputs,
                &witness_values,
            )?;
            qap.push(start.elapsed());
            black_box(h);
        }
        let (qmin, qmed, _) = stats(qap);
        println!(
            "  of which witness_map (LibSnark): min {:.1} ms | median {:.1} ms",
            ms(qmin),
            ms(qmed)
        );

        let mut qap_circom = Vec::with_capacity(reps);
        for _ in 0..reps {
            let start = Instant::now();
            let h = CircomReduction::witness_map_from_matrices::<Bn254, PlainGroth16Driver>(
                &mut (),
                &matrices,
                &public_inputs,
                &witness_values,
            )?;
            qap_circom.push(start.elapsed());
            black_box(h);
        }
        let (cmin, cmed, _) = stats(qap_circom);
        println!(
            "  witness_map (Circom/snarkjs style, for reference): min {:.1} ms | median {:.1} ms",
            ms(cmin),
            ms(cmed)
        );
        println!(
            "  => MSM phase (total - witness_map): {:.1} ms",
            ms(min) - ms(qmin)
        );
    }

    Ok(())
}
