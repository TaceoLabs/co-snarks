use std::{borrow::Borrow, marker::PhantomData};

use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::Result as R1CSResult;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSystem, ConstraintSystemRef, LinearCombination, OptimizationGoal,
    SynthesisError, Variable,
};
use circom_types::groth16::witness::Witness;
use circom_types::r1cs::R1CS;
use color_eyre::eyre::Result;
use mpc_core::{
    protocols::aby3::{network::Aby3MpcNet, Aby3Protocol},
    traits::{FFTProvider, PairingEcMpcProtocol, PrimeFieldMpcProtocol},
};
use mpc_net::config::NetworkConfig;
use num_traits::identities::One;
use num_traits::identities::Zero;
use rand::{CryptoRng, Rng};

use crate::circuit::Circuit;
pub type Aby3CollaborativeGroth16<P> =
    CollaborativeGroth16<Aby3Protocol<<P as Pairing>::ScalarField, Aby3MpcNet>, P>;

pub struct SharedWitness<T, F: PrimeField>
where
    T: PrimeFieldMpcProtocol<F>,
{
    //this will be a VecShareType
    pub values: Vec<<T as PrimeFieldMpcProtocol<F>>::FieldShare>,
}

pub struct CollaborativeGroth16<T, P: Pairing>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>,
{
    pub(crate) driver: T,
    phantom_data: PhantomData<P>,
}

impl<T, P: Pairing> CollaborativeGroth16<T, P>
where
    for<'a> T: PrimeFieldMpcProtocol<P::ScalarField>
        + PairingEcMpcProtocol<P>
        + FFTProvider<P::ScalarField>,
{
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            phantom_data: PhantomData,
        }
    }
    pub fn prove(
        &mut self,
        pk: &ProvingKey<P>,
        r1cs: &R1CS<P>,
        public_inputs: &[P::ScalarField],
        private_witness: <T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShareVec,
    ) -> Result<Proof<P>> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        Self::generate_constraints(public_inputs, r1cs, cs.clone())?;
        let matrices = cs.to_matrices().unwrap();
        let num_inputs = cs.num_instance_variables();
        let num_constraints = cs.num_constraints();
        let domain = GeneralEvaluationDomain::<P::ScalarField>::new(num_constraints + num_inputs)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        self.witness_map_from_matrices(
            &matrices,
            num_constraints,
            public_inputs,
            private_witness,
            domain,
        );
        todo!()
    }

    fn witness_map_from_matrices(
        &mut self,
        matrices: &ConstraintMatrices<P::ScalarField>,
        num_constraints: usize,
        public_inputs: &[P::ScalarField],
        private_witness: <T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShareVec,
        domain: GeneralEvaluationDomain<P::ScalarField>,
    ) -> Result<()> {
        let domain_size = domain.size();
        let mut a = Vec::with_capacity(domain_size);
        let mut b = Vec::with_capacity(domain_size);
        for (at_i, bt_i) in itertools::multizip((&matrices.a, &matrices.b)) {
            a.push(self.evaluate_constraint(at_i, public_inputs, &private_witness)?);
            b.push(self.evaluate_constraint(bt_i, public_inputs, &private_witness)?);
        }
        Ok(())
    }

    fn evaluate_constraint(
        &mut self,
        lhs: &[(P::ScalarField, usize)],
        public_inputs: &[P::ScalarField],
        private_witness: &<T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShareVec,
    ) -> Result<<T as PrimeFieldMpcProtocol<P::ScalarField>>::FieldShare> {
        let mut acc = self.driver.get_zero_share();
        for (coeff, index) in lhs {
            if index < &public_inputs.len() {
                let val = public_inputs[*index];
                let mul_result = val * coeff;
                acc = self.driver.add_with_public(&mul_result, &acc)?;
            } else {
                let val = &private_witness[*index];
                let mul_result = self.driver.mul_with_public(coeff, val)?;
                acc = self.driver.add(&mul_result, &acc);
                //let mul_result = val * coeff;
                //acc = self.driver.add_with_public(&mul_result, &acc)?;
            }
        }
        Ok(acc)
    }

    fn generate_constraints(
        public_inputs: &[P::ScalarField],
        r1cs: &R1CS<P>,
        cs: ConstraintSystemRef<P::ScalarField>,
    ) -> Result<()> {
        for f in public_inputs.iter().skip(1) {
            cs.new_input_variable(|| Ok(*f))?;
        }

        let make_index = |index| {
            if index < r1cs.num_inputs {
                Variable::Instance(index)
            } else {
                Variable::Witness(index - r1cs.num_inputs)
            }
        };
        let make_lc = |lc_data: &[(usize, P::ScalarField)]| {
            lc_data.iter().fold(
                LinearCombination::<P::ScalarField>::zero(),
                |lc: LinearCombination<P::ScalarField>, (index, coeff)| {
                    lc + (*coeff, make_index(*index))
                },
            )
        };

        for constraint in &r1cs.constraints {
            cs.enforce_constraint(
                make_lc(&constraint.0),
                make_lc(&constraint.1),
                make_lc(&constraint.2),
            )?;
        }
        cs.finalize();
        Ok(())
    }

    pub fn verify(
        &self,
        pvk: &PreparedVerifyingKey<P>,
        proof: &Proof<P>,
        public_inputs: &[P::ScalarField],
    ) -> R1CSResult<bool> {
        Groth16::<P>::verify_proof(pvk, proof, public_inputs)
    }
}

impl<P: Pairing> Aby3CollaborativeGroth16<P> {
    pub fn with_network_config(config: NetworkConfig) -> Result<Self> {
        let mpc_net = Aby3MpcNet::new(config)?;
        let driver = Aby3Protocol::<P::ScalarField, Aby3MpcNet>::new(mpc_net)?;
        Ok(CollaborativeGroth16::new(driver))
    }
}

impl<F: PrimeField> SharedWitness<Aby3Protocol<F, Aby3MpcNet>, F> {
    pub fn share_aby3<R: Rng + CryptoRng>(_witness: &Witness<F>, _rng: &mut R) -> [Self; 3] {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use ark_bn254::Bn254;
    use ark_poly::GeneralEvaluationDomain;
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};
    use circom_types::{groth16::witness::Witness, r1cs::R1CS};

    use crate::circom_reduction::CircomReduction;

    use super::Aby3CollaborativeGroth16;
    use ark_groth16::r1cs_to_qap::R1CSToQAP;

    /* #[test]
    fn test() {
        let witness_file = File::open("../test_vectors/bn254/witness.wtns").unwrap();
        let r1cs_file = File::open("../test_vectors/bn254/multiplier2.r1cs").unwrap();
        let witness = Witness::<ark_bn254::Fr>::from_reader(witness_file).unwrap();
        let r1cs = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        //get public inputs
        let mut pub_inputs = vec![];
        #[allow(clippy::needless_range_loop)]
        for i in 1..r1cs.num_inputs {
            pub_inputs.push(witness.values[r1cs.wire_mapping[i]])
        }

        Aby3CollaborativeGroth16::generate_constraints(&pub_inputs, r1cs, cs.clone()).unwrap();
        let test = CircomReduction::witness_map::<
            ark_bn254::Fr,
            GeneralEvaluationDomain<ark_bn254::Fr>,
        >(cs.clone())
        .unwrap();
        println!("{test:?}");
    }*/
}
