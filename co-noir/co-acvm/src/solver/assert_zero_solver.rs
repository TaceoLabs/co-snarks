use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{AcirField, acir_field::GenericFieldElement, native_types::Expression};
use ark_ff::{PrimeField, Zero};

use crate::solver::solver_utils;

use super::{CoAcvmResult, CoSolver};

fn ensure_zero_residual<F: PrimeField>(residual: F) -> CoAcvmResult<()> {
    if residual.is_zero() {
        tracing::trace!("nothing to do for us");
        Ok(())
    } else {
        Err(eyre::eyre!("UnsatisfiedConstraint"))?
    }
}

fn ensure_single_opened_zero_residual<F: PrimeField>(opened: Vec<F>) -> CoAcvmResult<()> {
    if opened.len() != 1 {
        Err(eyre::eyre!(
            "open_many returned {} values for one shared residual",
            opened.len()
        ))?
    }

    ensure_zero_residual(opened[0])
}

impl<T, F> CoSolver<T, F>
where
    T: NoirWitnessExtensionProtocol<F>,
    F: PrimeField,
{
    fn evaluate_mul_terms(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
        acc: &mut Expression<T::AcvmType>,
    ) -> CoAcvmResult<()> {
        tracing::trace!("evaluating mul terms for simplification");
        if expr.mul_terms.is_empty() {
            tracing::trace!("no mul term. we are done");
            Ok(())
        } else {
            for mul in expr.mul_terms.iter() {
                let (c, lhs, rhs) = mul;
                tracing::trace!("looking at mul term {c} * _{} * _{}", lhs.0, rhs.0);
                if c.is_zero() {
                    tracing::trace!("c is zero. We can skip this mul term");
                } else {
                    match (
                        self.witness().get(lhs).cloned(),
                        self.witness().get(rhs).cloned(),
                    ) {
                        // we could batch this multiplication but our currently planned network design
                        // should solve this without batching
                        (Some(lhs), Some(rhs)) => {
                            tracing::trace!("solving mul term...");
                            let solved = self.driver.solve_mul_term(c.into_repr(), lhs, rhs)?;
                            self.driver.add_assign(&mut acc.q_c, solved);
                        }
                        (Some(lhs), None) => {
                            tracing::trace!("partially solving mul term...");
                            let partly_solved = self.driver.mul_with_public(c.into_repr(), lhs);
                            acc.linear_combinations.push((partly_solved, *rhs));
                        }
                        (None, Some(rhs)) => {
                            tracing::trace!("partially solving mul term...");
                            let partly_solved = self.driver.mul_with_public(c.into_repr(), rhs);
                            acc.linear_combinations.push((partly_solved, *lhs));
                        }
                        (None, None) => Err(eyre::eyre!(
                            "two unknowns in evaluate mul term. Not solvable for expr: {:?}",
                            expr
                        ))?,
                    };
                    tracing::trace!("after eval mul term: {acc:?}");
                }
            }
            Ok(())
        }
    }

    fn evaluate_linear_terms(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
        acc: &mut Expression<T::AcvmType>,
    ) {
        for term in expr.linear_combinations.iter() {
            let (q_l, w_l) = term;
            tracing::trace!("looking at linear term: {q_l} * _{}..", w_l.0);
            if let Some(w_l) = self.witness().get(w_l).cloned() {
                tracing::trace!("is known! reduce it");
                self.driver
                    .solve_linear_term(q_l.into_repr(), w_l, &mut acc.q_c);
            } else {
                tracing::trace!("is unknown!");
                acc.linear_combinations
                    .push((T::AcvmType::from(q_l.into_repr()), *w_l))
            }
        }
    }

    pub(crate) fn simplify_expression(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
    ) -> CoAcvmResult<Expression<T::AcvmType>> {
        tracing::trace!("simplifying expression...");
        // default implementation not exposed if we not have AcirField trait bound
        let mut simplified = Expression {
            mul_terms: vec![],
            linear_combinations: vec![],
            q_c: T::public_zero(),
        };
        // evaluate mul terms
        self.evaluate_mul_terms(expr, &mut simplified)?;
        // evaluate linear terms
        self.evaluate_linear_terms(expr, &mut simplified);
        // add constants
        self.driver
            .add_assign_with_public(expr.q_c.into_repr(), &mut simplified.q_c);

        Ok(simplified)
    }

    pub(super) fn solve_assert_zero(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
    ) -> CoAcvmResult<()> {
        //first evaluate the already existing terms
        tracing::trace!(
            "solving assert zero: {}",
            solver_utils::expr_to_string(expr)
        );
        let simplified = self.simplify_expression(expr)?;
        tracing::trace!("simplified expr:     {:?}", simplified);
        // if we are here, we do not have any mul terms
        debug_assert!(simplified.mul_terms.is_empty());
        debug_assert!(
            simplified.linear_combinations.len() <= 4,
            "we need to simplify!!!"
        );
        // also if we are here and have more than one linear combination, we
        // cannot solve the expression
        if simplified.linear_combinations.is_empty() {
            if let Some(residual) = T::get_public(&simplified.q_c) {
                ensure_zero_residual(residual)
            } else if let Some(residual) = T::get_shared(&simplified.q_c) {
                let opened = self.driver.open_many(&[residual])?;
                ensure_single_opened_zero_residual(opened)
            } else if T::is_public_zero(&simplified.q_c) {
                tracing::trace!("nothing to do for us");
                Ok(())
            } else {
                Err(eyre::eyre!("UnsatisfiedConstraint"))?
            }
        } else if simplified.linear_combinations.len() == 1 {
            //we can solve it!
            tracing::trace!("solving equation...");
            let (q_l, w_l) = simplified.linear_combinations[0].clone();
            let witness = self.driver.solve_equation(q_l, simplified.q_c)?;
            self.witness().insert(w_l, witness);
            tracing::trace!("we did it!");
            Ok(())
        } else {
            Err(eyre::eyre!(
                "too many unknowns. not solvable for expression: {:?}",
                expr
            ))?
        }
    }

    pub(crate) fn evaluate_expression(
        &mut self,
        expr: &Expression<GenericFieldElement<F>>,
    ) -> CoAcvmResult<T::AcvmType> {
        Ok(self
            .simplify_expression(expr)?
            .to_const()
            .cloned()
            .ok_or(eyre::eyre!(
                "cannot evaluate expression to const - has unknown"
            ))?)
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_single_opened_zero_residual, ensure_zero_residual};
    use crate::mpc::{NoirWitnessExtensionProtocol, plain::PlainAcvmSolver};
    use crate::pss_store::PssStore;
    use crate::solver::CoSolver;
    use acir::{
        acir_field::GenericFieldElement,
        native_types::{Expression, Witness, WitnessMap},
    };
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use co_brillig::CoBrilligVM;
    use intmap::IntMap;
    use noirc_abi::Abi;

    fn field(value: Fr) -> GenericFieldElement<Fr> {
        GenericFieldElement::from_repr(value)
    }

    fn expression(q_c: Fr) -> Expression<GenericFieldElement<Fr>> {
        Expression {
            mul_terms: vec![],
            linear_combinations: vec![],
            q_c: field(q_c),
        }
    }

    fn solver_with_witness(witness: WitnessMap<Fr>) -> CoSolver<PlainAcvmSolver<Fr>, Fr> {
        let mut driver = PlainAcvmSolver::<Fr>::default();
        let brillig = CoBrilligVM::init(driver.init_brillig_driver().unwrap(), vec![]);
        CoSolver {
            driver,
            brillig,
            abi: Abi::default(),
            functions: vec![],
            value_store: PssStore::new(),
            witness_map: vec![witness],
            function_index: 0,
            memory_access: IntMap::new(),
            pedantic_solving: true,
        }
    }

    #[test]
    fn public_zero_residual_succeeds() {
        assert!(ensure_zero_residual(Fr::zero()).is_ok());
    }

    #[test]
    fn public_nonzero_residual_errors() {
        let err = ensure_zero_residual(Fr::one()).unwrap_err().to_string();
        assert!(err.contains("UnsatisfiedConstraint"));
    }

    #[test]
    fn shared_zero_residual_succeeds_after_opening() {
        assert!(ensure_single_opened_zero_residual(vec![Fr::zero()]).is_ok());
    }

    #[test]
    fn shared_nonzero_residual_errors_after_opening() {
        let err = ensure_single_opened_zero_residual(vec![Fr::one()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("UnsatisfiedConstraint"));
    }

    #[test]
    fn opened_shared_residual_must_preserve_input_length() {
        let err = ensure_single_opened_zero_residual::<Fr>(Vec::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("open_many returned 0 values for one shared residual"));
    }

    #[test]
    fn solve_assert_zero_accepts_simplified_public_zero_residual() {
        let mut solver = solver_with_witness(WitnessMap::default());

        assert!(solver.solve_assert_zero(&expression(Fr::zero())).is_ok());
    }

    #[test]
    fn solve_assert_zero_rejects_simplified_public_nonzero_residual() {
        let mut solver = solver_with_witness(WitnessMap::default());

        let err = solver
            .solve_assert_zero(&expression(Fr::one()))
            .unwrap_err()
            .to_string();

        assert!(err.contains("UnsatisfiedConstraint"));
    }

    #[test]
    fn solve_assert_zero_checks_residual_after_known_witness_simplification() {
        let witness_id = Witness(1);
        let mut witness = WitnessMap::default();
        witness.insert(witness_id, Fr::from(5u64));
        let mut solver = solver_with_witness(witness);
        let mut expr = expression(-Fr::from(5u64));
        expr.linear_combinations
            .push((field(Fr::one()), witness_id));

        assert!(solver.solve_assert_zero(&expr).is_ok());

        let mut bad_expr = expression(-Fr::from(4u64));
        bad_expr
            .linear_combinations
            .push((field(Fr::one()), witness_id));
        let err = solver.solve_assert_zero(&bad_expr).unwrap_err().to_string();
        assert!(err.contains("UnsatisfiedConstraint"));
    }
}
