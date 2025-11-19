/// Code for building and verifying circuits
mod builder;
/// Parsing code for Bristol Fashion circuits
mod parser;

use core::panic;
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    io::{Read, Write},
    path::Path,
};

use super::{CircuitBuilderError, CircuitExecutionError};

#[derive(Debug, Clone, PartialEq, Eq)]
enum BristolFashionGate {
    EqConst {
        input: bool,
        outwire: usize,
    },
    EqWire {
        inwire: usize,
        outwire: usize,
    },
    Inv {
        inwire: usize,
        outwire: usize,
    },
    And {
        inwire1: usize,
        inwire2: usize,
        outwire: usize,
    },
    Xor {
        inwire1: usize,
        inwire2: usize,
        outwire: usize,
    },
}

impl std::fmt::Display for BristolFashionGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BristolFashionGate::Inv { inwire, outwire } => {
                f.write_fmt(format_args!("1 1 {inwire} {outwire} INV"))
            }
            BristolFashionGate::EqConst { input, outwire } => {
                f.write_fmt(format_args!("1 1 {} {} EQ", i32::from(*input), outwire))
            }
            BristolFashionGate::EqWire { inwire, outwire } => {
                f.write_fmt(format_args!("1 1 {inwire} {outwire} EQW"))
            }
            BristolFashionGate::And {
                inwire1,
                inwire2,
                outwire,
            } => f.write_fmt(format_args!("2 1 {inwire1} {inwire2} {outwire} AND")),
            BristolFashionGate::Xor {
                inwire1,
                inwire2,
                outwire,
            } => f.write_fmt(format_args!("2 1 {inwire1} {inwire2} {outwire} XOR")),
        }
    }
}

/// A Bristol Fashion Circuit
#[derive(Clone, Debug)]
pub struct BristolFashionCircuit {
    input_wires: Vec<Vec<usize>>,
    output_wires: Vec<Vec<usize>>,
    gates: Vec<BristolFashionGate>,
    num_and_gates: usize,
}
#[expect(dead_code)]
impl BristolFashionCircuit {
    /// Parse a Bristol-Fashion style circuit from a file
    pub(crate) fn from_file(path: impl AsRef<Path>) -> Result<Self, CircuitBuilderError> {
        let circuit = std::fs::read_to_string(path)?;
        parser::parse(&circuit)?.verify()
    }
    /// Parse a Bristol-Fashion style circuit from a reader
    pub(crate) fn from_reader(mut reader: impl Read) -> Result<Self, CircuitBuilderError> {
        let mut circuit = String::new();
        reader.read_to_string(&mut circuit)?;
        parser::parse(&circuit)?.verify()
    }

    /// Transform circuit into a leveled circuit, for more efficient execution
    pub(crate) fn level(self) -> LeveledBristolFashionCircuit {
        let BristolFashionCircuit {
            input_wires,
            output_wires,
            gates,
            num_and_gates,
        } = self;

        // map of gate_output_wire_id -> (and_depth, total_depth)
        let mut gate_level: HashMap<usize, (usize, usize)> = HashMap::new();

        // store gates oganized by level: and_level -> internal normal_level -> gate
        let mut levels: BTreeMap<usize, BTreeMap<usize, Vec<BristolFashionGate>>> = BTreeMap::new();

        // input wires start at depth 0
        input_wires.iter().flatten().for_each(|id| {
            gate_level.insert(*id, (0, 0));
        });

        for gate in gates {
            match gate {
                // Const gates are the first things we handle in layer 1
                BristolFashionGate::EqConst { outwire, .. } => {
                    gate_level
                        .insert(outwire, (0, 1))
                        .ok_or(())
                        .expect_err("circuit already verified");
                    levels
                        .entry(0)
                        .or_default()
                        .entry(0)
                        .or_default()
                        .push(gate);
                }
                // EqWires are a bit strange, they should just be removed from the circuit alltogether in the future
                // Atm we add a linear level for them
                BristolFashionGate::EqWire { inwire, outwire } => {
                    let (and_depth, total_depth) = gate_level
                        .get(&inwire)
                        .expect("circuit already verified")
                        .to_owned();
                    let new_level = total_depth + 1;
                    let and_level = and_depth;
                    gate_level
                        .insert(outwire, (and_level, new_level))
                        .ok_or(())
                        .expect_err("circuit already verified");
                    levels
                        .entry(and_level)
                        .or_default()
                        .entry(new_level)
                        .or_default()
                        .push(gate);
                }
                // INV Gates add a linear level only
                BristolFashionGate::Inv { inwire, outwire } => {
                    let (and_depth, total_depth) = gate_level
                        .get(&inwire)
                        .expect("circuit already verified")
                        .to_owned();
                    let new_level = total_depth + 1;
                    let and_level = and_depth;
                    gate_level
                        .insert(outwire, (and_depth, new_level))
                        .ok_or(())
                        .expect_err("circuit already verified");
                    levels
                        .entry(and_level)
                        .or_default()
                        .entry(new_level)
                        .or_default()
                        .push(gate);
                }
                // XOR Gates add a linear level only
                BristolFashionGate::Xor {
                    inwire1,
                    inwire2,
                    outwire,
                } => {
                    let (and_depth1, total_depth1) = gate_level
                        .get(&inwire1)
                        .expect("circuit already verified")
                        .to_owned();
                    let (and_depth2, total_depth2) = gate_level
                        .get(&inwire2)
                        .expect("circuit already verified")
                        .to_owned();
                    let new_level = max(total_depth1, total_depth2) + 1;
                    let and_level = max(and_depth1, and_depth2);
                    gate_level
                        .insert(outwire, (and_level, new_level))
                        .ok_or(())
                        .expect_err("circuit already verified");
                    levels
                        .entry(and_level)
                        .or_default()
                        .entry(new_level)
                        .or_default()
                        .push(gate);
                }
                // AND Gates add a non-linear level
                BristolFashionGate::And {
                    inwire1,
                    inwire2,
                    outwire,
                } => {
                    let (and_depth1, total_depth1) = gate_level
                        .get(&inwire1)
                        .expect("circuit already verified")
                        .to_owned();
                    let (and_depth2, total_depth2) = gate_level
                        .get(&inwire2)
                        .expect("circuit already verified")
                        .to_owned();
                    let new_and_level = max(and_depth1, and_depth2) + 1;
                    let new_level = max(total_depth1, total_depth2) + 1;
                    gate_level
                        .insert(outwire, (new_and_level, new_level))
                        .ok_or(())
                        .expect_err("circuit already verified");
                    levels
                        .entry(new_and_level)
                        .or_default()
                        .entry(0)
                        .or_default()
                        .push(gate);
                }
            }
        }

        let levels: Vec<_> = levels
            .into_values()
            .enumerate()
            .flat_map(|(and_level, internal_levels)| {
                internal_levels
                    .into_values()
                    .enumerate()
                    .map(move |(index, gates)| {
                        if and_level > 0 && index == 0 {
                            CircuitLevel::NonLinearLevel(gates)
                        } else {
                            CircuitLevel::LinearLevel(gates)
                        }
                    })
            })
            .enumerate()
            .collect();

        LeveledBristolFashionCircuit {
            input_wires,
            output_wires,
            levels,
            num_and_gates,
        }
    }
    /// Returns the total number of AND gates
    pub(crate) fn num_and_gates(&self) -> usize {
        self.num_and_gates
    }
    /// Returns the total number of input wires
    pub(crate) fn num_input_wires(&self) -> usize {
        self.input_wires.iter().flatten().count()
    }
    /// Returns the input wires
    pub(crate) fn get_input_wires(&self) -> Vec<Vec<usize>> {
        self.input_wires.to_owned()
    }
    /// Returns the output wires
    pub(crate) fn get_output_wires(&self) -> Vec<Vec<usize>> {
        self.output_wires.to_owned()
    }

    /// Returns the total number of wires in the circuit, including input +  output wires
    pub(crate) fn num_wires(&self) -> usize {
        self.num_input_wires() + self.gates.len()
    }

    /// Evaluate the Bristol-Fashion circuit
    pub(crate) fn evaluate<T>(
        &self,
        inputs: &[impl AsRef<[T]>],
        evaluator: &mut impl BristolFashionEvaluator<WireValue = T>,
    ) -> Result<Vec<Vec<T>>, CircuitExecutionError>
    where
        T: Clone + Default,
    {
        self.evaluate_with_default(inputs, evaluator, T::default())
    }

    /// Evaluate the Bristol-Fashion circuit from a given default value, such that the Default trait not being required
    pub(crate) fn evaluate_with_default<T>(
        &self,
        inputs: &[impl AsRef<[T]>],
        evaluator: &mut impl BristolFashionEvaluator<WireValue = T>,
        default: T,
    ) -> Result<Vec<Vec<T>>, CircuitExecutionError>
    where
        T: Clone,
    {
        let mut execution_wires: Vec<T> = vec![default; self.num_wires()];

        if inputs.len() != self.input_wires.len() {
            return Err(CircuitExecutionError::InvalidInput(format!(
                "Provided {} input bundles, circuit requires {} input bundles",
                inputs.len(),
                self.input_wires.len()
            )));
        }

        for (j, (bools, wires)) in inputs.iter().zip(self.input_wires.iter()).enumerate() {
            let bools = bools.as_ref();
            if bools.len() != wires.len() {
                return Err(CircuitExecutionError::InvalidInput(format!(
                    "Input bundle {} has {} values, circuit requires it to have {} values",
                    j,
                    bools.len(),
                    wires.len()
                )));
            }
            for (val, &wire_id) in bools.iter().zip(wires) {
                execution_wires[wire_id] = val.clone();
            }
        }

        for gate in self.gates.iter() {
            match gate {
                BristolFashionGate::EqConst { input, outwire } => {
                    execution_wires[*outwire] = evaluator.constant(*input)?;
                }
                BristolFashionGate::EqWire { inwire, outwire } => {
                    let val = &execution_wires[*inwire];

                    let new_val = val.clone();
                    execution_wires[*outwire] = new_val;
                }
                BristolFashionGate::Inv { inwire, outwire } => {
                    let val = &execution_wires[*inwire];

                    let new_val = evaluator.inv(val)?;
                    execution_wires[*outwire] = new_val;
                }
                BristolFashionGate::Xor {
                    inwire1,
                    inwire2,
                    outwire,
                } => {
                    let val1 = &execution_wires[*inwire1];
                    let val2 = &execution_wires[*inwire2];

                    let new_val = evaluator.xor(val1, val2)?;
                    execution_wires[*outwire] = new_val;
                }
                BristolFashionGate::And {
                    inwire1,
                    inwire2,
                    outwire,
                } => {
                    let val1 = &execution_wires[*inwire1];
                    let val2 = &execution_wires[*inwire2];

                    let new_val = evaluator.and(val1, val2)?;
                    execution_wires[*outwire] = new_val;
                }
            }
        }

        Ok(self
            .output_wires
            .iter()
            .map(|output_bundle| {
                output_bundle
                    .iter()
                    .map(|wire_id| execution_wires[*wire_id].clone())
                    .collect::<Vec<T>>()
            })
            .collect::<Vec<Vec<T>>>())
    }

    pub(crate) fn write_circuit_file(&self, writer: &mut impl Write) -> Result<(), std::io::Error> {
        writeln!(writer, "{} {}", self.gates.len(), self.num_wires())?;
        write!(writer, "{} ", self.input_wires.len())?;
        for inputs in self.input_wires.iter() {
            write!(writer, "{} ", inputs.len())?;
        }
        writeln!(writer)?;
        write!(writer, "{} ", self.output_wires.len())?;
        for outputs in self.output_wires.iter() {
            write!(writer, "{} ", outputs.len())?;
        }
        writeln!(writer)?;
        writeln!(writer)?;

        for gate in self.gates.iter() {
            match gate {
                BristolFashionGate::EqConst { input, outwire } => {
                    writeln!(writer, "1 1 {} {} EQ", i32::from(*input), outwire)?;
                }
                BristolFashionGate::EqWire { inwire, outwire } => {
                    writeln!(writer, "1 1 {inwire} {outwire} EQW")?
                }
                BristolFashionGate::Inv { inwire, outwire } => {
                    writeln!(writer, "1 1 {inwire} {outwire} INV")?
                }
                BristolFashionGate::And {
                    inwire1,
                    inwire2,
                    outwire,
                } => writeln!(writer, "2 1 {inwire1} {inwire2} {outwire} AND")?,
                BristolFashionGate::Xor {
                    inwire1,
                    inwire2,
                    outwire,
                } => writeln!(writer, "2 1 {inwire1} {inwire2} {outwire} XOR")?,
            }
        }
        writeln!(writer)
    }
}

#[derive(Clone, Debug)]
enum CircuitLevel {
    LinearLevel(Vec<BristolFashionGate>),
    NonLinearLevel(Vec<BristolFashionGate>),
}

/// A Bristol Fashion Circuit, prepared for leveled evaluation
#[derive(Clone, Debug)]
pub struct LeveledBristolFashionCircuit {
    input_wires: Vec<Vec<usize>>,
    output_wires: Vec<Vec<usize>>,
    levels: Vec<(usize, CircuitLevel)>,
    num_and_gates: usize,
}
#[expect(dead_code)]
impl LeveledBristolFashionCircuit {
    /// Returns the total number of wires in the circuit, including input +  output wires
    pub(crate) fn num_wires(&self) -> usize {
        self.input_wires.iter().flatten().count()
            + self
                .levels
                .iter()
                .map(|(_, x)| match x {
                    CircuitLevel::LinearLevel(x) | CircuitLevel::NonLinearLevel(x) => x.len(),
                })
                .sum::<usize>()
    }
    /// Returns the total number of AND gates
    pub(crate) fn num_and_gates(&self) -> usize {
        self.num_and_gates
    }
    /// Returns the total number of input wires
    pub(crate) fn num_input_wires(&self) -> usize {
        self.input_wires.iter().flatten().count()
    }
    /// Returns the input wires
    pub(crate) fn get_input_wires(&self) -> Vec<Vec<usize>> {
        self.input_wires.to_owned()
    }
    /// Returns the output wires
    pub(crate) fn get_output_wires(&self) -> Vec<Vec<usize>> {
        self.output_wires.to_owned()
    }

    /// Evaluate the Bristol-Fashion circuit
    pub(crate) fn evaluate<T>(
        &self,
        inputs: &[impl AsRef<[T]>],
        evaluator: &mut impl BristolFashionEvaluator<WireValue = T>,
    ) -> Result<Vec<Vec<T>>, CircuitExecutionError>
    where
        T: Default + Clone,
    {
        self.evaluate_with_default(inputs, evaluator, T::default())
    }

    /// Evaluate the Bristol-Fashion circuit from a given default value, such that the Default trait not being required
    pub(crate) fn evaluate_with_default<T>(
        &self,
        inputs: &[impl AsRef<[T]>],
        evaluator: &mut impl BristolFashionEvaluator<WireValue = T>,
        default: T,
    ) -> Result<Vec<Vec<T>>, CircuitExecutionError>
    where
        T: Clone,
    {
        let mut execution_wires: Vec<T> = vec![default; self.num_wires()];

        if inputs.len() != self.input_wires.len() {
            return Err(CircuitExecutionError::InvalidInput(format!(
                "Provided {} input bundles, circuit requires {} input bundles",
                inputs.len(),
                self.input_wires.len()
            )));
        }

        for (j, (bools, wires)) in inputs.iter().zip(self.input_wires.iter()).enumerate() {
            let bools = bools.as_ref();
            if bools.len() != wires.len() {
                return Err(CircuitExecutionError::InvalidInput(format!(
                    "Input bundle {} has {} values, circuit requires it to have {} values",
                    j,
                    bools.len(),
                    wires.len()
                )));
            }
            for (val, &wire_id) in bools.iter().zip(wires) {
                execution_wires[wire_id] = val.clone();
            }
        }
        for (_level, level_gates) in self.levels.iter() {
            match level_gates {
                CircuitLevel::LinearLevel(gates) => {
                    for gate in gates {
                        match gate {
                            BristolFashionGate::EqConst { input, outwire } => {
                                execution_wires[*outwire] = evaluator.constant(*input)?;
                            }
                            BristolFashionGate::EqWire { inwire, outwire } => {
                                let val = &execution_wires[*inwire];

                                let new_val = val.clone();
                                execution_wires[*outwire] = new_val;
                            }
                            BristolFashionGate::Inv { inwire, outwire } => {
                                let val = &execution_wires[*inwire];

                                let new_val = evaluator.inv(val)?;
                                execution_wires[*outwire] = new_val;
                            }
                            BristolFashionGate::Xor {
                                inwire1,
                                inwire2,
                                outwire,
                            } => {
                                let val1 = &execution_wires[*inwire1];
                                let val2 = &execution_wires[*inwire2];

                                let new_val = evaluator.xor(val1, val2)?;
                                execution_wires[*outwire] = new_val;
                            }
                            BristolFashionGate::And { .. } => {
                                panic!("No AND gates in a LinearLevel")
                            }
                        }
                    }
                }
                CircuitLevel::NonLinearLevel(gates) => {
                    let mut inputs1 = Vec::with_capacity(gates.len());
                    let mut inputs2 = Vec::with_capacity(gates.len());
                    for gate in gates {
                        match gate {
                            BristolFashionGate::And {
                                inwire1, inwire2, ..
                            } => {
                                let val1 = &execution_wires[*inwire1];
                                let val2 = &execution_wires[*inwire2];
                                inputs1.push(val1);
                                inputs2.push(val2);
                            }
                            _ => panic!("Only AND gates in NonLinearLayer"),
                        }
                    }
                    let mut new_vals = evaluator.many_and(&inputs1, &inputs2)?;

                    for gate in gates.iter().rev() {
                        match gate {
                            BristolFashionGate::And { outwire, .. } => {
                                execution_wires[*outwire] =
                                    new_vals.pop().expect("we get a value for each gate");
                            }
                            _ => panic!("Only AND gates in NonLinearLayer"),
                        }
                    }
                }
            }
        }

        Ok(self
            .output_wires
            .iter()
            .map(|output_bundle| {
                output_bundle
                    .iter()
                    .map(|wire_id| execution_wires[*wire_id].clone())
                    .collect::<Vec<T>>()
            })
            .collect::<Vec<Vec<T>>>())
    }
}

/// A trait enabling the evaluation of circuits on different datatypes
pub trait BristolFashionEvaluator {
    /// The representation of values on Wires
    ///
    /// e.g., for a standard boolean circuit evaluation this could be `bool`
    /// e.g., for a evaluating a circuit using FHE, this could be an FHE ciphertext encrypting 0 or 1
    type WireValue: Sized + std::fmt::Debug + Clone;
    // TODO: once GATs are stable, see if we can maybe specify the error type here better

    /// Produce a `WireValue` equal to a zero/false bit if `input == false`,
    /// otherwise procude a `WireValue` equal to a one/true bit.
    fn constant(&mut self, input: bool) -> Result<Self::WireValue, CircuitExecutionError>;
    /// Produce a `WireValue` equal to the inverse of the input `WireValue`
    ///
    /// i.e., if the input `WireValue` represents 0, return 1 and vice versa
    fn inv(&mut self, input: &Self::WireValue) -> Result<Self::WireValue, CircuitExecutionError>;
    /// Produce a `WireValue` equal to the XOR of the two input `WireValue`s
    fn xor(
        &mut self,
        input1: &Self::WireValue,
        input2: &Self::WireValue,
    ) -> Result<Self::WireValue, CircuitExecutionError>;
    /// Produce a `WireValue` equal to the AND of the two input `WireValue`s
    fn and(
        &mut self,
        input1: &Self::WireValue,
        input2: &Self::WireValue,
    ) -> Result<Self::WireValue, CircuitExecutionError>;

    /// An interface for evaluating many ANDs at once, for optimized networking etc
    ///
    /// Produce a `WireValue` equal to the AND of the two input `WireValue`s for each
    /// pair of input values
    ///
    /// If no implementation is provided, this just repeatedly calls `self.and`.
    ///
    /// # Requirements
    /// The resulting Vector has to be the same length as the two inputs.
    ///
    /// # Panics
    /// Panics if `inputs1.len() != inputs2.len()`.
    fn many_and(
        &mut self,
        inputs1: &[&Self::WireValue],
        inputs2: &[&Self::WireValue],
    ) -> Result<Vec<Self::WireValue>, CircuitExecutionError> {
        assert_eq!(inputs1.len(), inputs2.len());
        inputs1
            .iter()
            .zip(inputs2)
            .map(|(&a, &b)| self.and(a, b))
            .collect()
    }
}

#[allow(dead_code)] // expect somehow does not work here?
pub struct BoolBristolFashionEvaluator;

impl BristolFashionEvaluator for BoolBristolFashionEvaluator {
    type WireValue = bool;

    fn constant(&mut self, input: bool) -> Result<Self::WireValue, CircuitExecutionError> {
        Ok(input)
    }

    fn inv(&mut self, input: &Self::WireValue) -> Result<Self::WireValue, CircuitExecutionError> {
        Ok(!input)
    }

    fn xor(
        &mut self,
        input1: &Self::WireValue,
        input2: &Self::WireValue,
    ) -> Result<Self::WireValue, CircuitExecutionError> {
        Ok(input1 ^ input2)
    }

    fn and(
        &mut self,
        input1: &Self::WireValue,
        input2: &Self::WireValue,
    ) -> Result<Self::WireValue, CircuitExecutionError> {
        Ok(input1 & input2)
    }
}

#[cfg(test)]
mod tests {

    use crate::protocols::rep3::yao::bristol_fashion::bristol::{
        BoolBristolFashionEvaluator, CircuitLevel,
    };

    use super::{BristolFashionCircuit, BristolFashionGate, parser};

    const SINGLE_XOR: &str = r#"1 3
2 1 1
1 1

2 1 0 1 2 XOR
"#;

    #[test]
    fn parse_simple() {
        parser::parse(SINGLE_XOR).unwrap();
    }
    #[test]
    fn parse_and_verify() {
        parser::parse(SINGLE_XOR).unwrap().verify().unwrap();
    }
    #[test]
    fn parse_and_verify_and_level() {
        let circ = parser::parse(SINGLE_XOR).unwrap().verify().unwrap().level();
        assert_eq!(circ.levels.len(), 1);
        assert_eq!(circ.input_wires.len(), 2);
        assert_eq!(circ.output_wires.len(), 1);
        assert_eq!(circ.input_wires[0].len(), 1);
        assert_eq!(circ.input_wires[1].len(), 1);
        assert_eq!(circ.output_wires[0].len(), 1);
        assert_eq!(circ.input_wires[0][0], 0);
        assert_eq!(circ.input_wires[1][0], 1);
        assert_eq!(circ.output_wires[0][0], 2);
        assert_eq!(circ.levels[0].0, 0);
        if let CircuitLevel::LinearLevel(gates) = &circ.levels[0].1 {
            assert_eq!(gates.len(), 1);
            assert_eq!(
                gates[0],
                BristolFashionGate::Xor {
                    inwire1: 0,
                    inwire2: 1,
                    outwire: 2
                }
            );
        } else {
            panic!("CircuitLevel should be LinearLevel");
        }
    }
    #[test]
    fn parse_reader() {
        let result = BristolFashionCircuit::from_reader(SINGLE_XOR.as_bytes()).unwrap();
        assert_eq!(result.gates.len(), 1);
        assert_eq!(result.input_wires.len(), 2);
        assert_eq!(result.output_wires.len(), 1);
        assert_eq!(result.input_wires[0].len(), 1);
        assert_eq!(result.input_wires[1].len(), 1);
        assert_eq!(result.output_wires[0].len(), 1);
        assert_eq!(result.input_wires[0][0], 0);
        assert_eq!(result.input_wires[1][0], 1);
        assert_eq!(result.output_wires[0][0], 2);
        assert_eq!(
            result.gates[0],
            BristolFashionGate::Xor {
                inwire1: 0,
                inwire2: 1,
                outwire: 2
            }
        );
    }
    #[test]
    fn eval_simple() {
        let circuit = BristolFashionCircuit::from_reader(SINGLE_XOR.as_bytes()).unwrap();

        for i in 0..4 {
            let a: bool = (i % 2) != 0;
            let b: bool = (i / 2) != 0;
            let r = a ^ b;

            let inputs = vec![vec![a], vec![b]];
            let c = circuit
                .evaluate(inputs.as_slice(), &mut BoolBristolFashionEvaluator)
                .unwrap();
            assert!(c.len() == 1);
            assert!(c[0].len() == 1);

            assert_eq!(r, c[0][0]);
        }
    }
    #[test]
    fn eval_leveled() {
        let circuit = BristolFashionCircuit::from_reader(SINGLE_XOR.as_bytes())
            .unwrap()
            .level();

        for i in 0..4 {
            let a: bool = (i % 2) != 0;
            let b: bool = (i / 2) != 0;
            let r = a ^ b;

            let inputs = vec![vec![a], vec![b]];
            let c = circuit
                .evaluate(inputs.as_slice(), &mut BoolBristolFashionEvaluator)
                .unwrap();
            assert!(c.len() == 1);
            assert!(c[0].len() == 1);

            assert_eq!(r, c[0][0]);
        }
    }
    const U8_ADDER: &str = r#"34 50
2 8 8
1 8

2 1 0 8 42 XOR
2 1 0 8 16 AND
2 1 9 16 17 XOR
2 1 1 17 43 XOR
2 1 1 16 18 XOR
2 1 18 17 19 AND
2 1 19 16 20 XOR
2 1 10 20 21 XOR
2 1 2 21 44 XOR
2 1 2 20 22 XOR
2 1 22 21 23 AND
2 1 23 20 24 XOR
2 1 11 24 25 XOR
2 1 3 25 45 XOR
2 1 3 24 26 XOR
2 1 26 25 27 AND
2 1 27 24 28 XOR
2 1 12 28 29 XOR
2 1 4 29 46 XOR
2 1 4 28 30 XOR
2 1 30 29 31 AND
2 1 31 28 32 XOR
2 1 13 32 33 XOR
2 1 5 33 47 XOR
2 1 5 32 34 XOR
2 1 34 33 35 AND
2 1 35 32 36 XOR
2 1 14 36 37 XOR
2 1 6 37 48 XOR
2 1 6 36 38 XOR
2 1 38 37 39 AND
2 1 39 36 40 XOR
2 1 15 40 41 XOR
2 1 7 41 49 XOR
"#;

    #[test]
    fn u8_adder_circuit() {
        let normal_circuit = BristolFashionCircuit::from_reader(U8_ADDER.as_bytes()).unwrap();

        for a in u8::MIN..u8::MAX {
            for b in u8::MIN..u8::MAX {
                let c = a.wrapping_add(b);
                let a_bits: Vec<bool> = (0..8).map(|i| ((a >> i) & 1) == 1).collect();
                let b_bits: Vec<bool> = (0..8).map(|i| ((b >> i) & 1) == 1).collect();

                let result = normal_circuit
                    .evaluate(&[a_bits, b_bits], &mut BoolBristolFashionEvaluator)
                    .expect("execution works");
                assert_eq!(result.len(), 1);
                assert_eq!(result[0].len(), 8);
                let calc_c = result[0]
                    .iter()
                    .enumerate()
                    .fold(0_u8, |a, (i, &b)| a + (u8::from(b) << i));
                //println!("{} + {} = {}, {}", a, b, c, calc_c);
                assert_eq!(c, calc_c);
            }
        }
    }

    #[test]
    fn u8_adder_circuit_leveled() {
        let leveled_circuit = BristolFashionCircuit::from_reader(U8_ADDER.as_bytes())
            .unwrap()
            .level();

        for a in u8::MIN..u8::MAX {
            for b in u8::MIN..u8::MAX {
                let c = a.wrapping_add(b);
                let a_bits: Vec<bool> = (0..8).map(|i| ((a >> i) & 1) == 1).collect();
                let b_bits: Vec<bool> = (0..8).map(|i| ((b >> i) & 1) == 1).collect();

                let result = leveled_circuit
                    .evaluate(&[a_bits, b_bits], &mut BoolBristolFashionEvaluator)
                    .expect("execution works");
                assert_eq!(result.len(), 1);
                assert_eq!(result[0].len(), 8);
                let calc_c = result[0]
                    .iter()
                    .enumerate()
                    .fold(0_u8, |a, (i, &b)| a + (u8::from(b) << i));
                //println!("{} + {} = {}, {}", a, b, c, calc_c);
                assert_eq!(c, calc_c);
            }
        }
    }
}
