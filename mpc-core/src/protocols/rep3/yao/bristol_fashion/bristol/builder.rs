use std::collections::HashSet;

use crate::protocols::rep3::yao::bristol_fashion::CircuitBuilderError;

use super::{BristolFashionCircuit, BristolFashionGate};

/// A Bristol Fashion Circuit
pub struct UnverifiedBristolFashionCircuit {
    pub(super) num_wires: usize,
    pub(super) input_wires: Vec<Vec<usize>>,
    pub(super) output_wires: Vec<Vec<usize>>,
    pub(super) gates: Vec<BristolFashionGate>,
}

impl UnverifiedBristolFashionCircuit {
    pub fn verify(self) -> Result<BristolFashionCircuit, CircuitBuilderError> {
        let mut wires: HashSet<usize> = HashSet::new();

        for id in self.input_wires.iter().flatten() {
            if !wires.insert(*id) {
                return Err(CircuitBuilderError::InvalidCircuit(format!(
                    "duplicate input wire with id {id}"
                )));
            }
        }
        let mut num_and_gates = 0;

        for gate in self.gates.iter() {
            match gate {
                BristolFashionGate::EqConst { input: _, outwire } => {
                    if !wires.insert(*outwire) {
                        return Err(CircuitBuilderError::InvalidCircuit(format!(
                            "output wire {outwire} already has a value (in ({gate}))"
                        )));
                    }
                }
                BristolFashionGate::EqWire { inwire, outwire } => {
                    let _ = wires.get(inwire).ok_or_else(|| {
                        CircuitBuilderError::InvalidCircuit(format!(
                            "input wire {inwire} does not have a value (in ({gate}))"
                        ))
                    })?;

                    if !wires.insert(*outwire) {
                        return Err(CircuitBuilderError::InvalidCircuit(format!(
                            "output wire {outwire} already has a value (in ({gate}))"
                        )));
                    }
                }
                BristolFashionGate::Inv { inwire, outwire } => {
                    let _ = wires.get(inwire).ok_or_else(|| {
                        CircuitBuilderError::InvalidCircuit(format!(
                            "input wire {inwire} does not have a value (in ({gate}))"
                        ))
                    })?;

                    if !wires.insert(*outwire) {
                        return Err(CircuitBuilderError::InvalidCircuit(format!(
                            "output wire {outwire} already has a value (in ({gate}))"
                        )));
                    }
                }
                BristolFashionGate::And {
                    inwire1,
                    inwire2,
                    outwire,
                } => {
                    let _ = wires.get(inwire1).ok_or_else(|| {
                        CircuitBuilderError::InvalidCircuit(format!(
                            "input wire {inwire1} does not have a value (in ({gate}))"
                        ))
                    })?;
                    let _ = wires.get(inwire2).ok_or_else(|| {
                        CircuitBuilderError::InvalidCircuit(format!(
                            "input wire {inwire2} does not have a value (in ({gate}))"
                        ))
                    })?;

                    if !wires.insert(*outwire) {
                        return Err(CircuitBuilderError::InvalidCircuit(format!(
                            "output wire {outwire} already has a value (in ({gate}))"
                        )));
                    }
                    num_and_gates += 1;
                }
                BristolFashionGate::Xor {
                    inwire1,
                    inwire2,
                    outwire,
                } => {
                    let _ = wires.get(inwire1).ok_or_else(|| {
                        CircuitBuilderError::InvalidCircuit(format!(
                            "input wire {inwire1} does not have a value (in ({gate}))"
                        ))
                    })?;
                    let _ = wires.get(inwire2).ok_or_else(|| {
                        CircuitBuilderError::InvalidCircuit(format!(
                            "input wire {inwire2} does not have a value (in ({gate}))"
                        ))
                    })?;

                    if !wires.insert(*outwire) {
                        return Err(CircuitBuilderError::InvalidCircuit(format!(
                            "output wire {outwire} already has a value (in ({gate}))"
                        )));
                    }
                }
            }
        }

        for id in self.output_wires.iter().flatten() {
            if !wires.contains(id) {
                return Err(CircuitBuilderError::InvalidCircuit(format!(
                    "output wire with id {id} does not have a value"
                )));
            }
        }

        if wires.len() != self.num_wires {
            return Err(CircuitBuilderError::InvalidCircuit(format!(
                "Circuit does not have the correct number of wires: {} specified, {} needed while executing",
                self.num_wires,
                wires.len()
            )));
        }

        let UnverifiedBristolFashionCircuit {
            num_wires: _,
            input_wires,
            output_wires,
            gates,
        } = self;

        Ok(BristolFashionCircuit {
            input_wires,
            output_wires,
            gates,
            num_and_gates,
        })
    }
}
