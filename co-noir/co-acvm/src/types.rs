use std::{collections::BTreeMap, fmt::Display, path::PathBuf};

use acir::{native_types::Witness, FieldElement};
use eyre::{bail, Ok};
use noirc_abi::{input_parser::Format, Abi, MAIN_RETURN_NAME};

#[derive(Default, Debug)]
pub struct CoWitnessMap<T: Clone> {
    // we maybe switch the internal working from the witness map. For now take the same as ACVM
    witnesses: BTreeMap<Witness, WitnessState<T>>,
}

//remove me this is just for the time being
pub struct FullWitness<T>(pub(crate) Vec<T>);

impl<T: Clone> TryFrom<CoWitnessMap<T>> for FullWitness<T> {
    type Error = eyre::Error;

    fn try_from(value: CoWitnessMap<T>) -> Result<Self, Self::Error> {
        let mut vec = Vec::with_capacity(value.witnesses.len());
        // This assumes we have an order of the CoWitnessMap. Atm we have BTreeMap which
        // has an order. If we change impl, we need to change that
        for witness in value.witnesses.into_values() {
            match witness {
                WitnessState::Known(witness) => vec.push(witness),
                WitnessState::Unknown => {
                    bail!("cannot build FullWitness from not solved CoWitnessMap")
                }
            }
        }
        Ok(Self(vec))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum WitnessState<T: Clone> {
    Known(T),
    Unknown,
}

impl<T: Clone> Default for WitnessState<T> {
    fn default() -> Self {
        Self::Unknown
    }
}

impl<T: Clone + Default> CoWitnessMap<T>
where
    T: From<FieldElement> + Clone + Default,
{
    pub fn read_abi<P>(path: P, abi: &Abi) -> eyre::Result<Self>
    where
        PathBuf: From<P>,
    {
        if abi.is_empty() {
            Ok(Self::default())
        } else {
            let input_string = std::fs::read_to_string(PathBuf::from(path))?;
            let mut input_map = Format::Toml.parse(&input_string, abi)?;
            let return_value = input_map.remove(MAIN_RETURN_NAME);
            // TODO the return value can be none for the witness extension
            // do we want to keep it like that? Seems not necessary but maybe
            // we need it for proving/verifiying
            let initial_witness = abi.encode(&input_map, return_value.clone())?;
            let mut witnesses = Self::default();
            for (witness, v) in initial_witness.into_iter() {
                witnesses.insert(&witness, T::from(v));
            }
            Ok(witnesses)
        }
    }
}

impl<T: Clone + Default> CoWitnessMap<T> {
    pub(super) fn get(&mut self, witness: &Witness) -> WitnessState<T> {
        match self.witnesses.get(witness) {
            Some(value) => value.clone(),
            None => WitnessState::Unknown,
        }
    }

    pub(super) fn insert(&mut self, witness: &Witness, value: T) {
        debug_assert!(
            self.is_unknown(witness),
            "witness must be unknown if you want to set"
        );
        self.witnesses.insert(*witness, WitnessState::Known(value));
    }

    pub(super) fn is_unknown(&self, witness: &Witness) -> bool {
        if let Some(value) = self.witnesses.get(witness) {
            matches!(value, WitnessState::Unknown)
        } else {
            true
        }
    }
}

impl<T: Clone + Display> std::fmt::Display for WitnessState<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessState::Known(v) => f.write_str(&format!("{v}")),
            WitnessState::Unknown => f.write_str("UNKNOWN"),
        }
    }
}

impl<T: Clone + Display> std::fmt::Display for CoWitnessMap<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WitnessMap: [")?;
        let string = self
            .witnesses
            .iter()
            .map(|(k, v)| format!("({}: {v})", k.0))
            .reduce(|x, y| format!("{x}, {y}"))
            .unwrap_or_default();
        f.write_str(&string)?;
        f.write_str("]")
    }
}
