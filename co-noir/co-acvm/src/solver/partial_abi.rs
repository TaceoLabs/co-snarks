use super::CoSolver;
use crate::mpc::NoirWitnessExtensionProtocol;
use acir::{FieldElement, circuit::PublicInputs, native_types::WitnessMap};
use eyre::eyre;
use noirc_abi::Abi;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// This type is copied from the noirc_abi crate, as it is not public. I just need it to be able to parse input.toml files.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
enum TomlTypes {
    // This is most likely going to be a hex string
    // But it is possible to support UTF-8
    String(String),
    // Just a regular integer, that can fit in 64 bits
    // Note that the toml spec specifies that all numbers are represented as `i64`s.
    Integer(u64),
    // Simple boolean flag
    Bool(bool),
    // Array of TomlTypes
    Array(Vec<TomlTypes>),
    // Struct of TomlTypes
    Table(BTreeMap<String, TomlTypes>),
}

pub enum PublicMarker<F> {
    Public(F),
    Private(F),
}

impl<T> CoSolver<T, ark_bn254::Fr>
where
    T: NoirWitnessExtensionProtocol<ark_bn254::Fr>,
{
    pub(crate) fn create_partial_abi(input_string: &str, abi: &Abi) -> eyre::Result<Abi> {
        let mut res_abi = Abi {
            parameters: Vec::new(),
            return_type: abi.return_type.clone(),
            error_types: BTreeMap::new(),
        };

        // Parse input.toml into a BTreeMap.
        let data: BTreeMap<String, TomlTypes> = toml::from_str(input_string)?;

        // Make a new Abi with only the parameters that are present in the input file.
        for param in abi.parameters.iter() {
            let arg_name = &param.name;
            let value = data.get(arg_name);
            match value {
                Some(_) => {
                    res_abi.parameters.push(param.clone());
                }
                None => {
                    tracing::warn!("Argument {} is missing from the input file", arg_name);
                }
            }
        }

        Ok(res_abi)
    }

    pub(crate) fn create_string_map(
        original_abi: &Abi,
        partial_abi: &Abi,
        witness: WitnessMap<FieldElement>,
        public_parameters: &PublicInputs,
    ) -> eyre::Result<BTreeMap<String, PublicMarker<FieldElement>>> {
        let mut res_map = BTreeMap::new();
        let mut wit_iter = witness.into_iter();

        let mut orig_params = original_abi.parameters.iter();
        let mut offset = 0;

        for param in partial_abi.parameters.iter() {
            let arg_name = &param.name;
            let typ_field_len = param.typ.field_count();

            // Calculate real witness offset for the public parameter marker
            loop {
                let next = orig_params
                    .next()
                    .ok_or(eyre!("Corrupted Witness: Too few witnesses"))?;

                if &next.name == arg_name {
                    break;
                }
                offset += next.typ.field_count();
            }

            for i in 0..typ_field_len {
                let name = if typ_field_len == 1 {
                    arg_name.to_owned()
                } else {
                    format!("{arg_name}[{i}]")
                };

                let (_, el) = wit_iter
                    .next()
                    .ok_or(eyre!("Corrupted Witness: Too few witnesses"))?;
                if public_parameters.contains((offset) as usize) {
                    res_map.insert(name, PublicMarker::Public(el));
                } else {
                    res_map.insert(name, PublicMarker::Private(el));
                }
                offset += 1;
            }
        }
        if wit_iter.next().is_some() {
            eyre::bail!("Corrupted Witness: Too much witnesses");
        }

        Ok(res_map)
    }

    pub fn witness_map_from_string_map<I, O>(
        witness: BTreeMap<String, I>,
        abi: &Abi,
    ) -> eyre::Result<WitnessMap<O>>
    where
        I: Clone,
        O: From<I> + Default,
    {
        let mut result = WitnessMap::default();

        let mut index = 0;
        for params in abi.parameters.iter() {
            let arg_name = &params.name;
            let typ_field_len = params.typ.field_count();
            for i in 0..typ_field_len {
                let should_name = if typ_field_len == 1 {
                    arg_name.to_owned()
                } else {
                    format!("{arg_name}[{i}]")
                };
                let el = witness
                    .get(&should_name)
                    .ok_or(eyre!("Corrupted Witness: Missing witness: {}", should_name))?;

                result.insert(index.into(), O::from(el.to_owned()));
                index += 1;
            }
        }
        if index as usize != witness.len() {
            eyre::bail!("Corrupted Witness: Too many witnesses");
        }

        Ok(result)
    }
}
