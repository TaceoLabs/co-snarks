use super::CoSolver;
use mpc_core::traits::NoirWitnessExtensionProtocol;
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
}
