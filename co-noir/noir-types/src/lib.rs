use std::{collections::BTreeMap, io};

use acir::FieldElement;
use acir::native_types::{WitnessMap, WitnessStack};
use ark_ff::Zero;
use co_noir_types::PubPrivate;
use noirc_abi::errors::InputParserError;
use noirc_abi::input_parser::json::JsonTypes;
use noirc_abi::input_parser::{Format, InputValue};

pub use noirc_abi::Abi;
use noirc_abi::MAIN_RETURN_NAME;
pub use noirc_artifacts::program::ProgramArtifact;

/// A map from of fields which correspond to some ABI to their values
pub type Input = serde_json::Map<String, serde_json::Value>;

fn create_string_map(
    original_abi: &Abi,
    partial_abi: &Abi,
    witness: WitnessMap<FieldElement>,
    public_parameters: &[u32],
) -> eyre::Result<BTreeMap<String, PubPrivate<ark_bn254::Fr>>> {
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
                .ok_or_else(|| eyre::eyre!("Corrupted Witness: Too few witnesses"))?;

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
                .ok_or_else(|| eyre::eyre!("Corrupted Witness: Too few witnesses"))?;
            if public_parameters.contains(&offset) {
                res_map.insert(name, PubPrivate::Public(el.into_repr()));
            } else {
                res_map.insert(name, PubPrivate::Private(el.into_repr()));
            }
            offset += 1;
        }
    }
    if wit_iter.next().is_some() {
        eyre::bail!("Corrupted Witness: Too much witnesses");
    }

    Ok(res_map)
}

fn create_partial_abi(inputs: Vec<&String>, abi: &Abi) -> eyre::Result<Abi> {
    let mut res_abi = Abi {
        parameters: Vec::new(),
        return_type: abi.return_type.clone(),
        error_types: BTreeMap::new(),
    };

    // Make a new Abi with only the parameters that are present in the input file.
    for param in abi.parameters.iter() {
        let arg_name = &param.name;
        if inputs.contains(&arg_name) {
            res_abi.parameters.push(param.clone());
        }
    }

    Ok(res_abi)
}

fn json_type_from_value(value: serde_json::Value) -> eyre::Result<JsonTypes> {
    match value {
        serde_json::Value::String(s) => Ok(JsonTypes::String(s)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(JsonTypes::Integer(i))
            } else if let Some(u) = n.as_u64() {
                Ok(JsonTypes::Integer(u as i64))
            } else {
                // If the number is too large, we will not be able to parse it as an i64
                // and will need to handle it as a string.
                Ok(JsonTypes::String(n.to_string()))
            }
        }
        serde_json::Value::Bool(b) => Ok(JsonTypes::Bool(b)),
        serde_json::Value::Array(arr) => Ok(JsonTypes::Array(
            arr.into_iter()
                .map(json_type_from_value)
                .collect::<eyre::Result<Vec<_>>>()?,
        )),
        serde_json::Value::Object(obj) => Ok(JsonTypes::Table(
            obj.into_iter()
                .map(|(k, v)| eyre::Ok((k, json_type_from_value(v)?)))
                .collect::<eyre::Result<BTreeMap<String, _>>>()?,
        )),
        x => eyre::bail!("Unsupported JSON type: {x}"),
    }
}

fn parse_json(
    input: BTreeMap<String, serde_json::Value>,
    abi: &Abi,
) -> eyre::Result<BTreeMap<String, InputValue>> {
    let json_inputs = input
        .into_iter()
        .map(|(k, v)| eyre::Ok((k, json_type_from_value(v)?)))
        .collect::<eyre::Result<BTreeMap<String, _>>>()?;

    // Convert arguments to field elements.
    let mut parsed_inputs = abi
        .to_btree_map()
        .into_iter()
        .map(|(arg_name, abi_type)| {
            // Check that json contains a value for each argument in the ABI.
            let value = json_inputs
                .get(&arg_name)
                .ok_or_else(|| InputParserError::MissingArgument(arg_name.clone()))?;

            InputValue::try_from_json(value.clone(), &abi_type, &arg_name)
                .map(|input_value| (arg_name, input_value))
        })
        .collect::<Result<BTreeMap<String, InputValue>, InputParserError>>()?;

    // If the json file also includes a return value then we parse it as well.
    // This isn't required as the prover calculates the return value itself.
    if let (Some(return_type), Some(json_return_value)) =
        (&abi.return_type, json_inputs.get(MAIN_RETURN_NAME))
    {
        let return_value = InputValue::try_from_json(
            json_return_value.clone(),
            &return_type.abi_type,
            MAIN_RETURN_NAME,
        )?;
        parsed_inputs.insert(MAIN_RETURN_NAME.to_owned(), return_value);
    }

    Ok(parsed_inputs)
}

pub fn partial_abi_bn254_from_json(
    input: BTreeMap<String, serde_json::Value>,
    abi: &Abi,
    public_parameters: &[u32],
) -> eyre::Result<BTreeMap<String, PubPrivate<ark_bn254::Fr>>> {
    if abi.is_empty() {
        Ok(BTreeMap::default())
    } else {
        let abi_ = create_partial_abi(input.keys().collect(), abi)?;
        let mut parsed_inputs = parse_json(input, &abi_)?;
        let return_value = parsed_inputs.remove(MAIN_RETURN_NAME);
        let encoded = abi_.encode(&parsed_inputs, return_value)?;
        Ok(create_string_map(abi, &abi_, encoded, public_parameters)?)
    }
}

pub fn partially_read_abi_bn254(
    mut reader: impl io::Read,
    abi: &Abi,
    public_parameters: &[u32],
) -> eyre::Result<BTreeMap<String, PubPrivate<ark_bn254::Fr>>> {
    if abi.is_empty() {
        Ok(BTreeMap::default())
    } else {
        let mut input_string = String::new();
        reader.read_to_string(&mut input_string)?;
        // Parse input.toml into a BTreeMap.
        let data: BTreeMap<String, toml::Value> = toml::from_str(&input_string)?;
        let abi_ = create_partial_abi(data.keys().collect(), abi)?;
        let mut parsed_inputs = Format::Toml.parse(&input_string, &abi_)?;
        let return_value = parsed_inputs.remove(MAIN_RETURN_NAME);
        let encoded = abi_.encode(&parsed_inputs, return_value)?;
        Ok(create_string_map(abi, &abi_, encoded, public_parameters)?)
    }
}

pub fn read_abi_bn254_fieldelement(
    mut reader: impl io::Read,
    abi: &Abi,
) -> eyre::Result<WitnessMap<FieldElement>> {
    if abi.is_empty() {
        Ok(WitnessMap::default())
    } else {
        let mut input_string = String::new();
        reader.read_to_string(&mut input_string)?;
        let mut input_map = Format::Toml.parse(&input_string, abi)?;
        let return_value = input_map.remove(MAIN_RETURN_NAME);
        // TACEO TODO the return value can be none for the witness extension
        // do we want to keep it like that? Seems not necessary but maybe
        // we need it for proving/verifying
        Ok(abi.encode(&input_map, return_value.clone())?)
    }
}

fn witness_stack_from_reader(mut reader: impl io::Read) -> io::Result<WitnessStack<FieldElement>> {
    let mut witness_stack = Vec::new();
    reader.read_to_end(&mut witness_stack)?;
    WitnessStack::try_from(witness_stack.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn witness_map_to_witness_vector(witness_map: WitnessMap<FieldElement>) -> Vec<ark_bn254::Fr> {
    let mut wv = Vec::new();
    let mut index = 0;
    for (w, f) in witness_map.into_iter() {
        // ACIR uses a sparse format for WitnessMap where unused witness indices may be left unassigned.
        // To ensure that witnesses sit at the correct indices in the `WitnessVector`, we fill any indices
        // which do not exist within the `WitnessMap` with the dummy value of zero.
        while index < w.0 {
            wv.push(ark_bn254::Fr::zero());
            index += 1;
        }
        wv.push(f.into_repr());
        index += 1;
    }
    wv
}

pub fn witness_from_reader(reader: impl io::Read) -> io::Result<Vec<ark_bn254::Fr>> {
    let mut witness_stack = witness_stack_from_reader(reader)?;
    let witness_map = witness_stack
        .pop()
        .expect("Witness should be present")
        .witness;
    let witness = witness_map_to_witness_vector(witness_map);
    Ok(witness)
}

pub fn program_artifact_from_reader(reader: impl io::Read) -> io::Result<ProgramArtifact> {
    Ok(serde_json::from_reader::<_, ProgramArtifact>(reader)?)
}
