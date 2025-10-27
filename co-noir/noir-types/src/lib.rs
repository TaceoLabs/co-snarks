use std::{collections::BTreeMap, io};

use acir::FieldElement;
use acir::native_types::{WitnessMap, WitnessStack};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use co_noir_types::PubPrivate;
use noirc_abi::errors::InputParserError;
use noirc_abi::input_parser::json::JsonTypes;
use noirc_abi::input_parser::{Format, InputValue};

pub use noirc_abi::Abi;
use noirc_abi::MAIN_RETURN_NAME;
pub use noirc_artifacts::program::ProgramArtifact;
use num_bigint::BigUint;
use ruint::Uint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof<F: Default> {
    proof: Vec<F>,
}

pub enum HonkProofType {
    FieldElements(HonkProof<ark_bn254::Fr>, Vec<ark_bn254::Fr>),
    U256Values(HonkProof<U256>, Vec<U256>),
}

impl HonkProofType {
    pub fn public_inputs_to_buffer(&self) -> Vec<u8> {
        match self {
            HonkProofType::FieldElements(_, public_inputs) => {
                SerializeF::to_buffer(public_inputs, false)
            }
            HonkProofType::U256Values(_, public_inputs) => U256::to_buffer(public_inputs),
        }
    }
    pub fn proof_to_buffer(&self) -> Vec<u8> {
        match self {
            HonkProofType::FieldElements(proof, _) => proof.to_buffer(),
            HonkProofType::U256Values(proof, _) => proof.to_buffer(),
        }
    }
    pub fn proof_and_public_inputs_from_buffer_field(
        buf_proof: &[u8],
        buf_public_inputs: &[u8],
    ) -> eyre::Result<HonkProofType> {
        let proof = HonkProof::<ark_bn254::Fr>::from_buffer(buf_proof)?;
        let public_inputs = SerializeF::from_buffer(buf_public_inputs, false)?;
        Ok(HonkProofType::FieldElements(proof, public_inputs))
    }

    pub fn proof_and_public_inputs_from_buffer_u256(
        buf_proof: &[u8],
        buf_public_inputs: &[u8],
    ) -> eyre::Result<HonkProofType> {
        let proof = HonkProof::<U256>::from_buffer(buf_proof)?;
        let public_inputs = U256::from_buffer(buf_public_inputs);
        Ok(HonkProofType::U256Values(proof, public_inputs))
    }

    pub fn proof_to_strings(&self) -> Vec<String> {
        match self {
            HonkProofType::FieldElements(proof, _) => proof
                .proof
                .iter()
                .map(|el| {
                    if el.is_zero() {
                        "0".to_string()
                    } else {
                        el.to_string()
                    }
                })
                .collect(),
            HonkProofType::U256Values(proof, _) => proof
                .proof
                .iter()
                .map(|el| {
                    if el.0.is_zero() {
                        "0".to_string()
                    } else {
                        el.0.to_string()
                    }
                })
                .collect(),
        }
    }
    pub fn public_inputs_to_strings(&self) -> Vec<String> {
        match self {
            HonkProofType::FieldElements(_, public_inputs) => public_inputs
                .iter()
                .map(|el| {
                    if el.is_zero() {
                        "0".to_string()
                    } else {
                        el.to_string()
                    }
                })
                .collect(),
            HonkProofType::U256Values(_, public_inputs) => public_inputs
                .iter()
                .map(|el| {
                    if el.0.is_zero() {
                        "0".to_string()
                    } else {
                        el.0.to_string()
                    }
                })
                .collect(),
        }
    }
    pub fn proof_and_public_inputs_from_string_field(
        str_proof: Vec<String>,
        str_public_inputs: Vec<String>,
    ) -> eyre::Result<HonkProofType> {
        let proof = HonkProof::<ark_bn254::Fr>::new(
            str_proof
                .into_iter()
                .map(|s| s.parse::<ark_bn254::Fr>().unwrap())
                .collect(),
        );
        let public_inputs = str_public_inputs
            .into_iter()
            .map(|s| s.parse::<ark_bn254::Fr>().unwrap())
            .collect();
        Ok(HonkProofType::FieldElements(proof, public_inputs))
    }
    pub fn proof_and_public_inputs_from_string_u256(
        str_proof: Vec<String>,
        str_public_inputs: Vec<String>,
    ) -> eyre::Result<HonkProofType> {
        let proof = HonkProof::<U256>::new(
            str_proof
                .into_iter()
                .map(|s| U256(Uint::<256, 4>::from(s.parse::<u128>().unwrap())))
                .collect(),
        );
        let public_inputs = str_public_inputs
            .into_iter()
            .map(|s| U256(Uint::<256, 4>::from(s.parse::<u128>().unwrap())))
            .collect();
        Ok(HonkProofType::U256Values(proof, public_inputs))
    }
}

impl<F: Default + Clone> HonkProof<F> {
    pub fn new(proof: Vec<F>) -> Self {
        Self { proof }
    }

    pub fn inner(self) -> Vec<F> {
        self.proof
    }
    pub fn insert_public_inputs(self, public_inputs: Vec<F>) -> Self {
        let mut proof = public_inputs;
        proof.extend(self.proof);
        Self::new(proof)
    }
    pub fn separate_proof_and_public_inputs(self, num_public_inputs: usize) -> (Self, Vec<F>) {
        let (public_inputs, proof) = self.proof.split_at(num_public_inputs);
        (Self::new(proof.to_vec()), public_inputs.to_vec())
    }
}

impl<F: PrimeField> HonkProof<F> {
    pub fn to_buffer(&self) -> Vec<u8> {
        SerializeF::to_buffer(&self.proof, false)
    }

    pub fn from_buffer(buf: &[u8]) -> eyre::Result<Self> {
        let res = SerializeF::from_buffer(buf, false)?;
        Ok(Self::new(res))
    }
}

impl HonkProof<U256> {
    pub fn to_buffer(&self) -> Vec<u8> {
        self.proof
            .iter()
            .flat_map(|el| el.0.to_be_bytes::<32>().to_vec())
            .collect::<Vec<u8>>()
    }

    pub fn from_buffer(buf: &[u8]) -> eyre::Result<Self> {
        let res = buf
            .chunks(32)
            .map(|chunk| {
                U256(Uint::<256, 4>::from_be_bytes::<32>(
                    chunk.try_into().expect("Chunk should be 32 bytes"),
                ))
            })
            .collect::<Vec<U256>>();
        Ok(Self::new(res))
    }
}

pub struct SerializeF<F: Field> {
    phantom: std::marker::PhantomData<F>,
}

impl<F: Field> SerializeF<F> {
    const NUM_64_LIMBS: u32 = <F::BasePrimeField as PrimeField>::MODULUS_BIT_SIZE.div_ceil(64);
    const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;
    const VEC_LEN_BYTES: u32 = 4;

    // TODO maybe change to impl Read?
    pub fn from_buffer(buf: &[u8], size_included: bool) -> eyre::Result<Vec<F>> {
        let size = buf.len();
        let mut offset = 0;

        // Check sizes
        let num_elements = if size_included {
            let num_elements =
                (size - Self::VEC_LEN_BYTES as usize) / Self::FIELDSIZE_BYTES as usize;
            if num_elements * Self::FIELDSIZE_BYTES as usize + Self::VEC_LEN_BYTES as usize != size
            {
                eyre::bail!("invalid length");
            }

            let read_num_elements = Self::read_u32(buf, &mut offset);
            if read_num_elements != num_elements as u32 {
                eyre::bail!("invalid length");
            }
            num_elements
        } else {
            let num_elements = size / Self::FIELDSIZE_BYTES as usize;
            if num_elements * Self::FIELDSIZE_BYTES as usize != size {
                eyre::bail!("invalid length");
            }
            num_elements
        };

        // Read data
        let mut res = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            res.push(Self::read_field_element(buf, &mut offset));
        }
        debug_assert_eq!(offset, size);
        Ok(res)
    }

    pub(crate) fn field_size() -> usize {
        Self::FIELDSIZE_BYTES as usize * F::extension_degree() as usize
    }

    pub fn to_buffer(buf: &[F], include_size: bool) -> Vec<u8> {
        let total_size = buf.len() as u32 * Self::field_size() as u32
            + if include_size { Self::VEC_LEN_BYTES } else { 0 };

        let mut res = Vec::with_capacity(total_size as usize);
        if include_size {
            Self::write_u32(&mut res, buf.len() as u32);
        }
        for el in buf.iter().cloned() {
            Self::write_field_element(&mut res, el);
        }
        debug_assert_eq!(res.len(), total_size as usize);
        res
    }

    pub fn read_u32(buf: &[u8], offset: &mut usize) -> u32 {
        const BYTES: usize = 4;
        let res = u32::from_be_bytes(buf[*offset..*offset + BYTES].try_into().unwrap());
        *offset += BYTES;
        res
    }

    pub fn read_u64(buf: &[u8], offset: &mut usize) -> u64 {
        const BYTES: usize = 8;
        let res = u64::from_be_bytes(buf[*offset..*offset + BYTES].try_into().unwrap());
        *offset += BYTES;
        res
    }

    pub fn read_biguint(buf: &[u8], num_64_limbs: usize, offset: &mut usize) -> BigUint {
        let mut bigint = BigUint::default();
        for _ in 0..num_64_limbs {
            let data = Self::read_u64(buf, offset);
            bigint <<= 64;
            bigint += data;
        }
        bigint
    }

    pub fn write_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend(val.to_be_bytes());
    }

    pub fn write_u64(buf: &mut Vec<u8>, val: u64) {
        buf.extend(val.to_be_bytes());
    }

    pub fn write_field_element(buf: &mut Vec<u8>, el: F) {
        let prev_len = buf.len();
        for el in el.to_base_prime_field_elements() {
            let el = el.into_bigint(); // Gets rid of montgomery form

            for data in el.as_ref().iter().rev().cloned() {
                Self::write_u64(buf, data);
            }

            debug_assert_eq!(
                buf.len() - prev_len,
                Self::FIELDSIZE_BYTES as usize * F::extension_degree() as usize
            );
        }
    }

    pub fn read_field_element(buf: &[u8], offset: &mut usize) -> F {
        let mut fields = Vec::with_capacity(F::extension_degree() as usize);

        for _ in 0..F::extension_degree() {
            let mut bigint: BigUint = Default::default();
            for _ in 0..Self::NUM_64_LIMBS {
                let data = Self::read_u64(buf, offset);
                bigint <<= 64;
                bigint += data;
            }
            fields.push(F::BasePrimeField::from(bigint));
        }

        F::from_base_prime_field_elems(fields).expect("Should work")
    }
}

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
    WitnessStack::deserialize(witness_stack.as_slice())
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct U256(pub Uint<256, 4>);

impl From<u32> for U256 {
    fn from(v: u32) -> Self {
        U256(Uint::<256, 4>::from(v))
    }
}
impl From<u64> for U256 {
    fn from(v: u64) -> Self {
        U256(Uint::<256, 4>::from(v))
    }
}

impl U256 {
    pub fn convert_field_into<F: PrimeField>(element: &F) -> Self {
        let bytes = element.into_bigint().to_bytes_be();
        let mut padded_bytes = [0u8; 32];
        let start = 32 - bytes.len();
        padded_bytes[start..].copy_from_slice(&bytes);
        U256(Uint::<256, 4>::from_be_bytes(padded_bytes))
    }

    pub fn slice(&self, start: u64, end: u64) -> Self {
        let range = end - start;
        let mask = if range == 256 {
            Uint::<256, 4>::MAX
        } else {
            (Uint::<256, 4>::from(1u8) << range) - Uint::<256, 4>::from(1u8)
        };
        U256((self.0 >> start) & mask)
    }

    pub fn to_buffer(inp: &[Self]) -> Vec<u8> {
        inp.iter()
            .flat_map(|el| el.0.to_be_bytes::<32>().to_vec())
            .collect::<Vec<u8>>()
    }
    pub fn from_buffer(buffer: &[u8]) -> Vec<Self> {
        buffer
            .chunks(32)
            .map(|chunk| {
                U256(Uint::<256, 4>::from_be_bytes::<32>(
                    chunk.try_into().expect("Chunk should be 32 bytes"),
                ))
            })
            .collect::<Vec<U256>>()
    }
}
