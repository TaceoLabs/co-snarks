use std::path::{Path, PathBuf};

use ark_ff::PrimeField;
use color_eyre::eyre::{self, Context, ContextCompat};
use num_bigint::BigUint;
use num_traits::Num;

/// An error type for file utility functions.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file was not found.
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
    /// The directory was not found.
    #[error("Dir not found: {0}")]
    DirNotFound(PathBuf),
    /// The path was expected to be a directory, but it is a file.
    #[error("Expected {0} to be a directory, but it is a file.")]
    ExpectedDir(PathBuf),
    /// The path was expected to be a file, but it is a directory.
    #[error("Expected {0} to be a file, but it is a directory.")]
    ExpectedFile(PathBuf),
    /// An I/O error occurred.
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// Check if a file exists at the given path, and is actually a file.
pub fn check_file_exists(file_path: &Path) -> Result<(), Error> {
    if !file_path.exists() {
        return Err(Error::FileNotFound(file_path.to_path_buf()));
    }
    if !file_path.is_file() {
        return Err(Error::ExpectedFile(file_path.to_path_buf()));
    }
    Ok(())
}

/// Check if a directory exists at the given path, and is actually a directory.
pub fn check_dir_exists(dir_path: &Path) -> Result<(), Error> {
    if !dir_path.exists() {
        return Err(Error::DirNotFound(dir_path.to_path_buf()));
    }
    if !dir_path.is_dir() {
        return Err(Error::ExpectedDir(dir_path.to_path_buf()));
    }
    Ok(())
}

pub(crate) fn parse_field<F>(val: &serde_json::Value) -> color_eyre::Result<F>
where
    F: std::str::FromStr + PrimeField,
{
    let s = val.as_str().ok_or_else(|| {
        eyre::eyre!(
            "expected input to be a field element string, got \"{}\"",
            val
        )
    })?;
    let (is_negative, stripped) = if let Some(stripped) = s.strip_prefix('-') {
        (true, stripped)
    } else {
        (false, s)
    };
    let positive_value = if let Some(stripped) = stripped.strip_prefix("0x") {
        let mut big_int = BigUint::from_str_radix(stripped, 16)
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?;
        let modulus = BigUint::try_from(F::MODULUS).expect("can convert mod to biguint");
        if big_int >= modulus {
            tracing::warn!("val {} >= mod", big_int);
            // snarkjs also does this
            big_int %= modulus;
        }
        let big_int: F::BigInt = big_int
            .try_into()
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?;
        F::from(big_int)
    } else {
        stripped
            .parse::<F>()
            .map_err(|_| eyre::eyre!("could not parse field element: \"{}\"", val))
            .context("while parsing field element")?
    };
    if is_negative {
        Ok(-positive_value)
    } else {
        Ok(positive_value)
    }
}

pub(crate) fn parse_array<F: PrimeField>(val: &serde_json::Value) -> color_eyre::Result<Vec<F>> {
    let json_arr = val.as_array().expect("is an array");
    let mut field_elements = vec![];
    for ele in json_arr {
        if ele.is_array() {
            field_elements.extend(parse_array::<F>(ele)?);
        } else if ele.is_boolean() {
            field_elements.push(parse_boolean(ele)?);
        } else {
            field_elements.push(parse_field(ele)?);
        }
    }
    Ok(field_elements)
}

pub(crate) fn parse_boolean<F: PrimeField>(val: &serde_json::Value) -> color_eyre::Result<F> {
    let bool = val
        .as_bool()
        .with_context(|| format!("expected input to be a bool, got {val}"))?;
    if bool {
        Ok(F::ONE)
    } else {
        Ok(F::ZERO)
    }
}
