use std::str::FromStr;

use clap::ValueEnum;
use color_eyre::eyre::{eyre, Report};

pub mod file_utils;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MPCProtocol {
    REP3,
}

impl ValueEnum for MPCProtocol {
    fn value_variants<'a>() -> &'a [Self] {
        &[MPCProtocol::REP3]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            MPCProtocol::REP3 => Some(clap::builder::PossibleValue::new("REP3")),
        }
    }
}

impl FromStr for MPCProtocol {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "REP3" => Ok(MPCProtocol::REP3),
            _ => Err(eyre!("Unsupported MPC protocol: {}", s)),
        }
    }
}

impl std::fmt::Display for MPCProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MPCProtocol::REP3 => write!(f, "REP3"),
        }
    }
}
