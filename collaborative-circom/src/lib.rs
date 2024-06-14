use clap::ValueEnum;

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

impl std::fmt::Display for MPCProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MPCProtocol::REP3 => write!(f, "REP3"),
        }
    }
}
