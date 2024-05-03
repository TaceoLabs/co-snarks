use std::error::Error;

/// An enum representing the party ID
#[derive(std::cmp::Eq, std::cmp::PartialEq, Clone, Copy, Debug)]
pub enum PartyID {
    /// Party 0
    ID0 = 0,
    /// Party 1
    ID1 = 1,
    /// Party 2
    ID2 = 2,
}

#[derive(Debug)]
pub struct InvalidPartyId(usize);

impl std::fmt::Display for InvalidPartyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid party ID: {}, expected (0,1,2)", self.0)
    }
}

impl Error for InvalidPartyId {}

impl PartyID {
    /// get next ID
    pub fn next_id(&self) -> Self {
        match *self {
            PartyID::ID0 => PartyID::ID1,
            PartyID::ID1 => PartyID::ID2,
            PartyID::ID2 => PartyID::ID0,
        }
    }

    /// get previous ID
    pub fn prev_id(&self) -> Self {
        match *self {
            PartyID::ID0 => PartyID::ID2,
            PartyID::ID1 => PartyID::ID0,
            PartyID::ID2 => PartyID::ID1,
        }
    }
}

impl TryFrom<usize> for PartyID {
    type Error = InvalidPartyId;

    fn try_from(other: usize) -> Result<Self, Self::Error> {
        match other {
            0 => Ok(PartyID::ID0),
            1 => Ok(PartyID::ID1),
            2 => Ok(PartyID::ID2),
            i => Err(InvalidPartyId(i)),
        }
    }
}

impl TryFrom<u8> for PartyID {
    type Error = InvalidPartyId;

    #[inline(always)]
    fn try_from(other: u8) -> Result<Self, Self::Error> {
        (other as usize).try_into()
    }
}

impl From<PartyID> for usize {
    #[inline(always)]
    fn from(other: PartyID) -> Self {
        other as usize
    }
}

impl std::fmt::Display for PartyID {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as usize)
    }
}
