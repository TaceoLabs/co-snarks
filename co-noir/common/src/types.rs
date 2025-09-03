#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZeroKnowledge {
    No,
    Yes,
}

impl From<bool> for ZeroKnowledge {
    fn from(value: bool) -> Self {
        if value {
            ZeroKnowledge::Yes
        } else {
            ZeroKnowledge::No
        }
    }
}
