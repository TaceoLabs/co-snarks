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

pub struct RelationParameters<F> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
    pub public_input_delta: F,
}
