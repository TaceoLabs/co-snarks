#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

#[derive(Default)]
pub struct RelationParameters<F: Default> {
    pub eta_1: F,
    pub eta_2: F,
    pub eta_3: F,
    pub beta: F,
    pub gamma: F,
    pub public_input_delta: F,
}

pub type Bn254G1 = <ark_ec::bn::Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::G1;
