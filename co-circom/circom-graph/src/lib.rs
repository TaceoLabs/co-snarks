use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
pub use witness::HashSignalInfo;

pub mod executor;
pub mod optimize;

#[derive(Hash, PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Operation {
    Mul,
    Add,
    Sub,
    Eq,
    Neq,
    Lt,
    Gt,
    Leq,
    Geq,
    Lor,
    Shl,
    Shr,
    Band,
}

impl From<witness::graph::Operation> for Operation {
    fn from(value: witness::graph::Operation) -> Self {
        match value {
            witness::graph::Operation::Mul => Operation::Mul,
            witness::graph::Operation::MMul => todo!(),
            witness::graph::Operation::Add => Operation::Add,
            witness::graph::Operation::Sub => Operation::Sub,
            witness::graph::Operation::Eq => Operation::Eq,
            witness::graph::Operation::Neq => Operation::Neq,
            witness::graph::Operation::Lt => Operation::Lt,
            witness::graph::Operation::Gt => Operation::Gt,
            witness::graph::Operation::Leq => Operation::Leq,
            witness::graph::Operation::Geq => Operation::Geq,
            witness::graph::Operation::Lor => Operation::Lor,
            witness::graph::Operation::Shl => Operation::Shl,
            witness::graph::Operation::Shr => Operation::Shr,
            witness::graph::Operation::Band => Operation::Band,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Node<F> {
    Input(usize),
    Constant(F),
    Op(Operation, usize, usize),
}

impl From<witness::graph::Node> for Node<ark_bn254::Fr> {
    fn from(value: witness::graph::Node) -> Self {
        match value {
            witness::graph::Node::Input(i) => Node::Input(i),
            witness::graph::Node::Constant(c) => {
                Node::Constant(ark_bn254::Fr::from_le_bytes_mod_order(c.as_le_slice()))
            }
            witness::graph::Node::MontConstant(c) => Node::Constant(c),
            witness::graph::Node::Op(op, left_idx, right_idx) => {
                Node::Op(Operation::from(op), left_idx, right_idx)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graph<F> {
    pub nodes: Vec<Node<F>>,
    pub signals: Vec<usize>,
    pub input_mapping: Vec<HashSignalInfo>,
}

impl From<witness::Graph> for Graph<ark_bn254::Fr> {
    fn from(value: witness::Graph) -> Self {
        Graph {
            nodes: value.nodes.into_iter().map(Node::from).collect(),
            signals: value.signals,
            input_mapping: value.input_mapping,
        }
    }
}
