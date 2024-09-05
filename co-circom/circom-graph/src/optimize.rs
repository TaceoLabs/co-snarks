use crate::{Graph, HashSignalInfo, Node, Operation};

pub struct DepthAwareNode<F> {
    pub node: TypedNode<F>,
    pub depth: usize,
    pub comm_depth: usize,
}

pub struct DepthAwareGraph<F> {
    // node, graph_depth, comm_depth
    pub nodes: Vec<DepthAwareNode<F>>,
    pub signals: Vec<usize>,
    pub input_mapping: Vec<HashSignalInfo>,
    pub node_levels: Vec<Vec<usize>>,
    pub node_comm_levels: Vec<Vec<usize>>,
}

impl<F> From<TypedGraph<F>> for DepthAwareGraph<F> {
    fn from(graph: TypedGraph<F>) -> Self {
        let mut nodes: Vec<DepthAwareNode<F>> = Vec::with_capacity(graph.nodes.len());

        for node in graph.nodes.into_iter() {
            let dnode = match node.node {
                Node::Input(_) | Node::Constant(_) => DepthAwareNode {
                    node: node,
                    depth: 0,
                    comm_depth: 0,
                },
                Node::Op(op, left_idx, right_idx) => {
                    let left_node_depth = nodes[left_idx].depth;
                    let right_node_depth = nodes[right_idx].depth;
                    let left_node_comm_depth = nodes[left_idx].comm_depth;
                    let right_node_comm_depth = nodes[right_idx].comm_depth;
                    let left_type = nodes[left_idx].node.output_type;
                    let right_type = nodes[right_idx].node.output_type;
                    let depth = std::cmp::max(left_node_depth, right_node_depth) + 1;
                    let comm_depth = match op {
                        Operation::Mul => {
                            if left_type == Type::Public || right_type == Type::Public {
                                std::cmp::max(left_node_comm_depth, right_node_comm_depth)
                            } else {
                                std::cmp::max(left_node_comm_depth, right_node_comm_depth) + 1
                            }
                        }
                        Operation::Add | Operation::Sub => {
                            std::cmp::max(left_node_comm_depth, right_node_comm_depth)
                        }
                        Operation::Eq
                        | Operation::Neq
                        | Operation::Lt
                        | Operation::Gt
                        | Operation::Leq
                        | Operation::Geq => {
                            // TODO: comm depth for comparison
                            std::cmp::max(left_node_comm_depth, right_node_comm_depth) + 1
                        }
                        Operation::Lor => {
                            // TODO: Comm depth for OR
                            std::cmp::max(left_node_comm_depth, right_node_comm_depth) + 1
                        }
                        Operation::Shl => {
                            // TODO: Comm depth for shift
                            std::cmp::max(left_node_comm_depth, right_node_comm_depth) + 1
                        }
                        Operation::Shr => {
                            // TODO: Comm depth for shift
                            std::cmp::max(left_node_comm_depth, right_node_comm_depth) + 1
                        }
                        Operation::Band => {
                            // TODO: comm depth for AND
                            std::cmp::max(left_node_comm_depth, right_node_comm_depth) + 1
                        }
                    };
                    DepthAwareNode {
                        node: node,
                        depth: depth,
                        comm_depth: comm_depth,
                    }
                }
            };
            nodes.push(dnode);
        }
        let max_depth = nodes.iter().map(|x| x.depth).max().unwrap_or(0);
        let max_comm_depth = nodes.iter().map(|x| x.comm_depth).max().unwrap_or(0);

        let mut node_levels: Vec<Vec<usize>> = vec![Vec::new(); max_depth + 1];
        let mut node_comm_levels: Vec<Vec<usize>> = vec![Vec::new(); max_comm_depth + 1];

        for (i, node) in nodes.iter().enumerate() {
            node_levels[node.depth].push(i);
            node_comm_levels[node.comm_depth].push(i);
        }

        Self {
            nodes,
            signals: graph.signals,
            input_mapping: graph.input_mapping,
            node_levels,
            node_comm_levels,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Public,
    SecretArith,
    SecretBin,
}

pub struct TypedNode<F> {
    pub node: Node<F>,
    pub output_type: Type,
}

pub struct TypedGraph<F> {
    pub nodes: Vec<TypedNode<F>>,
    pub signals: Vec<usize>,
    pub input_mapping: Vec<HashSignalInfo>,
}

impl<F> From<Graph<F>> for TypedGraph<F> {
    fn from(graph: Graph<F>) -> Self {
        let mut nodes: Vec<TypedNode<F>> = Vec::with_capacity(graph.nodes.len());
        for node in graph.nodes.into_iter() {
            let typed_node = match node {
                Node::Input(i) => TypedNode {
                    node: Node::Input(i),
                    output_type: Type::SecretArith,
                },
                Node::Constant(c) => TypedNode {
                    node: Node::Constant(c),
                    output_type: Type::Public,
                },
                Node::Op(op, left, right) => {
                    let left_type = nodes[left].output_type;
                    let right_type = nodes[right].output_type;

                    // some typechecking:
                    match op {
                        Operation::Shl | Operation::Shr => {
                            assert_eq!(right_type, Type::Public, "Shift amount must be public");
                        }
                        _ => {}
                    }

                    TypedNode {
                        node: Node::Op(op, left, right),
                        output_type: match (left_type, right_type) {
                            (Type::Public, Type::Public) => Type::Public,
                            (Type::SecretArith, Type::SecretArith) => Type::SecretArith,
                            (Type::Public, Type::SecretArith) => Type::SecretArith,
                            (Type::SecretArith, Type::Public) => Type::SecretArith,
                            (Type::SecretBin, Type::SecretBin) => Type::SecretBin,
                            (Type::SecretBin, Type::Public) => Type::SecretBin,
                            (Type::Public, Type::SecretBin) => Type::SecretBin,
                            _ => panic!("Type mismatch in operation"),
                        },
                    }
                }
            };
            nodes.push(typed_node);
        }

        Self {
            nodes,
            signals: graph.signals,
            input_mapping: graph.input_mapping,
        }
    }
}
