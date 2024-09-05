use std::sync::Arc;

use ark_ff::PrimeField;
use eyre::Report;
use mpc_core::protocols::rep3::{network::Rep3MpcNet, witness_extension_impl::Rep3VmType};
use num_bigint::BigUint;
use tokio::task::JoinSet;

use crate::{optimize::DepthAwareGraph, Node, Operation};
pub struct GraphExecutionError;

pub struct GraphExecutionEngine<E, F> {
    driver: E,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField, E: GraphExecutor<F>> GraphExecutionEngine<E, F> {
    pub fn new(driver: E) -> Self {
        Self {
            driver,
            _phantom: Default::default(),
        }
    }

    pub async fn execute(
        &self,
        graph: &DepthAwareGraph<F>,
        inputs: &[E::VMType],
    ) -> Result<Vec<E::VMType>, Report> {
        let mut memory = vec![E::VMType::default(); graph.nodes.len()];
        // prepare constants + inputs
        for &node_idx in &graph.node_levels[0] {
            match graph.nodes[node_idx].node.node {
                Node::Input(i) => {
                    memory[node_idx] = inputs[i];
                }
                Node::Constant(c) => {
                    memory[node_idx] = E::VMType::from(c.into());
                }
                _ => unreachable!(),
            }
        }
        for level in graph.node_levels.iter().skip(1) {
            let mut level_futures = JoinSet::new();
            for &node_idx in level {
                let node = &graph.nodes[node_idx];
                match node.node.node {
                    Node::Op(op, a, b) => {
                        let a = memory[a];
                        let b = memory[b];
                        let io = self.driver.get_io_context().await;
                        match op {
                            Operation::Mul => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::mul(io, a, b).await, node_idx)
                            }),
                            Operation::Add => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::add(io, a, b).await, node_idx)
                            }),
                            Operation::Sub => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::sub(io, a, b).await, node_idx)
                            }),
                            Operation::Eq => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::eq(io, a, b).await, node_idx)
                            }),
                            Operation::Neq => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::neq(io, a, b).await, node_idx)
                            }),
                            Operation::Lt => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::lt(io, a, b).await, node_idx)
                            }),
                            Operation::Gt => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::gt(io, a, b).await, node_idx)
                            }),
                            Operation::Leq => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::leq(io, a, b).await, node_idx)
                            }),
                            Operation::Geq => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::geq(io, a, b).await, node_idx)
                            }),
                            Operation::Lor => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::lor(io, a, b).await, node_idx)
                            }),
                            Operation::Band => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::band(io, a, b).await, node_idx)
                            }),
                            Operation::Shl => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::shl(io, a, b).await, node_idx)
                            }),
                            Operation::Shr => level_futures.spawn(async move {
                                (<E as GraphExecutor<F>>::shr(io, a, b).await, node_idx)
                            }),
                        };
                    }
                    _ => unreachable!(),
                }
            }
            while let Some(res) = level_futures.join_next().await {
                let (res, node_idx) = res?;
                memory[node_idx] = res;
            }
        }
        let output = memory
            .into_iter()
            .enumerate()
            .filter_map(|(i, v)| {
                if graph.signals.contains(&i) {
                    Some(v)
                } else {
                    None
                }
            })
            .collect();
        Ok(output)
    }
}

pub trait GraphExecutor<F: PrimeField> {
    type VMType: Copy + Clone + Default + Send + Sync + From<F> + 'static;
    type IoContext: Send + Sync + 'static;
    async fn get_io_context(&self) -> Self::IoContext;
    fn mul(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    // TODO: should this be non-async?
    fn add(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    // TODO: should this be non-async?
    fn sub(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn eq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn neq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn lt(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn gt(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn leq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn geq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn lor(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn band(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn shl(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
    fn shr(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send;
}

#[derive(Default)]
pub struct PlainGraphExecutor<F> {
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> GraphExecutor<F> for PlainGraphExecutor<F> {
    type VMType = F;
    type IoContext = ();

    async fn get_io_context(&self) -> Self::IoContext {
        ()
    }

    async fn mul(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        a * b
    }

    async fn add(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        a + b
    }

    async fn sub(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        a - b
    }

    async fn eq(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        (a == b).into()
    }

    async fn neq(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        (a != b).into()
    }

    async fn lt(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        // TODO: fix these semantics
        (a < b).into()
    }

    async fn gt(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        (a > b).into()
    }

    async fn leq(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        (a <= b).into()
    }

    async fn geq(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        (a >= b).into()
    }

    async fn lor(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        let a_bi: BigUint = a.into();
        let b_bi: BigUint = b.into();
        (a_bi | b_bi).into()
    }

    async fn band(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        let a_bi: BigUint = a.into();
        let b_bi: BigUint = b.into();
        (a_bi & b_bi).into()
    }

    async fn shl(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        let a_bi: BigUint = a.into();
        let b_bi: BigUint = b.into();
        let b_usize: usize = b_bi.try_into().unwrap();
        (a_bi << b_usize).into()
    }

    async fn shr(_: (), a: Self::VMType, b: Self::VMType) -> Self::VMType {
        let a_bi: BigUint = a.into();
        let b_bi: BigUint = b.into();
        let b_usize: usize = b_bi.try_into().unwrap();
        (a_bi >> b_usize).into()
    }
}

pub struct Rep3GraphExecutor<F> {
    network: Arc<Rep3MpcNet>,
    _marker: std::marker::PhantomData<F>,
}

impl<F> Rep3GraphExecutor<F> {
    pub fn new(network: Arc<Rep3MpcNet>) -> Self {
        Self {
            network,
            _marker: Default::default(),
        }
    }
}

impl<F: PrimeField> GraphExecutor<F> for Rep3GraphExecutor<F> {
    type VMType = Rep3VmType<F>;

    type IoContext = ();

    async fn get_io_context(&self) -> Self::IoContext {
        todo!()
    }

    fn mul(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn add(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn sub(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn eq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn neq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn lt(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn gt(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn leq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn geq(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn lor(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn band(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn shl(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }

    fn shr(
        io: Self::IoContext,
        a: Self::VMType,
        b: Self::VMType,
    ) -> impl std::future::Future<Output = Self::VMType> + Send {
        todo!()
    }
}
