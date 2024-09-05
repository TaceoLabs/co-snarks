use ark_ff::PrimeField;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use circom_graph::{
    executor::{GraphExecutionEngine, PlainGraphExecutor},
    optimize::{DepthAwareGraph, TypedGraph},
    Graph,
};
use eyre::Result;
use ruint::aliases::U256;

const GRAPH: &[u8] = include_bytes!("graph.bin");

#[tokio::main]
async fn main() -> Result<()> {
    let wit_graph = witness::init_graph(GRAPH)?;
    let wit_graph2 = witness::init_graph(GRAPH)?;
    let graph: Graph<ark_bn254::Fr> = wit_graph.into();
    let tgraph = TypedGraph::from(graph);
    let dgraph = DepthAwareGraph::from(tgraph);
    dbg!(dgraph.node_levels.len());
    dbg!(dgraph.signals.len());
    dbg!(dgraph.node_comm_levels.len());

    let executor = GraphExecutionEngine::new(PlainGraphExecutor::<ark_bn254::Fr>::default());

    let data = r#"
    {
        "identityNullifier": ["0x099ab25e555083e656e9ec66a5368d1edd3314bd2dc77553813c5145d37326a3"],
        "identityTrapdoor": ["0x1db60e4cd8008edd85c68d461bf00d04f1620372f45c6ffacdb1a318791c2dd3"],
        "treePathIndices": [
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0"
        ],
        "treeSiblings": [
            "0x0",
            "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
            "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
            "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
            "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
            "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
            "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
            "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
            "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
            "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
            "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
            "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
            "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
            "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
            "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
            "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92"
        ],
        "externalNullifier": ["0x00fd3a1e9736c12a5d4a31f26362b577ccafbd523d358daf40cdc04d90e17f77"],
        "signalHash": ["0x00bc6bb462e38af7da48e0ae7b5cbae860141c04e5af2cf92328cd6548df111f"]
    }"#;

    let ops: HashSet<_> = wit_graph2
        .nodes
        .iter()
        .filter_map(|x| match x {
            witness::graph::Node::Op(y, _, _) => Some(y),
            _ => None,
        })
        .collect();
    dbg!(ops);

    let inputs: HashMap<String, Vec<U256>> = serde_json::from_str(data).unwrap();
    let mut inputs_buffer = witness::get_inputs_buffer(witness::get_inputs_size(&wit_graph2));
    let input_mapping = witness::get_input_mapping(&inputs.keys().cloned().collect(), &wit_graph2);
    witness::populate_inputs(&inputs, &input_mapping, &mut inputs_buffer);

    let inputs = inputs_buffer
        .into_iter()
        .map(|x| ark_bn254::Fr::from_le_bytes_mod_order(&x.as_le_bytes()))
        .collect::<Vec<_>>();

    for _ in 0..10 {
        let now = Instant::now();
        let output = executor.execute(&dgraph, &inputs).await?;
        println!("Execution time: {:?}", now.elapsed());
    }

    Ok(())
}
