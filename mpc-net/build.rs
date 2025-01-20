fn main() {
    tonic_build::configure()
        .out_dir("src/proto_generated")
        .compile_protos(&["src/proto/party_node.proto"], &["src/proto"])
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
}
