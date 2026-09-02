use std::path::PathBuf;

fn main() {
    let proto = "proto/identitycrypto/v1/identity.proto";
    println!("cargo:rerun-if-changed={proto}");

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    std::env::set_var("PROTOC", &protoc);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let descriptor_path = out_dir.join("proto_descriptor.bin");

    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(&descriptor_path);
    config
        .compile_protos(&[proto], &["proto/"])
        .expect("compiling identitycrypto/v1/identity.proto");

    // pbjson_build gives the generated types real serde Serialize/Deserialize
    // impls (JSON-canonical), not just prost::Message -- needed by any
    // consumer storing one of these on disk as JSON (e.g. gait's
    // keyring.json, which serializes a KeyScheme field directly).
    let descriptor_set = std::fs::read(&descriptor_path).expect("read descriptor set");
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor_set)
        .expect("register descriptors")
        .exclude([
            ".identitycrypto.v1.AttestedMessage",
            ".identitycrypto.v1.DeliveryAttestation",
        ])
        .build(&[".identitycrypto"])
        .expect("build pbjson serde");
}
