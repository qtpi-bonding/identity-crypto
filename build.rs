fn main() {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    prost_build::compile_protos(
        &["proto/identitycrypto/v1/identity.proto"],
        &["proto/"],
    )
    .expect("compiling identitycrypto/v1/identity.proto");
    println!("cargo:rerun-if-changed=proto/identitycrypto/v1/identity.proto");
}
