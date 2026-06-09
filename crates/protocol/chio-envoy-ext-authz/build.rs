//! Build-time codegen for the vendored Envoy ext_authz v3 protobuf definitions.
//!
//! The protos under `proto/` are a minimal subset of Envoy's upstream API
//! (see the headers of each `.proto` for the source link). `tonic-build`
//! compiles them into Rust modules that the service implementation re-exports
//! via [`tonic::include_proto!`] in `lib.rs`.

use std::io;

fn main() -> io::Result<()> {
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to locate vendored protoc: {error}"),
            )
        })?;
        std::env::set_var("PROTOC", protoc);
    }

    let proto_root = "proto";

    let protos = [
        "proto/envoy/service/auth/v3/external_auth.proto",
        "proto/envoy/service/auth/v3/attribute_context.proto",
        "proto/envoy/config/core/v3/base.proto",
        "proto/envoy/type/v3/http_status.proto",
        "proto/google/rpc/status.proto",
    ];

    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed={proto_root}");

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &[proto_root])?;

    Ok(())
}
