//! Independent Envoy v3 wire bytes: no generated encoder shares the decoder's schema.
#![allow(clippy::unwrap_used)]
use chio_envoy_ext_authz::{
    check_request_to_tool_call, proto::envoy::service::auth::v3::CheckRequest,
};
use prost::Message;

#[test]
fn upstream_v3_request_with_socket_address_decodes() {
    // CheckRequest.attributes(1), source(1), Address.socket_address(1),
    // SocketAddress.address(2)/port_value(3); AttributeContext.request(4),
    // Request.http(2), HttpRequest.method(2)/path(4). Field numbers from
    // Envoy v1.39.1's independently published protobuf contract.
    let wire = hex::decode("0a200a110a0f0a0d12093132372e302e302e311850220b1209120347455422022f78")
        .unwrap();
    let request = CheckRequest::decode(wire.as_slice()).unwrap();
    let call = check_request_to_tool_call(&request).unwrap();
    assert_eq!(call.method, "GET");
    assert_eq!(call.path, "/x");
}
