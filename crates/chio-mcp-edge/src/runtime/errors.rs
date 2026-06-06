use serde_json::Value;

pub(super) struct JsonRpcProtocolErrorArgs<'a> {
    pub(super) id: Value,
    pub(super) jsonrpc_code: i64,
    pub(super) message: &'a str,
    pub(super) chio_code: i64,
    pub(super) name: &'a str,
    pub(super) retry_strategy: &'a str,
    pub(super) guidance: &'a str,
    pub(super) context: Option<Value>,
}
