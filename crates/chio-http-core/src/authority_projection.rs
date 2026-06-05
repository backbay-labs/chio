use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authority::{
    HttpAuthorityInput, HttpAuthorityPolicy, HTTP_AUTHORITY_SERVER_ID, HTTP_AUTHORITY_TOOL_NAME,
};
use crate::HttpMethod;

pub(crate) const MALFORMED_CHIO_TOOLS_PATH_REASON: &str = "malformed /chio/tools path identity";

pub(crate) struct CapabilityBinding {
    pub(crate) requested_tool_server: Option<String>,
    pub(crate) requested_tool_name: Option<String>,
    pub(crate) requested_arguments: Option<Value>,
    pub(crate) invalid_reason: Option<String>,
    pub(crate) policy: HttpAuthorityPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HttpKernelAuthorizationRequest {
    pub(crate) request_id: String,
    pub(crate) method: HttpMethod,
    pub(crate) route_pattern: String,
    pub(crate) path: String,
    pub(crate) content_hash: String,
    pub(crate) caller_identity_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_id: Option<String>,
    pub(crate) policy: HttpAuthorityPolicy,
    pub(crate) capability: HttpKernelCapabilityState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HttpKernelCapabilityState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) invalid_reason: Option<String>,
}

enum ChioToolsPathIdentity {
    NotToolsPath,
    Malformed,
    Identity {
        server_id: String,
        tool_name: String,
    },
}

pub(crate) fn capability_binding(
    input: &HttpAuthorityInput<'_>,
    caller_identity_hash: &str,
) -> CapabilityBinding {
    match chio_tools_path_identity(input.path) {
        ChioToolsPathIdentity::Identity {
            server_id,
            tool_name,
        } => {
            return CapabilityBinding {
                requested_tool_server: Some(server_id),
                requested_tool_name: Some(tool_name),
                requested_arguments: input.requested_arguments.cloned(),
                invalid_reason: None,
                policy: HttpAuthorityPolicy::DenyByDefault,
            };
        }
        ChioToolsPathIdentity::Malformed => {
            return CapabilityBinding {
                requested_tool_server: None,
                requested_tool_name: None,
                requested_arguments: input.requested_arguments.cloned(),
                invalid_reason: Some(MALFORMED_CHIO_TOOLS_PATH_REASON.to_string()),
                policy: HttpAuthorityPolicy::DenyByDefault,
            };
        }
        ChioToolsPathIdentity::NotToolsPath => {}
    }

    if input.policy != HttpAuthorityPolicy::DenyByDefault {
        return request_field_capability_binding(input);
    }

    http_authority_capability_binding(input, caller_identity_hash)
}

fn request_field_capability_binding(input: &HttpAuthorityInput<'_>) -> CapabilityBinding {
    CapabilityBinding {
        requested_tool_server: input.requested_tool_server.map(str::to_owned),
        requested_tool_name: input.requested_tool_name.map(str::to_owned),
        requested_arguments: input.requested_arguments.cloned(),
        invalid_reason: None,
        policy: input.policy,
    }
}

fn http_authority_capability_binding(
    input: &HttpAuthorityInput<'_>,
    caller_identity_hash: &str,
) -> CapabilityBinding {
    let arguments = serde_json::to_value(HttpKernelAuthorizationRequest {
        request_id: input.request_id.clone(),
        method: input.method,
        route_pattern: input.route_pattern.clone(),
        path: input.path.to_string(),
        content_hash: input.body_hash.clone().unwrap_or_default(),
        caller_identity_hash: caller_identity_hash.to_string(),
        session_id: input.session_id.clone(),
        policy: input.policy,
        capability: HttpKernelCapabilityState {
            id: None,
            invalid_reason: None,
        },
    })
    .unwrap_or(Value::Null);

    CapabilityBinding {
        requested_tool_server: Some(HTTP_AUTHORITY_SERVER_ID.to_string()),
        requested_tool_name: Some(HTTP_AUTHORITY_TOOL_NAME.to_string()),
        requested_arguments: Some(arguments),
        invalid_reason: None,
        policy: input.policy,
    }
}

fn chio_tools_path_identity(path: &str) -> ChioToolsPathIdentity {
    let Some(rest) = path.strip_prefix("/chio/tools/") else {
        return ChioToolsPathIdentity::NotToolsPath;
    };
    let Some((server_id, tool_name)) = rest.split_once('/') else {
        return ChioToolsPathIdentity::Malformed;
    };
    if server_id.is_empty() || tool_name.is_empty() || tool_name.contains('/') {
        return ChioToolsPathIdentity::Malformed;
    }
    let Some(server_id) = decode_path_identity_segment(server_id) else {
        return ChioToolsPathIdentity::Malformed;
    };
    let Some(tool_name) = decode_path_identity_segment(tool_name) else {
        return ChioToolsPathIdentity::Malformed;
    };
    ChioToolsPathIdentity::Identity {
        server_id,
        tool_name,
    }
}

fn decode_path_identity_segment(segment: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(segment.len());
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    if decoded.is_empty() {
        return None;
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chio_tools_path_identity_parses_reserved_prefix() {
        let ChioToolsPathIdentity::Identity {
            server_id,
            tool_name,
        } = chio_tools_path_identity("/chio/tools/matrix/files.read")
        else {
            panic!("expected identity");
        };
        assert_eq!(server_id, "matrix");
        assert_eq!(tool_name, "files.read");
    }

    #[test]
    fn chio_tools_path_identity_rejects_missing_tool_segment() {
        assert!(matches!(
            chio_tools_path_identity("/chio/tools/matrix"),
            ChioToolsPathIdentity::Malformed
        ));
    }

    #[test]
    fn chio_tools_path_identity_requires_trailing_slash_prefix() {
        assert!(matches!(
            chio_tools_path_identity("/chio/tools"),
            ChioToolsPathIdentity::NotToolsPath
        ));
    }

    #[test]
    fn chio_tools_path_identity_rejects_nested_tool_segments() {
        assert!(matches!(
            chio_tools_path_identity("/chio/tools/matrix/files/read"),
            ChioToolsPathIdentity::Malformed
        ));
    }

    #[test]
    fn chio_tools_path_identity_rejects_incomplete_percent_encoding() {
        assert!(decode_path_identity_segment("terminal%2").is_none());
        assert!(matches!(
            chio_tools_path_identity("/chio/tools/acp/terminal%2"),
            ChioToolsPathIdentity::Malformed
        ));
    }

    #[test]
    fn chio_tools_path_identity_rejects_non_utf8_percent_encoding() {
        assert!(decode_path_identity_segment("terminal%FFcreate").is_none());
        assert!(matches!(
            chio_tools_path_identity("/chio/tools/acp/terminal%FFcreate"),
            ChioToolsPathIdentity::Malformed
        ));
    }

    #[test]
    fn chio_tools_path_identity_non_tools_path_is_not_tools_path() {
        assert!(matches!(
            chio_tools_path_identity("/pets/42"),
            ChioToolsPathIdentity::NotToolsPath
        ));
    }
}
