use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;

/// Root metadata exposed by the client to bound filesystem access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RootDefinition {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Normalized root view consumed by the shared runtime.
///
/// `RootDefinition` remains the transport shape received from the client. The
/// runtime uses `NormalizedRoot` to freeze whether a root is enforceable for
/// filesystem-shaped access or should be treated as metadata only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NormalizedRoot {
    EnforceableFileSystem {
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        normalized_path: String,
    },
    UnenforceableFileSystem {
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        reason: String,
    },
    NonFileSystem {
        uri: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        scheme: String,
    },
}

/// Explicit runtime classification for resource URIs.
///
/// Resource reads can point at provider-owned identifiers that are not
/// filesystem-backed. The runtime uses this boundary to decide when negotiated
/// filesystem roots apply and when a resource should remain provider-defined.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceUriClassification {
    EnforceableFileSystem {
        uri: String,
        normalized_path: String,
    },
    UnenforceableFileSystem {
        uri: String,
        reason: String,
    },
    NonFileSystem {
        uri: String,
        scheme: String,
    },
}

impl RootDefinition {
    /// Normalize the transport-provided root into the runtime's shared model.
    pub fn normalize_for_runtime(&self) -> NormalizedRoot {
        NormalizedRoot::from_root_definition(self)
    }
}

impl NormalizedRoot {
    pub fn from_root_definition(root: &RootDefinition) -> Self {
        match Url::parse(&root.uri) {
            Ok(parsed) if parsed.scheme() == "file" => match normalize_local_file_uri_path(&parsed)
            {
                Ok(normalized_path) => Self::EnforceableFileSystem {
                    uri: root.uri.clone(),
                    name: root.name.clone(),
                    normalized_path,
                },
                Err(reason) => Self::UnenforceableFileSystem {
                    uri: root.uri.clone(),
                    name: root.name.clone(),
                    reason: reason.to_string(),
                },
            },
            Ok(parsed) => Self::NonFileSystem {
                uri: root.uri.clone(),
                name: root.name.clone(),
                scheme: parsed.scheme().to_string(),
            },
            Err(_) if root.uri.starts_with("file:") => Self::UnenforceableFileSystem {
                uri: root.uri.clone(),
                name: root.name.clone(),
                reason: "invalid_file_uri".to_string(),
            },
            Err(_) => Self::NonFileSystem {
                uri: root.uri.clone(),
                name: root.name.clone(),
                scheme: extract_uri_scheme(&root.uri).unwrap_or_else(|| "unknown".to_string()),
            },
        }
    }

    pub fn is_enforceable_filesystem(&self) -> bool {
        matches!(self, Self::EnforceableFileSystem { .. })
    }

    pub fn normalized_filesystem_path(&self) -> Option<&str> {
        match self {
            Self::EnforceableFileSystem {
                normalized_path, ..
            } => Some(normalized_path.as_str()),
            Self::UnenforceableFileSystem { .. } | Self::NonFileSystem { .. } => None,
        }
    }

    pub fn uri(&self) -> &str {
        match self {
            Self::EnforceableFileSystem { uri, .. }
            | Self::UnenforceableFileSystem { uri, .. }
            | Self::NonFileSystem { uri, .. } => uri.as_str(),
        }
    }
}

impl ResourceUriClassification {
    pub fn from_uri(uri: &str) -> Self {
        match Url::parse(uri) {
            Ok(parsed) if parsed.scheme() == "file" => match normalize_local_file_uri_path(&parsed)
            {
                Ok(normalized_path) => Self::EnforceableFileSystem {
                    uri: uri.to_string(),
                    normalized_path,
                },
                Err(reason) => Self::UnenforceableFileSystem {
                    uri: uri.to_string(),
                    reason: reason.to_string(),
                },
            },
            Ok(parsed) => Self::NonFileSystem {
                uri: uri.to_string(),
                scheme: parsed.scheme().to_string(),
            },
            Err(_) if uri.starts_with("file:") => Self::UnenforceableFileSystem {
                uri: uri.to_string(),
                reason: "invalid_file_uri".to_string(),
            },
            Err(_) => Self::NonFileSystem {
                uri: uri.to_string(),
                scheme: extract_uri_scheme(uri).unwrap_or_else(|| "unknown".to_string()),
            },
        }
    }

    pub fn is_enforceable_filesystem(&self) -> bool {
        matches!(self, Self::EnforceableFileSystem { .. })
    }

    pub fn normalized_filesystem_path(&self) -> Option<&str> {
        match self {
            Self::EnforceableFileSystem {
                normalized_path, ..
            } => Some(normalized_path.as_str()),
            Self::UnenforceableFileSystem { .. } | Self::NonFileSystem { .. } => None,
        }
    }
}

fn normalize_local_file_uri_path(parsed: &Url) -> core::result::Result<String, &'static str> {
    match parsed.host_str() {
        None => {}
        Some(host) if host.eq_ignore_ascii_case("localhost") => {}
        Some(_) => return Err("non_local_file_authority"),
    }

    let decoded_path = percent_decode_str(parsed.path())
        .decode_utf8()
        .map_err(|_| "invalid_utf8_path")?;

    normalize_absolute_filesystem_path(decoded_path.as_ref()).ok_or("file_path_not_absolute")
}

pub(super) fn normalize_absolute_filesystem_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");

    let (prefix, remainder) = if let Some(after_root) = path.strip_prefix('/') {
        if let Some((drive, remainder)) = split_windows_drive(after_root) {
            (format!("{drive}:"), remainder)
        } else {
            ("/".to_string(), after_root)
        }
    } else if let Some((drive, remainder)) = split_windows_drive(&path) {
        (format!("{drive}:"), remainder)
    } else {
        return None;
    };

    let mut segments: Vec<&str> = Vec::new();
    for segment in remainder.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        if segment == ".." {
            if !segments.is_empty() {
                segments.pop();
            }
            continue;
        }

        segments.push(segment);
    }

    if prefix == "/" {
        if segments.is_empty() {
            Some("/".to_string())
        } else {
            Some(format!("/{}", segments.join("/")))
        }
    } else if segments.is_empty() {
        Some(format!("{prefix}/"))
    } else {
        Some(format!("{prefix}/{}", segments.join("/")))
    }
}

pub(super) fn split_windows_drive(path: &str) -> Option<(char, &str)> {
    let bytes = path.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }

    let drive = char::from(bytes[0]).to_ascii_uppercase();
    match bytes.get(2).copied() {
        None => Some((drive, "")),
        Some(b'/') => Some((drive, &path[3..])),
        _ => None,
    }
}

pub(super) fn extract_uri_scheme(uri: &str) -> Option<String> {
    let (scheme, _) = uri.split_once(':')?;
    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if chars.all(|character| {
        character.is_ascii_alphanumeric()
            || character == '+'
            || character == '-'
            || character == '.'
    }) {
        Some(scheme.to_string())
    } else {
        None
    }
}
