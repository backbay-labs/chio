// DO NOT EDIT - regenerate via 'make regen-rust' or 'cargo xtask codegen rust'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:   typify =0.4.3 (see xtask/codegen-tools.lock.toml)
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration; the
// `_generated_check` integration test enforces this header on every file
// under `crates/chio-core-types/src/_generated/`.

/// Error types.
pub mod error {
    /// Error from a `TryFrom` or `FromStr` implementation.
    pub struct ConversionError(::std::borrow::Cow<'static, str>);
    impl ::std::error::Error for ConversionError {}
    impl ::std::fmt::Display for ConversionError {
        fn fmt(
            &self,
            f: &mut ::std::fmt::Formatter<'_>,
        ) -> Result<(), ::std::fmt::Error> {
            ::std::fmt::Display::fmt(&self.0, f)
        }
    }
    impl ::std::fmt::Debug for ConversionError {
        fn fmt(
            &self,
            f: &mut ::std::fmt::Formatter<'_>,
        ) -> Result<(), ::std::fmt::Error> {
            ::std::fmt::Debug::fmt(&self.0, f)
        }
    }
    impl From<&'static str> for ConversionError {
        fn from(value: &'static str) -> Self {
            Self(value.into())
        }
    }
    impl From<String> for ConversionError {
        fn from(value: String) -> Self {
            Self(value.into())
        }
    }
}
///`ChioAgentMessageHeartbeat`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio AgentMessage heartbeat",
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "const": "heartbeat"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageHeartbeat {
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioAgentMessageHeartbeat> for ChioAgentMessageHeartbeat {
    fn from(value: &ChioAgentMessageHeartbeat) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageListCapabilities`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio AgentMessage list_capabilities",
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "const": "list_capabilities"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageListCapabilities {
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioAgentMessageListCapabilities>
for ChioAgentMessageListCapabilities {
    fn from(value: &ChioAgentMessageListCapabilities) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequest`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio AgentMessage tool_call_request",
///  "type": "object",
///  "required": [
///    "capability_token",
///    "id",
///    "params",
///    "server_id",
///    "tool",
///    "type"
///  ],
///  "properties": {
///    "capability_token": {
///      "type": "object",
///      "required": [
///        "expires_at",
///        "id",
///        "issued_at",
///        "issuer",
///        "scope",
///        "signature",
///        "subject"
///      ],
///      "properties": {
///        "delegation_chain": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "capability_id",
///              "delegatee",
///              "delegator",
///              "signature",
///              "timestamp"
///            ],
///            "properties": {
///              "attenuations": {
///                "type": "array",
///                "items": {
///                  "type": "object"
///                }
///              },
///              "capability_id": {
///                "type": "string",
///                "minLength": 1
///              },
///              "delegatee": {
///                "type": "string",
///                "pattern": "^[0-9a-f]{64}$"
///              },
///              "delegator": {
///                "type": "string",
///                "pattern": "^[0-9a-f]{64}$"
///              },
///              "signature": {
///                "type": "string",
///                "pattern": "^[0-9a-f]{128}$"
///              },
///              "timestamp": {
///                "type": "integer",
///                "minimum": 0.0
///              }
///            },
///            "additionalProperties": false
///          }
///        },
///        "expires_at": {
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "id": {
///          "type": "string",
///          "minLength": 1
///        },
///        "issued_at": {
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "issuer": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{64}$"
///        },
///        "scope": {
///          "type": "object",
///          "properties": {
///            "grants": {
///              "type": "array",
///              "items": {
///                "type": "object",
///                "required": [
///                  "operations",
///                  "server_id",
///                  "tool_name"
///                ],
///                "properties": {
///                  "constraints": {
///                    "type": "array",
///                    "items": {
///                      "type": "object",
///                      "required": [
///                        "type"
///                      ],
///                      "properties": {
///                        "type": {
///                          "type": "string",
///                          "minLength": 1
///                        },
///                        "value": true
///                      }
///                    }
///                  },
///                  "dpop_required": {
///                    "type": "boolean"
///                  },
///                  "max_cost_per_invocation": {
///                    "type": "object",
///                    "required": [
///                      "currency",
///                      "units"
///                    ],
///                    "properties": {
///                      "currency": {
///                        "type": "string",
///                        "minLength": 1
///                      },
///                      "units": {
///                        "type": "integer",
///                        "minimum": 0.0
///                      }
///                    },
///                    "additionalProperties": false
///                  },
///                  "max_invocations": {
///                    "type": "integer",
///                    "minimum": 0.0
///                  },
///                  "max_total_cost": {
///                    "type": "object",
///                    "required": [
///                      "currency",
///                      "units"
///                    ],
///                    "properties": {
///                      "currency": {
///                        "type": "string",
///                        "minLength": 1
///                      },
///                      "units": {
///                        "type": "integer",
///                        "minimum": 0.0
///                      }
///                    },
///                    "additionalProperties": false
///                  },
///                  "operations": {
///                    "type": "array",
///                    "items": {
///                      "enum": [
///                        "invoke",
///                        "read_result",
///                        "read",
///                        "subscribe",
///                        "get",
///                        "delegate"
///                      ]
///                    },
///                    "minItems": 1
///                  },
///                  "server_id": {
///                    "type": "string",
///                    "minLength": 1
///                  },
///                  "tool_name": {
///                    "type": "string",
///                    "minLength": 1
///                  }
///                },
///                "additionalProperties": false
///              }
///            },
///            "prompt_grants": {
///              "type": "array",
///              "items": {
///                "type": "object",
///                "required": [
///                  "operations",
///                  "prompt_name"
///                ],
///                "properties": {
///                  "operations": {
///                    "type": "array",
///                    "items": {
///                      "enum": [
///                        "invoke",
///                        "read_result",
///                        "read",
///                        "subscribe",
///                        "get",
///                        "delegate"
///                      ]
///                    },
///                    "minItems": 1
///                  },
///                  "prompt_name": {
///                    "type": "string",
///                    "minLength": 1
///                  }
///                },
///                "additionalProperties": false
///              }
///            },
///            "resource_grants": {
///              "type": "array",
///              "items": {
///                "type": "object",
///                "required": [
///                  "operations",
///                  "uri_pattern"
///                ],
///                "properties": {
///                  "operations": {
///                    "type": "array",
///                    "items": {
///                      "enum": [
///                        "invoke",
///                        "read_result",
///                        "read",
///                        "subscribe",
///                        "get",
///                        "delegate"
///                      ]
///                    },
///                    "minItems": 1
///                  },
///                  "uri_pattern": {
///                    "type": "string",
///                    "minLength": 1
///                  }
///                },
///                "additionalProperties": false
///              }
///            }
///          },
///          "additionalProperties": false
///        },
///        "signature": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{128}$"
///        },
///        "subject": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{64}$"
///        }
///      },
///      "additionalProperties": false
///    },
///    "id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "params": true,
///    "server_id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "tool": {
///      "type": "string",
///      "minLength": 1
///    },
///    "type": {
///      "const": "tool_call_request"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequest {
    pub capability_token: ChioAgentMessageToolCallRequestCapabilityToken,
    pub id: ChioAgentMessageToolCallRequestId,
    pub params: ::serde_json::Value,
    pub server_id: ChioAgentMessageToolCallRequestServerId,
    pub tool: ChioAgentMessageToolCallRequestTool,
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequest>
for ChioAgentMessageToolCallRequest {
    fn from(value: &ChioAgentMessageToolCallRequest) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityToken`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "expires_at",
///    "id",
///    "issued_at",
///    "issuer",
///    "scope",
///    "signature",
///    "subject"
///  ],
///  "properties": {
///    "delegation_chain": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "capability_id",
///          "delegatee",
///          "delegator",
///          "signature",
///          "timestamp"
///        ],
///        "properties": {
///          "attenuations": {
///            "type": "array",
///            "items": {
///              "type": "object"
///            }
///          },
///          "capability_id": {
///            "type": "string",
///            "minLength": 1
///          },
///          "delegatee": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{64}$"
///          },
///          "delegator": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{64}$"
///          },
///          "signature": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{128}$"
///          },
///          "timestamp": {
///            "type": "integer",
///            "minimum": 0.0
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "expires_at": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "issued_at": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "issuer": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "scope": {
///      "type": "object",
///      "properties": {
///        "grants": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "operations",
///              "server_id",
///              "tool_name"
///            ],
///            "properties": {
///              "constraints": {
///                "type": "array",
///                "items": {
///                  "type": "object",
///                  "required": [
///                    "type"
///                  ],
///                  "properties": {
///                    "type": {
///                      "type": "string",
///                      "minLength": 1
///                    },
///                    "value": true
///                  }
///                }
///              },
///              "dpop_required": {
///                "type": "boolean"
///              },
///              "max_cost_per_invocation": {
///                "type": "object",
///                "required": [
///                  "currency",
///                  "units"
///                ],
///                "properties": {
///                  "currency": {
///                    "type": "string",
///                    "minLength": 1
///                  },
///                  "units": {
///                    "type": "integer",
///                    "minimum": 0.0
///                  }
///                },
///                "additionalProperties": false
///              },
///              "max_invocations": {
///                "type": "integer",
///                "minimum": 0.0
///              },
///              "max_total_cost": {
///                "type": "object",
///                "required": [
///                  "currency",
///                  "units"
///                ],
///                "properties": {
///                  "currency": {
///                    "type": "string",
///                    "minLength": 1
///                  },
///                  "units": {
///                    "type": "integer",
///                    "minimum": 0.0
///                  }
///                },
///                "additionalProperties": false
///              },
///              "operations": {
///                "type": "array",
///                "items": {
///                  "enum": [
///                    "invoke",
///                    "read_result",
///                    "read",
///                    "subscribe",
///                    "get",
///                    "delegate"
///                  ]
///                },
///                "minItems": 1
///              },
///              "server_id": {
///                "type": "string",
///                "minLength": 1
///              },
///              "tool_name": {
///                "type": "string",
///                "minLength": 1
///              }
///            },
///            "additionalProperties": false
///          }
///        },
///        "prompt_grants": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "operations",
///              "prompt_name"
///            ],
///            "properties": {
///              "operations": {
///                "type": "array",
///                "items": {
///                  "enum": [
///                    "invoke",
///                    "read_result",
///                    "read",
///                    "subscribe",
///                    "get",
///                    "delegate"
///                  ]
///                },
///                "minItems": 1
///              },
///              "prompt_name": {
///                "type": "string",
///                "minLength": 1
///              }
///            },
///            "additionalProperties": false
///          }
///        },
///        "resource_grants": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "operations",
///              "uri_pattern"
///            ],
///            "properties": {
///              "operations": {
///                "type": "array",
///                "items": {
///                  "enum": [
///                    "invoke",
///                    "read_result",
///                    "read",
///                    "subscribe",
///                    "get",
///                    "delegate"
///                  ]
///                },
///                "minItems": 1
///              },
///              "uri_pattern": {
///                "type": "string",
///                "minLength": 1
///              }
///            },
///            "additionalProperties": false
///          }
///        }
///      },
///      "additionalProperties": false
///    },
///    "signature": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{128}$"
///    },
///    "subject": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityToken {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub delegation_chain: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItem,
    >,
    pub expires_at: u64,
    pub id: ChioAgentMessageToolCallRequestCapabilityTokenId,
    pub issued_at: u64,
    pub issuer: ChioAgentMessageToolCallRequestCapabilityTokenIssuer,
    pub scope: ChioAgentMessageToolCallRequestCapabilityTokenScope,
    pub signature: ChioAgentMessageToolCallRequestCapabilityTokenSignature,
    pub subject: ChioAgentMessageToolCallRequestCapabilityTokenSubject,
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestCapabilityToken>
for ChioAgentMessageToolCallRequestCapabilityToken {
    fn from(value: &ChioAgentMessageToolCallRequestCapabilityToken) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "capability_id",
///    "delegatee",
///    "delegator",
///    "signature",
///    "timestamp"
///  ],
///  "properties": {
///    "attenuations": {
///      "type": "array",
///      "items": {
///        "type": "object"
///      }
///    },
///    "capability_id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "delegatee": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "delegator": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "signature": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{128}$"
///    },
///    "timestamp": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItem {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub attenuations: ::std::vec::Vec<
        ::serde_json::Map<::std::string::String, ::serde_json::Value>,
    >,
    pub capability_id: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId,
    pub delegatee: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee,
    pub delegator: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator,
    pub signature: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature,
    pub timestamp: u64,
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItem,
> for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId,
> for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemCapabilityId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee,
> for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegatee {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator,
> for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemDelegator {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{128}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature,
> for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{128}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{128}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenDelegationChainItemSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenId(::std::string::String);
impl ::std::ops::Deref for ChioAgentMessageToolCallRequestCapabilityTokenId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioAgentMessageToolCallRequestCapabilityTokenId>
for ::std::string::String {
    fn from(value: ChioAgentMessageToolCallRequestCapabilityTokenId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestCapabilityTokenId>
for ChioAgentMessageToolCallRequestCapabilityTokenId {
    fn from(value: &ChioAgentMessageToolCallRequestCapabilityTokenId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioAgentMessageToolCallRequestCapabilityTokenId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioAgentMessageToolCallRequestCapabilityTokenId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenIssuer`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenIssuer(::std::string::String);
impl ::std::ops::Deref for ChioAgentMessageToolCallRequestCapabilityTokenIssuer {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioAgentMessageToolCallRequestCapabilityTokenIssuer>
for ::std::string::String {
    fn from(value: ChioAgentMessageToolCallRequestCapabilityTokenIssuer) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestCapabilityTokenIssuer>
for ChioAgentMessageToolCallRequestCapabilityTokenIssuer {
    fn from(value: &ChioAgentMessageToolCallRequestCapabilityTokenIssuer) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioAgentMessageToolCallRequestCapabilityTokenIssuer {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenIssuer {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScope`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "properties": {
///    "grants": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "operations",
///          "server_id",
///          "tool_name"
///        ],
///        "properties": {
///          "constraints": {
///            "type": "array",
///            "items": {
///              "type": "object",
///              "required": [
///                "type"
///              ],
///              "properties": {
///                "type": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "value": true
///              }
///            }
///          },
///          "dpop_required": {
///            "type": "boolean"
///          },
///          "max_cost_per_invocation": {
///            "type": "object",
///            "required": [
///              "currency",
///              "units"
///            ],
///            "properties": {
///              "currency": {
///                "type": "string",
///                "minLength": 1
///              },
///              "units": {
///                "type": "integer",
///                "minimum": 0.0
///              }
///            },
///            "additionalProperties": false
///          },
///          "max_invocations": {
///            "type": "integer",
///            "minimum": 0.0
///          },
///          "max_total_cost": {
///            "type": "object",
///            "required": [
///              "currency",
///              "units"
///            ],
///            "properties": {
///              "currency": {
///                "type": "string",
///                "minLength": 1
///              },
///              "units": {
///                "type": "integer",
///                "minimum": 0.0
///              }
///            },
///            "additionalProperties": false
///          },
///          "operations": {
///            "type": "array",
///            "items": {
///              "enum": [
///                "invoke",
///                "read_result",
///                "read",
///                "subscribe",
///                "get",
///                "delegate"
///              ]
///            },
///            "minItems": 1
///          },
///          "server_id": {
///            "type": "string",
///            "minLength": 1
///          },
///          "tool_name": {
///            "type": "string",
///            "minLength": 1
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "prompt_grants": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "operations",
///          "prompt_name"
///        ],
///        "properties": {
///          "operations": {
///            "type": "array",
///            "items": {
///              "enum": [
///                "invoke",
///                "read_result",
///                "read",
///                "subscribe",
///                "get",
///                "delegate"
///              ]
///            },
///            "minItems": 1
///          },
///          "prompt_name": {
///            "type": "string",
///            "minLength": 1
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "resource_grants": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "operations",
///          "uri_pattern"
///        ],
///        "properties": {
///          "operations": {
///            "type": "array",
///            "items": {
///              "enum": [
///                "invoke",
///                "read_result",
///                "read",
///                "subscribe",
///                "get",
///                "delegate"
///              ]
///            },
///            "minItems": 1
///          },
///          "uri_pattern": {
///            "type": "string",
///            "minLength": 1
///          }
///        },
///        "additionalProperties": false
///      }
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScope {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub grants: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItem,
    >,
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub prompt_grants: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItem,
    >,
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub resource_grants: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItem,
    >,
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestCapabilityTokenScope>
for ChioAgentMessageToolCallRequestCapabilityTokenScope {
    fn from(value: &ChioAgentMessageToolCallRequestCapabilityTokenScope) -> Self {
        value.clone()
    }
}
impl ::std::default::Default for ChioAgentMessageToolCallRequestCapabilityTokenScope {
    fn default() -> Self {
        Self {
            grants: Default::default(),
            prompt_grants: Default::default(),
            resource_grants: Default::default(),
        }
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "operations",
///    "server_id",
///    "tool_name"
///  ],
///  "properties": {
///    "constraints": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "type"
///        ],
///        "properties": {
///          "type": {
///            "type": "string",
///            "minLength": 1
///          },
///          "value": true
///        }
///      }
///    },
///    "dpop_required": {
///      "type": "boolean"
///    },
///    "max_cost_per_invocation": {
///      "type": "object",
///      "required": [
///        "currency",
///        "units"
///      ],
///      "properties": {
///        "currency": {
///          "type": "string",
///          "minLength": 1
///        },
///        "units": {
///          "type": "integer",
///          "minimum": 0.0
///        }
///      },
///      "additionalProperties": false
///    },
///    "max_invocations": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "max_total_cost": {
///      "type": "object",
///      "required": [
///        "currency",
///        "units"
///      ],
///      "properties": {
///        "currency": {
///          "type": "string",
///          "minLength": 1
///        },
///        "units": {
///          "type": "integer",
///          "minimum": 0.0
///        }
///      },
///      "additionalProperties": false
///    },
///    "operations": {
///      "type": "array",
///      "items": {
///        "enum": [
///          "invoke",
///          "read_result",
///          "read",
///          "subscribe",
///          "get",
///          "delegate"
///        ]
///      },
///      "minItems": 1
///    },
///    "server_id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "tool_name": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItem {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub constraints: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItem,
    >,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub dpop_required: ::std::option::Option<bool>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_cost_per_invocation: ::std::option::Option<
        ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocation,
    >,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_invocations: ::std::option::Option<u64>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_total_cost: ::std::option::Option<
        ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCost,
    >,
    pub operations: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem,
    >,
    pub server_id: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId,
    pub tool_name: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName,
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItem>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "type": "string",
///      "minLength": 1
///    },
///    "value": true
///  }
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItem {
    #[serde(rename = "type")]
    pub type_: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub value: ::std::option::Option<::serde_json::Value>,
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItem,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemConstraintsItemType {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocation`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "currency",
///    "units"
///  ],
///  "properties": {
///    "currency": {
///      "type": "string",
///      "minLength": 1
///    },
///    "units": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocation {
    pub currency: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency,
    pub units: u64,
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocation,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocation {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocation,
    ) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency,
>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxCostPerInvocationCurrency {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCost`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "currency",
///    "units"
///  ],
///  "properties": {
///    "currency": {
///      "type": "string",
///      "minLength": 1
///    },
///    "units": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCost {
    pub currency: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency,
    pub units: u64,
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCost,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCost {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCost,
    ) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemMaxTotalCostCurrency {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemServerId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeGrantsItemToolName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "operations",
///    "prompt_name"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "enum": [
///          "invoke",
///          "read_result",
///          "read",
///          "subscribe",
///          "get",
///          "delegate"
///        ]
///      },
///      "minItems": 1
///    },
///    "prompt_name": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItem {
    pub operations: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem,
    >,
    pub prompt_name: ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName,
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItem,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenScopePromptGrantsItemPromptName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "operations",
///    "uri_pattern"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "enum": [
///          "invoke",
///          "read_result",
///          "read",
///          "subscribe",
///          "get",
///          "delegate"
///        ]
///      },
///      "minItems": 1
///    },
///    "uri_pattern": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItem {
    pub operations: ::std::vec::Vec<
        ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem,
    >,
    pub uri_pattern: ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern,
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItem,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern,
> for ::std::string::String {
    fn from(
        value: ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern,
> for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern {
    fn from(
        value: &ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenScopeResourceGrantsItemUriPattern {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenSignature`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{128}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenSignature(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioAgentMessageToolCallRequestCapabilityTokenSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioAgentMessageToolCallRequestCapabilityTokenSignature>
for ::std::string::String {
    fn from(value: ChioAgentMessageToolCallRequestCapabilityTokenSignature) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestCapabilityTokenSignature>
for ChioAgentMessageToolCallRequestCapabilityTokenSignature {
    fn from(value: &ChioAgentMessageToolCallRequestCapabilityTokenSignature) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioAgentMessageToolCallRequestCapabilityTokenSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{128}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{128}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestCapabilityTokenSubject`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestCapabilityTokenSubject(::std::string::String);
impl ::std::ops::Deref for ChioAgentMessageToolCallRequestCapabilityTokenSubject {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioAgentMessageToolCallRequestCapabilityTokenSubject>
for ::std::string::String {
    fn from(value: ChioAgentMessageToolCallRequestCapabilityTokenSubject) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestCapabilityTokenSubject>
for ChioAgentMessageToolCallRequestCapabilityTokenSubject {
    fn from(value: &ChioAgentMessageToolCallRequestCapabilityTokenSubject) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioAgentMessageToolCallRequestCapabilityTokenSubject {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioAgentMessageToolCallRequestCapabilityTokenSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestCapabilityTokenSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioAgentMessageToolCallRequestCapabilityTokenSubject {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestId(::std::string::String);
impl ::std::ops::Deref for ChioAgentMessageToolCallRequestId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioAgentMessageToolCallRequestId> for ::std::string::String {
    fn from(value: ChioAgentMessageToolCallRequestId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestId>
for ChioAgentMessageToolCallRequestId {
    fn from(value: &ChioAgentMessageToolCallRequestId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioAgentMessageToolCallRequestId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioAgentMessageToolCallRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioAgentMessageToolCallRequestId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestServerId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestServerId(::std::string::String);
impl ::std::ops::Deref for ChioAgentMessageToolCallRequestServerId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioAgentMessageToolCallRequestServerId>
for ::std::string::String {
    fn from(value: ChioAgentMessageToolCallRequestServerId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestServerId>
for ChioAgentMessageToolCallRequestServerId {
    fn from(value: &ChioAgentMessageToolCallRequestServerId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioAgentMessageToolCallRequestServerId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioAgentMessageToolCallRequestServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioAgentMessageToolCallRequestServerId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioAgentMessageToolCallRequestTool`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioAgentMessageToolCallRequestTool(::std::string::String);
impl ::std::ops::Deref for ChioAgentMessageToolCallRequestTool {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioAgentMessageToolCallRequestTool>
for ::std::string::String {
    fn from(value: ChioAgentMessageToolCallRequestTool) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioAgentMessageToolCallRequestTool>
for ChioAgentMessageToolCallRequestTool {
    fn from(value: &ChioAgentMessageToolCallRequestTool) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioAgentMessageToolCallRequestTool {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioAgentMessageToolCallRequestTool {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioAgentMessageToolCallRequestTool {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioAgentMessageToolCallRequestTool {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioAgentMessageToolCallRequestTool {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///A single grant carried inside a capability token's `scope`. Chio uses three distinct grant kinds (tool, resource, prompt) that share no common discriminator field; this schema accepts any one of them via `oneOf`. Mirrors `ToolGrant`, `ResourceGrant`, and `PromptGrant` in `crates/chio-core-types/src/capability.rs`. The wrapper `ChioScope` partitions grants into three named arrays (`grants`, `resource_grants`, `prompt_grants`); validators that consume a token can dispatch to the appropriate `$defs/*` shape directly without relying on `oneOf` matching.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/capability/grant/v1",
///  "title": "Chio Capability Grant",
///  "description": "A single grant carried inside a capability token's `scope`. Chio uses three distinct grant kinds (tool, resource, prompt) that share no common discriminator field; this schema accepts any one of them via `oneOf`. Mirrors `ToolGrant`, `ResourceGrant`, and `PromptGrant` in `crates/chio-core-types/src/capability.rs`. The wrapper `ChioScope` partitions grants into three named arrays (`grants`, `resource_grants`, `prompt_grants`); validators that consume a token can dispatch to the appropriate `$defs/*` shape directly without relying on `oneOf` matching.",
///  "oneOf": [
///    {
///      "$ref": "#/$defs/toolGrant"
///    },
///    {
///      "$ref": "#/$defs/resourceGrant"
///    },
///    {
///      "$ref": "#/$defs/promptGrant"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ChioCapabilityGrant {
    ToolGrant(ToolGrant),
    ResourceGrant(ResourceGrant),
    PromptGrant(PromptGrant),
}
impl ::std::convert::From<&Self> for ChioCapabilityGrant {
    fn from(value: &ChioCapabilityGrant) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<ToolGrant> for ChioCapabilityGrant {
    fn from(value: ToolGrant) -> Self {
        Self::ToolGrant(value)
    }
}
impl ::std::convert::From<ResourceGrant> for ChioCapabilityGrant {
    fn from(value: ResourceGrant) -> Self {
        Self::ResourceGrant(value)
    }
}
impl ::std::convert::From<PromptGrant> for ChioCapabilityGrant {
    fn from(value: PromptGrant) -> Self {
        Self::PromptGrant(value)
    }
}
///A single revocation entry recording that a previously issued capability token (identified by its `id`) is no longer valid as of `revoked_at`. Mirrors `RevocationRecord` in `crates/chio-kernel/src/revocation_store.rs` (the kernel's persisted revocation row), and is the wire-level companion to the `capability_revoked` kernel notification under `chio-wire/v1/kernel/capability_revoked.schema.json`. Operators read these entries from `/admin/revocations` (hosted edge) and from the trust-control revocation list.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/capability/revocation/v1",
///  "title": "Chio Capability Revocation Entry",
///  "description": "A single revocation entry recording that a previously issued capability token (identified by its `id`) is no longer valid as of `revoked_at`. Mirrors `RevocationRecord` in `crates/chio-kernel/src/revocation_store.rs` (the kernel's persisted revocation row), and is the wire-level companion to the `capability_revoked` kernel notification under `chio-wire/v1/kernel/capability_revoked.schema.json`. Operators read these entries from `/admin/revocations` (hosted edge) and from the trust-control revocation list.",
///  "type": "object",
///  "required": [
///    "capability_id",
///    "revoked_at"
///  ],
///  "properties": {
///    "capability_id": {
///      "description": "The `id` field of the revoked CapabilityToken. Used to match revocations against presented tokens.",
///      "type": "string",
///      "minLength": 1
///    },
///    "revoked_at": {
///      "description": "Unix timestamp (seconds) at which the revocation took effect. Stored as a signed integer in the kernel store; negative values are not produced by the issuer but are not rejected here in order to match the Rust `i64` shape.",
///      "type": "integer"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioCapabilityRevocationEntry {
    ///The `id` field of the revoked CapabilityToken. Used to match revocations against presented tokens.
    pub capability_id: ChioCapabilityRevocationEntryCapabilityId,
    ///Unix timestamp (seconds) at which the revocation took effect. Stored as a signed integer in the kernel store; negative values are not produced by the issuer but are not rejected here in order to match the Rust `i64` shape.
    pub revoked_at: i64,
}
impl ::std::convert::From<&ChioCapabilityRevocationEntry>
for ChioCapabilityRevocationEntry {
    fn from(value: &ChioCapabilityRevocationEntry) -> Self {
        value.clone()
    }
}
///The `id` field of the revoked CapabilityToken. Used to match revocations against presented tokens.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "The `id` field of the revoked CapabilityToken. Used to match revocations against presented tokens.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioCapabilityRevocationEntryCapabilityId(::std::string::String);
impl ::std::ops::Deref for ChioCapabilityRevocationEntryCapabilityId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioCapabilityRevocationEntryCapabilityId>
for ::std::string::String {
    fn from(value: ChioCapabilityRevocationEntryCapabilityId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioCapabilityRevocationEntryCapabilityId>
for ChioCapabilityRevocationEntryCapabilityId {
    fn from(value: &ChioCapabilityRevocationEntryCapabilityId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioCapabilityRevocationEntryCapabilityId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioCapabilityRevocationEntryCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioCapabilityRevocationEntryCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioCapabilityRevocationEntryCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioCapabilityRevocationEntryCapabilityId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///A Chio capability token: an Ed25519-signed (or FIPS-algorithm), scoped, time-bounded authorization to invoke a tool. Mirrors the serde shape of `CapabilityToken` in `crates/chio-core-types/src/capability.rs`. The `signature` field covers the canonical JSON of all other fields except `algorithm`. The `algorithm` envelope field is informational (verification dispatches off the signature hex prefix) and is omitted for legacy Ed25519 tokens. PublicKey serde renders Ed25519 keys as bare 64-character lowercase hex (`PublicKey::to_hex` in `crates/chio-core-types/src/crypto.rs`), and renders FIPS keys with a self-describing prefix (`p256:<130-char hex>` for uncompressed SEC1 P-256, `p384:<194-char hex>` for P-384). Signatures follow the same convention: bare 128-char hex for Ed25519, `p256:<DER hex>` and `p384:<DER hex>` for FIPS algorithms. The grant `$defs` (`toolGrant`, `resourceGrant`, `promptGrant`, `operation`, `monetaryAmount`, `constraint`) are duplicated with `capability/grant.schema.json` because the current Rust codegen pipeline (`typify =0.4.3`) does not support cross-file `$ref`; both copies must be kept byte-identical when either file is edited until the M01 phase 3 codegen split lands.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/capability/token/v1",
///  "title": "Chio CapabilityToken",
///  "description": "A Chio capability token: an Ed25519-signed (or FIPS-algorithm), scoped, time-bounded authorization to invoke a tool. Mirrors the serde shape of `CapabilityToken` in `crates/chio-core-types/src/capability.rs`. The `signature` field covers the canonical JSON of all other fields except `algorithm`. The `algorithm` envelope field is informational (verification dispatches off the signature hex prefix) and is omitted for legacy Ed25519 tokens. PublicKey serde renders Ed25519 keys as bare 64-character lowercase hex (`PublicKey::to_hex` in `crates/chio-core-types/src/crypto.rs`), and renders FIPS keys with a self-describing prefix (`p256:<130-char hex>` for uncompressed SEC1 P-256, `p384:<194-char hex>` for P-384). Signatures follow the same convention: bare 128-char hex for Ed25519, `p256:<DER hex>` and `p384:<DER hex>` for FIPS algorithms. The grant `$defs` (`toolGrant`, `resourceGrant`, `promptGrant`, `operation`, `monetaryAmount`, `constraint`) are duplicated with `capability/grant.schema.json` because the current Rust codegen pipeline (`typify =0.4.3`) does not support cross-file `$ref`; both copies must be kept byte-identical when either file is edited until the M01 phase 3 codegen split lands.",
///  "type": "object",
///  "required": [
///    "expires_at",
///    "id",
///    "issued_at",
///    "issuer",
///    "scope",
///    "signature",
///    "subject"
///  ],
///  "properties": {
///    "algorithm": {
///      "description": "Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.",
///      "type": "string",
///      "enum": [
///        "ed25519",
///        "p256",
///        "p384"
///      ]
///    },
///    "delegation_chain": {
///      "description": "Ordered list of delegation links from the root authority to this token. Omitted (or empty) for direct issuances.",
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/delegationLink"
///      }
///    },
///    "expires_at": {
///      "description": "Unix timestamp (seconds) when the token expires.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "id": {
///      "description": "Unique token ID (UUIDv7 recommended), used for revocation.",
///      "type": "string",
///      "minLength": 1
///    },
///    "issued_at": {
///      "description": "Unix timestamp (seconds) when the token was issued.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "issuer": {
///      "description": "Public key of the Capability Authority (or delegating agent) that issued this token. Bare 64-char lowercase hex for Ed25519, or `p256:<130-char hex>` / `p384:<194-char hex>` for FIPS algorithms (uncompressed SEC1 encoding).",
///      "type": "string",
///      "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///    },
///    "scope": {
///      "$ref": "#/$defs/chioScope"
///    },
///    "signature": {
///      "description": "Hex-encoded signature over the canonical JSON of the token body. Bare 128-char hex for Ed25519, or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.",
///      "type": "string",
///      "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$"
///    },
///    "subject": {
///      "description": "Public key of the agent this capability is bound to (DPoP sender constraint). Same encoding as `issuer`.",
///      "type": "string",
///      "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioCapabilityToken {
    ///Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub algorithm: ::std::option::Option<ChioCapabilityTokenAlgorithm>,
    ///Ordered list of delegation links from the root authority to this token. Omitted (or empty) for direct issuances.
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub delegation_chain: ::std::vec::Vec<DelegationLink>,
    ///Unix timestamp (seconds) when the token expires.
    pub expires_at: u64,
    ///Unique token ID (UUIDv7 recommended), used for revocation.
    pub id: ChioCapabilityTokenId,
    ///Unix timestamp (seconds) when the token was issued.
    pub issued_at: u64,
    ///Public key of the Capability Authority (or delegating agent) that issued this token. Bare 64-char lowercase hex for Ed25519, or `p256:<130-char hex>` / `p384:<194-char hex>` for FIPS algorithms (uncompressed SEC1 encoding).
    pub issuer: ChioCapabilityTokenIssuer,
    pub scope: ChioScope,
    ///Hex-encoded signature over the canonical JSON of the token body. Bare 128-char hex for Ed25519, or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
    pub signature: ChioCapabilityTokenSignature,
    ///Public key of the agent this capability is bound to (DPoP sender constraint). Same encoding as `issuer`.
    pub subject: ChioCapabilityTokenSubject,
}
impl ::std::convert::From<&ChioCapabilityToken> for ChioCapabilityToken {
    fn from(value: &ChioCapabilityToken) -> Self {
        value.clone()
    }
}
///Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.",
///  "type": "string",
///  "enum": [
///    "ed25519",
///    "p256",
///    "p384"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioCapabilityTokenAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "p256")]
    P256,
    #[serde(rename = "p384")]
    P384,
}
impl ::std::convert::From<&Self> for ChioCapabilityTokenAlgorithm {
    fn from(value: &ChioCapabilityTokenAlgorithm) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioCapabilityTokenAlgorithm {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Ed25519 => f.write_str("ed25519"),
            Self::P256 => f.write_str("p256"),
            Self::P384 => f.write_str("p384"),
        }
    }
}
impl ::std::str::FromStr for ChioCapabilityTokenAlgorithm {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "ed25519" => Ok(Self::Ed25519),
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioCapabilityTokenAlgorithm {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioCapabilityTokenAlgorithm {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioCapabilityTokenAlgorithm {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Unique token ID (UUIDv7 recommended), used for revocation.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Unique token ID (UUIDv7 recommended), used for revocation.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioCapabilityTokenId(::std::string::String);
impl ::std::ops::Deref for ChioCapabilityTokenId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioCapabilityTokenId> for ::std::string::String {
    fn from(value: ChioCapabilityTokenId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioCapabilityTokenId> for ChioCapabilityTokenId {
    fn from(value: &ChioCapabilityTokenId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioCapabilityTokenId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioCapabilityTokenId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioCapabilityTokenId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioCapabilityTokenId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioCapabilityTokenId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Public key of the Capability Authority (or delegating agent) that issued this token. Bare 64-char lowercase hex for Ed25519, or `p256:<130-char hex>` / `p384:<194-char hex>` for FIPS algorithms (uncompressed SEC1 encoding).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Public key of the Capability Authority (or delegating agent) that issued this token. Bare 64-char lowercase hex for Ed25519, or `p256:<130-char hex>` / `p384:<194-char hex>` for FIPS algorithms (uncompressed SEC1 encoding).",
///  "type": "string",
///  "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioCapabilityTokenIssuer(::std::string::String);
impl ::std::ops::Deref for ChioCapabilityTokenIssuer {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioCapabilityTokenIssuer> for ::std::string::String {
    fn from(value: ChioCapabilityTokenIssuer) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioCapabilityTokenIssuer> for ChioCapabilityTokenIssuer {
    fn from(value: &ChioCapabilityTokenIssuer) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioCapabilityTokenIssuer {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new(
                    "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$",
                )
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioCapabilityTokenIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioCapabilityTokenIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioCapabilityTokenIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioCapabilityTokenIssuer {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Hex-encoded signature over the canonical JSON of the token body. Bare 128-char hex for Ed25519, or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Hex-encoded signature over the canonical JSON of the token body. Bare 128-char hex for Ed25519, or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.",
///  "type": "string",
///  "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioCapabilityTokenSignature(::std::string::String);
impl ::std::ops::Deref for ChioCapabilityTokenSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioCapabilityTokenSignature> for ::std::string::String {
    fn from(value: ChioCapabilityTokenSignature) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioCapabilityTokenSignature>
for ChioCapabilityTokenSignature {
    fn from(value: &ChioCapabilityTokenSignature) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioCapabilityTokenSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new("^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$")
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioCapabilityTokenSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioCapabilityTokenSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioCapabilityTokenSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioCapabilityTokenSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Public key of the agent this capability is bound to (DPoP sender constraint). Same encoding as `issuer`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Public key of the agent this capability is bound to (DPoP sender constraint). Same encoding as `issuer`.",
///  "type": "string",
///  "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioCapabilityTokenSubject(::std::string::String);
impl ::std::ops::Deref for ChioCapabilityTokenSubject {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioCapabilityTokenSubject> for ::std::string::String {
    fn from(value: ChioCapabilityTokenSubject) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioCapabilityTokenSubject> for ChioCapabilityTokenSubject {
    fn from(value: &ChioCapabilityTokenSubject) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioCapabilityTokenSubject {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new(
                    "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$",
                )
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioCapabilityTokenSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioCapabilityTokenSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioCapabilityTokenSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioCapabilityTokenSubject {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///JSON-RPC 2.0 notification envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_notification` (lines 770-774) and the streaming-chunk and cancellation notifications in `crates/chio-mcp-edge/src/runtime/protocol.rs` and transport.rs (lines 401-407, 1384-1392). A notification is structurally a request with no `id` field; the receiver MUST NOT respond. Common Chio notification methods include 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status', 'notifications/resources/updated', 'notifications/resources/list_changed', and the Chio-specific tool-streaming chunk method exposed as `CHIO_TOOL_STREAMING_NOTIFICATION_METHOD`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/jsonrpc/notification/v1",
///  "title": "Chio JSON-RPC 2.0 Notification",
///  "description": "JSON-RPC 2.0 notification envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_notification` (lines 770-774) and the streaming-chunk and cancellation notifications in `crates/chio-mcp-edge/src/runtime/protocol.rs` and transport.rs (lines 401-407, 1384-1392). A notification is structurally a request with no `id` field; the receiver MUST NOT respond. Common Chio notification methods include 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status', 'notifications/resources/updated', 'notifications/resources/list_changed', and the Chio-specific tool-streaming chunk method exposed as `CHIO_TOOL_STREAMING_NOTIFICATION_METHOD`.",
///  "type": "object",
///  "not": {
///    "required": [
///      "id"
///    ]
///  },
///  "required": [
///    "jsonrpc",
///    "method"
///  ],
///  "properties": {
///    "jsonrpc": {
///      "description": "Protocol version literal. Always the string '2.0'.",
///      "const": "2.0"
///    },
///    "method": {
///      "description": "Notification method name (for example 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status').",
///      "type": "string",
///      "minLength": 1
///    },
///    "params": {
///      "description": "Method parameters. JSON-RPC 2.0 allows omission; Chio call sites typically supply at least an empty object.",
///      "oneOf": [
///        {
///          "type": "object"
///        },
///        {
///          "type": "array"
///        }
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioJsonRpc20Notification {
    ///Protocol version literal. Always the string '2.0'.
    pub jsonrpc: ::serde_json::Value,
    ///Notification method name (for example 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status').
    pub method: ChioJsonRpc20NotificationMethod,
    ///Method parameters. JSON-RPC 2.0 allows omission; Chio call sites typically supply at least an empty object.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub params: ::std::option::Option<ChioJsonRpc20NotificationParams>,
}
impl ::std::convert::From<&ChioJsonRpc20Notification> for ChioJsonRpc20Notification {
    fn from(value: &ChioJsonRpc20Notification) -> Self {
        value.clone()
    }
}
///Notification method name (for example 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status').
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Notification method name (for example 'notifications/initialized', 'notifications/cancelled', 'notifications/tasks/status').",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioJsonRpc20NotificationMethod(::std::string::String);
impl ::std::ops::Deref for ChioJsonRpc20NotificationMethod {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioJsonRpc20NotificationMethod> for ::std::string::String {
    fn from(value: ChioJsonRpc20NotificationMethod) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioJsonRpc20NotificationMethod>
for ChioJsonRpc20NotificationMethod {
    fn from(value: &ChioJsonRpc20NotificationMethod) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioJsonRpc20NotificationMethod {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioJsonRpc20NotificationMethod {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioJsonRpc20NotificationMethod {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioJsonRpc20NotificationMethod {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioJsonRpc20NotificationMethod {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Method parameters. JSON-RPC 2.0 allows omission; Chio call sites typically supply at least an empty object.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Method parameters. JSON-RPC 2.0 allows omission; Chio call sites typically supply at least an empty object.",
///  "oneOf": [
///    {
///      "type": "object"
///    },
///    {
///      "type": "array"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ChioJsonRpc20NotificationParams {
    Variant0(::serde_json::Map<::std::string::String, ::serde_json::Value>),
    Variant1(::std::vec::Vec<::serde_json::Value>),
}
impl ::std::convert::From<&Self> for ChioJsonRpc20NotificationParams {
    fn from(value: &ChioJsonRpc20NotificationParams) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<::serde_json::Map<::std::string::String, ::serde_json::Value>>
for ChioJsonRpc20NotificationParams {
    fn from(
        value: ::serde_json::Map<::std::string::String, ::serde_json::Value>,
    ) -> Self {
        Self::Variant0(value)
    }
}
impl ::std::convert::From<::std::vec::Vec<::serde_json::Value>>
for ChioJsonRpc20NotificationParams {
    fn from(value: ::std::vec::Vec<::serde_json::Value>) -> Self {
        Self::Variant1(value)
    }
}
///JSON-RPC 2.0 request envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_request` (lines 643-648) and the typed `A2aJsonRpcRequest<T>` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 234-241). The `id` may be an integer, a string, or null; null is permitted on the wire because Chio relays peers that originate ids upstream and forward them verbatim. `params` is optional per JSON-RPC 2.0 (notifications and parameterless calls omit it), but most Chio call sites supply at least an empty object.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/jsonrpc/request/v1",
///  "title": "Chio JSON-RPC 2.0 Request",
///  "description": "JSON-RPC 2.0 request envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shape constructed in `crates/chio-mcp-adapter/src/transport.rs::send_request` (lines 643-648) and the typed `A2aJsonRpcRequest<T>` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 234-241). The `id` may be an integer, a string, or null; null is permitted on the wire because Chio relays peers that originate ids upstream and forward them verbatim. `params` is optional per JSON-RPC 2.0 (notifications and parameterless calls omit it), but most Chio call sites supply at least an empty object.",
///  "type": "object",
///  "required": [
///    "id",
///    "jsonrpc",
///    "method"
///  ],
///  "properties": {
///    "id": {
///      "description": "Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.",
///      "oneOf": [
///        {
///          "type": "integer"
///        },
///        {
///          "type": "string",
///          "minLength": 1
///        },
///        {
///          "type": "null"
///        }
///      ]
///    },
///    "jsonrpc": {
///      "description": "Protocol version literal. Always the string '2.0'.",
///      "const": "2.0"
///    },
///    "method": {
///      "description": "RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').",
///      "type": "string",
///      "minLength": 1
///    },
///    "params": {
///      "description": "Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array.",
///      "oneOf": [
///        {
///          "type": "object"
///        },
///        {
///          "type": "array"
///        }
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioJsonRpc20Request {
    ///Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.
    pub id: ChioJsonRpc20RequestId,
    ///Protocol version literal. Always the string '2.0'.
    pub jsonrpc: ::serde_json::Value,
    ///RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').
    pub method: ChioJsonRpc20RequestMethod,
    ///Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub params: ::std::option::Option<ChioJsonRpc20RequestParams>,
}
impl ::std::convert::From<&ChioJsonRpc20Request> for ChioJsonRpc20Request {
    fn from(value: &ChioJsonRpc20Request) -> Self {
        value.clone()
    }
}
///Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Request correlation id. Chio adapters originate monotonic integer ids; relayed peer ids may be strings. Null is permitted per JSON-RPC 2.0 but discouraged for new requests because it is indistinguishable from a server-side parse failure response.",
///  "oneOf": [
///    {
///      "type": "integer"
///    },
///    {
///      "type": "string",
///      "minLength": 1
///    },
///    {
///      "type": "null"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ChioJsonRpc20RequestId {
    Variant0(i64),
    Variant1(ChioJsonRpc20RequestIdVariant1),
    Variant2,
}
impl ::std::convert::From<&Self> for ChioJsonRpc20RequestId {
    fn from(value: &ChioJsonRpc20RequestId) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<i64> for ChioJsonRpc20RequestId {
    fn from(value: i64) -> Self {
        Self::Variant0(value)
    }
}
impl ::std::convert::From<ChioJsonRpc20RequestIdVariant1> for ChioJsonRpc20RequestId {
    fn from(value: ChioJsonRpc20RequestIdVariant1) -> Self {
        Self::Variant1(value)
    }
}
///`ChioJsonRpc20RequestIdVariant1`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioJsonRpc20RequestIdVariant1(::std::string::String);
impl ::std::ops::Deref for ChioJsonRpc20RequestIdVariant1 {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioJsonRpc20RequestIdVariant1> for ::std::string::String {
    fn from(value: ChioJsonRpc20RequestIdVariant1) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioJsonRpc20RequestIdVariant1>
for ChioJsonRpc20RequestIdVariant1 {
    fn from(value: &ChioJsonRpc20RequestIdVariant1) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioJsonRpc20RequestIdVariant1 {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioJsonRpc20RequestIdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioJsonRpc20RequestIdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioJsonRpc20RequestIdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioJsonRpc20RequestIdVariant1 {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "RPC method name (for example 'tools/call', 'initialize', 'sampling/createMessage').",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioJsonRpc20RequestMethod(::std::string::String);
impl ::std::ops::Deref for ChioJsonRpc20RequestMethod {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioJsonRpc20RequestMethod> for ::std::string::String {
    fn from(value: ChioJsonRpc20RequestMethod) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioJsonRpc20RequestMethod> for ChioJsonRpc20RequestMethod {
    fn from(value: &ChioJsonRpc20RequestMethod) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioJsonRpc20RequestMethod {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioJsonRpc20RequestMethod {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioJsonRpc20RequestMethod {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioJsonRpc20RequestMethod {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioJsonRpc20RequestMethod {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Method parameters. JSON-RPC 2.0 allows omission for parameterless methods; structured params are typically an object, occasionally an array.",
///  "oneOf": [
///    {
///      "type": "object"
///    },
///    {
///      "type": "array"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ChioJsonRpc20RequestParams {
    Variant0(::serde_json::Map<::std::string::String, ::serde_json::Value>),
    Variant1(::std::vec::Vec<::serde_json::Value>),
}
impl ::std::convert::From<&Self> for ChioJsonRpc20RequestParams {
    fn from(value: &ChioJsonRpc20RequestParams) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<::serde_json::Map<::std::string::String, ::serde_json::Value>>
for ChioJsonRpc20RequestParams {
    fn from(
        value: ::serde_json::Map<::std::string::String, ::serde_json::Value>,
    ) -> Self {
        Self::Variant0(value)
    }
}
impl ::std::convert::From<::std::vec::Vec<::serde_json::Value>>
for ChioJsonRpc20RequestParams {
    fn from(value: ::std::vec::Vec<::serde_json::Value>) -> Self {
        Self::Variant1(value)
    }
}
///JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed in `crates/chio-mcp-adapter/src/transport.rs::json_rpc_result` and `json_rpc_error` (lines 1299-1316) and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 243-255). Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in transport.rs lines 1280-1297). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/jsonrpc/response/v1",
///  "title": "Chio JSON-RPC 2.0 Response",
///  "description": "JSON-RPC 2.0 response envelope used by Chio for MCP and A2A wire framing. Mirrors the inline serde shapes constructed in `crates/chio-mcp-adapter/src/transport.rs::json_rpc_result` and `json_rpc_error` (lines 1299-1316) and the typed `A2aJsonRpcResponse<T>` / `A2aJsonRpcError` in `crates/chio-a2a-adapter/src/protocol.rs` (lines 243-255). Exactly one of `result` or `error` MUST be present, enforced via `oneOf`. The `error.code` field is an integer (Chio uses standard JSON-RPC reserved codes -32600 through -32603, MCP's -32800 for cancellation, and Chio extension codes such as -32002 for nested-flow policy denials and -32042 for URL elicitations required - see `map_nested_flow_error_code` in transport.rs lines 1280-1297). The `id` is null only when the server cannot determine the request id (parse error before the id was readable).",
///  "type": "object",
///  "oneOf": [
///    {
///      "not": {
///        "required": [
///          "error"
///        ]
///      },
///      "required": [
///        "result"
///      ]
///    },
///    {
///      "not": {
///        "required": [
///          "result"
///        ]
///      },
///      "required": [
///        "error"
///      ]
///    }
///  ],
///  "required": [
///    "id",
///    "jsonrpc"
///  ],
///  "properties": {
///    "error": {
///      "description": "Error payload. Present only on failure. Mutually exclusive with `result`.",
///      "type": "object",
///      "required": [
///        "code",
///        "message"
///      ],
///      "properties": {
///        "code": {
///          "description": "JSON-RPC 2.0 error code. Reserved range -32768..-32000 is implementation-defined; Chio uses -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32800 (request cancelled, MCP), -32002 (nested-flow policy denial, Chio), -32042 (URL elicitations required, Chio).",
///          "type": "integer"
///        },
///        "data": {
///          "description": "Optional structured detail. Shape is method- or code-specific."
///        },
///        "message": {
///          "description": "Short human-readable error description.",
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    },
///    "id": {
///      "description": "Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).",
///      "oneOf": [
///        {
///          "type": "integer"
///        },
///        {
///          "type": "string",
///          "minLength": 1
///        },
///        {
///          "type": "null"
///        }
///      ]
///    },
///    "jsonrpc": {
///      "description": "Protocol version literal. Always the string '2.0'.",
///      "const": "2.0"
///    },
///    "result": {
///      "description": "Method-specific success payload. Present only on success. Mutually exclusive with `error`. Shape is method-defined; commonly an object."
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged, deny_unknown_fields)]
pub enum ChioJsonRpc20Response {
    Variant0 {
        ///Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).
        id: ChioJsonRpc20ResponseVariant0Id,
        ///Protocol version literal. Always the string '2.0'.
        jsonrpc: ::serde_json::Value,
        ///Method-specific success payload. Present only on success. Mutually exclusive with `error`. Shape is method-defined; commonly an object.
        result: ::serde_json::Value,
    },
    Variant1 {
        error: ChioJsonRpc20ResponseVariant1Error,
        ///Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).
        id: ChioJsonRpc20ResponseVariant1Id,
        ///Protocol version literal. Always the string '2.0'.
        jsonrpc: ::serde_json::Value,
    },
}
impl ::std::convert::From<&Self> for ChioJsonRpc20Response {
    fn from(value: &ChioJsonRpc20Response) -> Self {
        value.clone()
    }
}
///Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).",
///  "oneOf": [
///    {
///      "type": "integer"
///    },
///    {
///      "type": "string",
///      "minLength": 1
///    },
///    {
///      "type": "null"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ChioJsonRpc20ResponseVariant0Id {
    Variant0(i64),
    Variant1(ChioJsonRpc20ResponseVariant0IdVariant1),
    Variant2,
}
impl ::std::convert::From<&Self> for ChioJsonRpc20ResponseVariant0Id {
    fn from(value: &ChioJsonRpc20ResponseVariant0Id) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<i64> for ChioJsonRpc20ResponseVariant0Id {
    fn from(value: i64) -> Self {
        Self::Variant0(value)
    }
}
impl ::std::convert::From<ChioJsonRpc20ResponseVariant0IdVariant1>
for ChioJsonRpc20ResponseVariant0Id {
    fn from(value: ChioJsonRpc20ResponseVariant0IdVariant1) -> Self {
        Self::Variant1(value)
    }
}
///`ChioJsonRpc20ResponseVariant0IdVariant1`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioJsonRpc20ResponseVariant0IdVariant1(::std::string::String);
impl ::std::ops::Deref for ChioJsonRpc20ResponseVariant0IdVariant1 {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioJsonRpc20ResponseVariant0IdVariant1>
for ::std::string::String {
    fn from(value: ChioJsonRpc20ResponseVariant0IdVariant1) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioJsonRpc20ResponseVariant0IdVariant1>
for ChioJsonRpc20ResponseVariant0IdVariant1 {
    fn from(value: &ChioJsonRpc20ResponseVariant0IdVariant1) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioJsonRpc20ResponseVariant0IdVariant1 {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioJsonRpc20ResponseVariant0IdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioJsonRpc20ResponseVariant0IdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioJsonRpc20ResponseVariant0IdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioJsonRpc20ResponseVariant0IdVariant1 {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Error payload. Present only on failure. Mutually exclusive with `result`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Error payload. Present only on failure. Mutually exclusive with `result`.",
///  "type": "object",
///  "required": [
///    "code",
///    "message"
///  ],
///  "properties": {
///    "code": {
///      "description": "JSON-RPC 2.0 error code. Reserved range -32768..-32000 is implementation-defined; Chio uses -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32800 (request cancelled, MCP), -32002 (nested-flow policy denial, Chio), -32042 (URL elicitations required, Chio).",
///      "type": "integer"
///    },
///    "data": {
///      "description": "Optional structured detail. Shape is method- or code-specific."
///    },
///    "message": {
///      "description": "Short human-readable error description.",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioJsonRpc20ResponseVariant1Error {
    ///JSON-RPC 2.0 error code. Reserved range -32768..-32000 is implementation-defined; Chio uses -32600 (Invalid Request), -32601 (Method not found), -32602 (Invalid params), -32603 (Internal error), -32800 (request cancelled, MCP), -32002 (nested-flow policy denial, Chio), -32042 (URL elicitations required, Chio).
    pub code: i64,
    ///Optional structured detail. Shape is method- or code-specific.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub data: ::std::option::Option<::serde_json::Value>,
    ///Short human-readable error description.
    pub message: ChioJsonRpc20ResponseVariant1ErrorMessage,
}
impl ::std::convert::From<&ChioJsonRpc20ResponseVariant1Error>
for ChioJsonRpc20ResponseVariant1Error {
    fn from(value: &ChioJsonRpc20ResponseVariant1Error) -> Self {
        value.clone()
    }
}
///Short human-readable error description.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Short human-readable error description.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioJsonRpc20ResponseVariant1ErrorMessage(::std::string::String);
impl ::std::ops::Deref for ChioJsonRpc20ResponseVariant1ErrorMessage {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioJsonRpc20ResponseVariant1ErrorMessage>
for ::std::string::String {
    fn from(value: ChioJsonRpc20ResponseVariant1ErrorMessage) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioJsonRpc20ResponseVariant1ErrorMessage>
for ChioJsonRpc20ResponseVariant1ErrorMessage {
    fn from(value: &ChioJsonRpc20ResponseVariant1ErrorMessage) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioJsonRpc20ResponseVariant1ErrorMessage {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioJsonRpc20ResponseVariant1ErrorMessage {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioJsonRpc20ResponseVariant1ErrorMessage {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioJsonRpc20ResponseVariant1ErrorMessage {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioJsonRpc20ResponseVariant1ErrorMessage {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Echoes the request id. Null only for error responses where the server failed to parse the request id (parse error or invalid request, per JSON-RPC 2.0 section 5).",
///  "oneOf": [
///    {
///      "type": "integer"
///    },
///    {
///      "type": "string",
///      "minLength": 1
///    },
///    {
///      "type": "null"
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ChioJsonRpc20ResponseVariant1Id {
    Variant0(i64),
    Variant1(ChioJsonRpc20ResponseVariant1IdVariant1),
    Variant2,
}
impl ::std::convert::From<&Self> for ChioJsonRpc20ResponseVariant1Id {
    fn from(value: &ChioJsonRpc20ResponseVariant1Id) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<i64> for ChioJsonRpc20ResponseVariant1Id {
    fn from(value: i64) -> Self {
        Self::Variant0(value)
    }
}
impl ::std::convert::From<ChioJsonRpc20ResponseVariant1IdVariant1>
for ChioJsonRpc20ResponseVariant1Id {
    fn from(value: ChioJsonRpc20ResponseVariant1IdVariant1) -> Self {
        Self::Variant1(value)
    }
}
///`ChioJsonRpc20ResponseVariant1IdVariant1`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioJsonRpc20ResponseVariant1IdVariant1(::std::string::String);
impl ::std::ops::Deref for ChioJsonRpc20ResponseVariant1IdVariant1 {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioJsonRpc20ResponseVariant1IdVariant1>
for ::std::string::String {
    fn from(value: ChioJsonRpc20ResponseVariant1IdVariant1) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioJsonRpc20ResponseVariant1IdVariant1>
for ChioJsonRpc20ResponseVariant1IdVariant1 {
    fn from(value: &ChioJsonRpc20ResponseVariant1IdVariant1) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioJsonRpc20ResponseVariant1IdVariant1 {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioJsonRpc20ResponseVariant1IdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioJsonRpc20ResponseVariant1IdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioJsonRpc20ResponseVariant1IdVariant1 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioJsonRpc20ResponseVariant1IdVariant1 {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityList`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio KernelMessage capability_list",
///  "type": "object",
///  "required": [
///    "capabilities",
///    "type"
///  ],
///  "properties": {
///    "capabilities": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "expires_at",
///          "id",
///          "issued_at",
///          "issuer",
///          "scope",
///          "signature",
///          "subject"
///        ],
///        "properties": {
///          "delegation_chain": {
///            "type": "array",
///            "items": {
///              "type": "object",
///              "required": [
///                "capability_id",
///                "delegatee",
///                "delegator",
///                "signature",
///                "timestamp"
///              ],
///              "properties": {
///                "attenuations": {
///                  "type": "array",
///                  "items": {
///                    "type": "object"
///                  }
///                },
///                "capability_id": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "delegatee": {
///                  "type": "string",
///                  "pattern": "^[0-9a-f]{64}$"
///                },
///                "delegator": {
///                  "type": "string",
///                  "pattern": "^[0-9a-f]{64}$"
///                },
///                "signature": {
///                  "type": "string",
///                  "pattern": "^[0-9a-f]{128}$"
///                },
///                "timestamp": {
///                  "type": "integer",
///                  "minimum": 0.0
///                }
///              },
///              "additionalProperties": false
///            }
///          },
///          "expires_at": {
///            "type": "integer",
///            "minimum": 0.0
///          },
///          "id": {
///            "type": "string",
///            "minLength": 1
///          },
///          "issued_at": {
///            "type": "integer",
///            "minimum": 0.0
///          },
///          "issuer": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{64}$"
///          },
///          "scope": {
///            "type": "object",
///            "properties": {
///              "grants": {
///                "type": "array",
///                "items": {
///                  "type": "object",
///                  "required": [
///                    "operations",
///                    "server_id",
///                    "tool_name"
///                  ],
///                  "properties": {
///                    "constraints": {
///                      "type": "array",
///                      "items": {
///                        "type": "object",
///                        "required": [
///                          "type"
///                        ],
///                        "properties": {
///                          "type": {
///                            "type": "string",
///                            "minLength": 1
///                          },
///                          "value": true
///                        }
///                      }
///                    },
///                    "dpop_required": {
///                      "type": "boolean"
///                    },
///                    "max_cost_per_invocation": {
///                      "type": "object",
///                      "required": [
///                        "currency",
///                        "units"
///                      ],
///                      "properties": {
///                        "currency": {
///                          "type": "string",
///                          "minLength": 1
///                        },
///                        "units": {
///                          "type": "integer",
///                          "minimum": 0.0
///                        }
///                      },
///                      "additionalProperties": false
///                    },
///                    "max_invocations": {
///                      "type": "integer",
///                      "minimum": 0.0
///                    },
///                    "max_total_cost": {
///                      "type": "object",
///                      "required": [
///                        "currency",
///                        "units"
///                      ],
///                      "properties": {
///                        "currency": {
///                          "type": "string",
///                          "minLength": 1
///                        },
///                        "units": {
///                          "type": "integer",
///                          "minimum": 0.0
///                        }
///                      },
///                      "additionalProperties": false
///                    },
///                    "operations": {
///                      "type": "array",
///                      "items": {
///                        "enum": [
///                          "invoke",
///                          "read_result",
///                          "read",
///                          "subscribe",
///                          "get",
///                          "delegate"
///                        ]
///                      },
///                      "minItems": 1
///                    },
///                    "server_id": {
///                      "type": "string",
///                      "minLength": 1
///                    },
///                    "tool_name": {
///                      "type": "string",
///                      "minLength": 1
///                    }
///                  },
///                  "additionalProperties": false
///                }
///              },
///              "prompt_grants": {
///                "type": "array",
///                "items": {
///                  "type": "object",
///                  "required": [
///                    "operations",
///                    "prompt_name"
///                  ],
///                  "properties": {
///                    "operations": {
///                      "type": "array",
///                      "items": {
///                        "enum": [
///                          "invoke",
///                          "read_result",
///                          "read",
///                          "subscribe",
///                          "get",
///                          "delegate"
///                        ]
///                      },
///                      "minItems": 1
///                    },
///                    "prompt_name": {
///                      "type": "string",
///                      "minLength": 1
///                    }
///                  },
///                  "additionalProperties": false
///                }
///              },
///              "resource_grants": {
///                "type": "array",
///                "items": {
///                  "type": "object",
///                  "required": [
///                    "operations",
///                    "uri_pattern"
///                  ],
///                  "properties": {
///                    "operations": {
///                      "type": "array",
///                      "items": {
///                        "enum": [
///                          "invoke",
///                          "read_result",
///                          "read",
///                          "subscribe",
///                          "get",
///                          "delegate"
///                        ]
///                      },
///                      "minItems": 1
///                    },
///                    "uri_pattern": {
///                      "type": "string",
///                      "minLength": 1
///                    }
///                  },
///                  "additionalProperties": false
///                }
///              }
///            },
///            "additionalProperties": false
///          },
///          "signature": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{128}$"
///          },
///          "subject": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{64}$"
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "type": {
///      "const": "capability_list"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityList {
    pub capabilities: ::std::vec::Vec<ChioKernelMessageCapabilityListCapabilitiesItem>,
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioKernelMessageCapabilityList>
for ChioKernelMessageCapabilityList {
    fn from(value: &ChioKernelMessageCapabilityList) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "expires_at",
///    "id",
///    "issued_at",
///    "issuer",
///    "scope",
///    "signature",
///    "subject"
///  ],
///  "properties": {
///    "delegation_chain": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "capability_id",
///          "delegatee",
///          "delegator",
///          "signature",
///          "timestamp"
///        ],
///        "properties": {
///          "attenuations": {
///            "type": "array",
///            "items": {
///              "type": "object"
///            }
///          },
///          "capability_id": {
///            "type": "string",
///            "minLength": 1
///          },
///          "delegatee": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{64}$"
///          },
///          "delegator": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{64}$"
///          },
///          "signature": {
///            "type": "string",
///            "pattern": "^[0-9a-f]{128}$"
///          },
///          "timestamp": {
///            "type": "integer",
///            "minimum": 0.0
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "expires_at": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "issued_at": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "issuer": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "scope": {
///      "type": "object",
///      "properties": {
///        "grants": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "operations",
///              "server_id",
///              "tool_name"
///            ],
///            "properties": {
///              "constraints": {
///                "type": "array",
///                "items": {
///                  "type": "object",
///                  "required": [
///                    "type"
///                  ],
///                  "properties": {
///                    "type": {
///                      "type": "string",
///                      "minLength": 1
///                    },
///                    "value": true
///                  }
///                }
///              },
///              "dpop_required": {
///                "type": "boolean"
///              },
///              "max_cost_per_invocation": {
///                "type": "object",
///                "required": [
///                  "currency",
///                  "units"
///                ],
///                "properties": {
///                  "currency": {
///                    "type": "string",
///                    "minLength": 1
///                  },
///                  "units": {
///                    "type": "integer",
///                    "minimum": 0.0
///                  }
///                },
///                "additionalProperties": false
///              },
///              "max_invocations": {
///                "type": "integer",
///                "minimum": 0.0
///              },
///              "max_total_cost": {
///                "type": "object",
///                "required": [
///                  "currency",
///                  "units"
///                ],
///                "properties": {
///                  "currency": {
///                    "type": "string",
///                    "minLength": 1
///                  },
///                  "units": {
///                    "type": "integer",
///                    "minimum": 0.0
///                  }
///                },
///                "additionalProperties": false
///              },
///              "operations": {
///                "type": "array",
///                "items": {
///                  "enum": [
///                    "invoke",
///                    "read_result",
///                    "read",
///                    "subscribe",
///                    "get",
///                    "delegate"
///                  ]
///                },
///                "minItems": 1
///              },
///              "server_id": {
///                "type": "string",
///                "minLength": 1
///              },
///              "tool_name": {
///                "type": "string",
///                "minLength": 1
///              }
///            },
///            "additionalProperties": false
///          }
///        },
///        "prompt_grants": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "operations",
///              "prompt_name"
///            ],
///            "properties": {
///              "operations": {
///                "type": "array",
///                "items": {
///                  "enum": [
///                    "invoke",
///                    "read_result",
///                    "read",
///                    "subscribe",
///                    "get",
///                    "delegate"
///                  ]
///                },
///                "minItems": 1
///              },
///              "prompt_name": {
///                "type": "string",
///                "minLength": 1
///              }
///            },
///            "additionalProperties": false
///          }
///        },
///        "resource_grants": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "operations",
///              "uri_pattern"
///            ],
///            "properties": {
///              "operations": {
///                "type": "array",
///                "items": {
///                  "enum": [
///                    "invoke",
///                    "read_result",
///                    "read",
///                    "subscribe",
///                    "get",
///                    "delegate"
///                  ]
///                },
///                "minItems": 1
///              },
///              "uri_pattern": {
///                "type": "string",
///                "minLength": 1
///              }
///            },
///            "additionalProperties": false
///          }
///        }
///      },
///      "additionalProperties": false
///    },
///    "signature": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{128}$"
///    },
///    "subject": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItem {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub delegation_chain: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItem,
    >,
    pub expires_at: u64,
    pub id: ChioKernelMessageCapabilityListCapabilitiesItemId,
    pub issued_at: u64,
    pub issuer: ChioKernelMessageCapabilityListCapabilitiesItemIssuer,
    pub scope: ChioKernelMessageCapabilityListCapabilitiesItemScope,
    pub signature: ChioKernelMessageCapabilityListCapabilitiesItemSignature,
    pub subject: ChioKernelMessageCapabilityListCapabilitiesItemSubject,
}
impl ::std::convert::From<&ChioKernelMessageCapabilityListCapabilitiesItem>
for ChioKernelMessageCapabilityListCapabilitiesItem {
    fn from(value: &ChioKernelMessageCapabilityListCapabilitiesItem) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "capability_id",
///    "delegatee",
///    "delegator",
///    "signature",
///    "timestamp"
///  ],
///  "properties": {
///    "attenuations": {
///      "type": "array",
///      "items": {
///        "type": "object"
///      }
///    },
///    "capability_id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "delegatee": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "delegator": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "signature": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{128}$"
///    },
///    "timestamp": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItem {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub attenuations: ::std::vec::Vec<
        ::serde_json::Map<::std::string::String, ::serde_json::Value>,
    >,
    pub capability_id: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId,
    pub delegatee: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee,
    pub delegator: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator,
    pub signature: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature,
    pub timestamp: u64,
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItem,
> for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId,
> for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemCapabilityId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee,
> for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegatee {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator,
> for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemDelegator {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{128}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature,
> for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{128}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{128}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemDelegationChainItemSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemId(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageCapabilityListCapabilitiesItemId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageCapabilityListCapabilitiesItemId>
for ::std::string::String {
    fn from(value: ChioKernelMessageCapabilityListCapabilitiesItemId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageCapabilityListCapabilitiesItemId>
for ChioKernelMessageCapabilityListCapabilitiesItemId {
    fn from(value: &ChioKernelMessageCapabilityListCapabilitiesItemId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageCapabilityListCapabilitiesItemId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemIssuer`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemIssuer(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageCapabilityListCapabilitiesItemIssuer {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageCapabilityListCapabilitiesItemIssuer>
for ::std::string::String {
    fn from(value: ChioKernelMessageCapabilityListCapabilitiesItemIssuer) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageCapabilityListCapabilitiesItemIssuer>
for ChioKernelMessageCapabilityListCapabilitiesItemIssuer {
    fn from(value: &ChioKernelMessageCapabilityListCapabilitiesItemIssuer) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageCapabilityListCapabilitiesItemIssuer {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemIssuer {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScope`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "properties": {
///    "grants": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "operations",
///          "server_id",
///          "tool_name"
///        ],
///        "properties": {
///          "constraints": {
///            "type": "array",
///            "items": {
///              "type": "object",
///              "required": [
///                "type"
///              ],
///              "properties": {
///                "type": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "value": true
///              }
///            }
///          },
///          "dpop_required": {
///            "type": "boolean"
///          },
///          "max_cost_per_invocation": {
///            "type": "object",
///            "required": [
///              "currency",
///              "units"
///            ],
///            "properties": {
///              "currency": {
///                "type": "string",
///                "minLength": 1
///              },
///              "units": {
///                "type": "integer",
///                "minimum": 0.0
///              }
///            },
///            "additionalProperties": false
///          },
///          "max_invocations": {
///            "type": "integer",
///            "minimum": 0.0
///          },
///          "max_total_cost": {
///            "type": "object",
///            "required": [
///              "currency",
///              "units"
///            ],
///            "properties": {
///              "currency": {
///                "type": "string",
///                "minLength": 1
///              },
///              "units": {
///                "type": "integer",
///                "minimum": 0.0
///              }
///            },
///            "additionalProperties": false
///          },
///          "operations": {
///            "type": "array",
///            "items": {
///              "enum": [
///                "invoke",
///                "read_result",
///                "read",
///                "subscribe",
///                "get",
///                "delegate"
///              ]
///            },
///            "minItems": 1
///          },
///          "server_id": {
///            "type": "string",
///            "minLength": 1
///          },
///          "tool_name": {
///            "type": "string",
///            "minLength": 1
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "prompt_grants": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "operations",
///          "prompt_name"
///        ],
///        "properties": {
///          "operations": {
///            "type": "array",
///            "items": {
///              "enum": [
///                "invoke",
///                "read_result",
///                "read",
///                "subscribe",
///                "get",
///                "delegate"
///              ]
///            },
///            "minItems": 1
///          },
///          "prompt_name": {
///            "type": "string",
///            "minLength": 1
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "resource_grants": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "operations",
///          "uri_pattern"
///        ],
///        "properties": {
///          "operations": {
///            "type": "array",
///            "items": {
///              "enum": [
///                "invoke",
///                "read_result",
///                "read",
///                "subscribe",
///                "get",
///                "delegate"
///              ]
///            },
///            "minItems": 1
///          },
///          "uri_pattern": {
///            "type": "string",
///            "minLength": 1
///          }
///        },
///        "additionalProperties": false
///      }
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScope {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub grants: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItem,
    >,
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub prompt_grants: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItem,
    >,
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub resource_grants: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItem,
    >,
}
impl ::std::convert::From<&ChioKernelMessageCapabilityListCapabilitiesItemScope>
for ChioKernelMessageCapabilityListCapabilitiesItemScope {
    fn from(value: &ChioKernelMessageCapabilityListCapabilitiesItemScope) -> Self {
        value.clone()
    }
}
impl ::std::default::Default for ChioKernelMessageCapabilityListCapabilitiesItemScope {
    fn default() -> Self {
        Self {
            grants: Default::default(),
            prompt_grants: Default::default(),
            resource_grants: Default::default(),
        }
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "operations",
///    "server_id",
///    "tool_name"
///  ],
///  "properties": {
///    "constraints": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "type"
///        ],
///        "properties": {
///          "type": {
///            "type": "string",
///            "minLength": 1
///          },
///          "value": true
///        }
///      }
///    },
///    "dpop_required": {
///      "type": "boolean"
///    },
///    "max_cost_per_invocation": {
///      "type": "object",
///      "required": [
///        "currency",
///        "units"
///      ],
///      "properties": {
///        "currency": {
///          "type": "string",
///          "minLength": 1
///        },
///        "units": {
///          "type": "integer",
///          "minimum": 0.0
///        }
///      },
///      "additionalProperties": false
///    },
///    "max_invocations": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "max_total_cost": {
///      "type": "object",
///      "required": [
///        "currency",
///        "units"
///      ],
///      "properties": {
///        "currency": {
///          "type": "string",
///          "minLength": 1
///        },
///        "units": {
///          "type": "integer",
///          "minimum": 0.0
///        }
///      },
///      "additionalProperties": false
///    },
///    "operations": {
///      "type": "array",
///      "items": {
///        "enum": [
///          "invoke",
///          "read_result",
///          "read",
///          "subscribe",
///          "get",
///          "delegate"
///        ]
///      },
///      "minItems": 1
///    },
///    "server_id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "tool_name": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItem {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub constraints: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItem,
    >,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub dpop_required: ::std::option::Option<bool>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_cost_per_invocation: ::std::option::Option<
        ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocation,
    >,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_invocations: ::std::option::Option<u64>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_total_cost: ::std::option::Option<
        ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCost,
    >,
    pub operations: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem,
    >,
    pub server_id: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId,
    pub tool_name: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName,
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItem,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "type": "string",
///      "minLength": 1
///    },
///    "value": true
///  }
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItem {
    #[serde(rename = "type")]
    pub type_: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub value: ::std::option::Option<::serde_json::Value>,
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItem,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemConstraintsItemType {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocation`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "currency",
///    "units"
///  ],
///  "properties": {
///    "currency": {
///      "type": "string",
///      "minLength": 1
///    },
///    "units": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocation {
    pub currency: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency,
    pub units: u64,
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocation,
>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocation {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocation,
    ) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency,
>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxCostPerInvocationCurrency {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCost`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "currency",
///    "units"
///  ],
///  "properties": {
///    "currency": {
///      "type": "string",
///      "minLength": 1
///    },
///    "units": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCost {
    pub currency: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency,
    pub units: u64,
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCost,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCost {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCost,
    ) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency,
>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemMaxTotalCostCurrency {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemServerId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeGrantsItemToolName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "operations",
///    "prompt_name"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "enum": [
///          "invoke",
///          "read_result",
///          "read",
///          "subscribe",
///          "get",
///          "delegate"
///        ]
///      },
///      "minItems": 1
///    },
///    "prompt_name": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItem {
    pub operations: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem,
    >,
    pub prompt_name: ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName,
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItem,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemScopePromptGrantsItemPromptName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "operations",
///    "uri_pattern"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "enum": [
///          "invoke",
///          "read_result",
///          "read",
///          "subscribe",
///          "get",
///          "delegate"
///        ]
///      },
///      "minItems": 1
///    },
///    "uri_pattern": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItem {
    pub operations: ::std::vec::Vec<
        ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem,
    >,
    pub uri_pattern: ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern,
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItem,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItem,
    ) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemOperationsItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern,
> for ::std::string::String {
    fn from(
        value: ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern,
> for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern {
    fn from(
        value: &ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemScopeResourceGrantsItemUriPattern {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemSignature`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{128}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemSignature(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioKernelMessageCapabilityListCapabilitiesItemSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageCapabilityListCapabilitiesItemSignature>
for ::std::string::String {
    fn from(value: ChioKernelMessageCapabilityListCapabilitiesItemSignature) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageCapabilityListCapabilitiesItemSignature>
for ChioKernelMessageCapabilityListCapabilitiesItemSignature {
    fn from(value: &ChioKernelMessageCapabilityListCapabilitiesItemSignature) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageCapabilityListCapabilitiesItemSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{128}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{128}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityListCapabilitiesItemSubject`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityListCapabilitiesItemSubject(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageCapabilityListCapabilitiesItemSubject {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageCapabilityListCapabilitiesItemSubject>
for ::std::string::String {
    fn from(value: ChioKernelMessageCapabilityListCapabilitiesItemSubject) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageCapabilityListCapabilitiesItemSubject>
for ChioKernelMessageCapabilityListCapabilitiesItemSubject {
    fn from(value: &ChioKernelMessageCapabilityListCapabilitiesItemSubject) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageCapabilityListCapabilitiesItemSubject {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageCapabilityListCapabilitiesItemSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityListCapabilitiesItemSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageCapabilityListCapabilitiesItemSubject {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageCapabilityRevoked`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio KernelMessage capability_revoked",
///  "type": "object",
///  "required": [
///    "id",
///    "type"
///  ],
///  "properties": {
///    "id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "type": {
///      "const": "capability_revoked"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageCapabilityRevoked {
    pub id: ChioKernelMessageCapabilityRevokedId,
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioKernelMessageCapabilityRevoked>
for ChioKernelMessageCapabilityRevoked {
    fn from(value: &ChioKernelMessageCapabilityRevoked) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageCapabilityRevokedId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageCapabilityRevokedId(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageCapabilityRevokedId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageCapabilityRevokedId>
for ::std::string::String {
    fn from(value: ChioKernelMessageCapabilityRevokedId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageCapabilityRevokedId>
for ChioKernelMessageCapabilityRevokedId {
    fn from(value: &ChioKernelMessageCapabilityRevokedId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageCapabilityRevokedId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioKernelMessageCapabilityRevokedId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageCapabilityRevokedId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageCapabilityRevokedId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioKernelMessageCapabilityRevokedId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageHeartbeat`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio KernelMessage heartbeat",
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "const": "heartbeat"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageHeartbeat {
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioKernelMessageHeartbeat> for ChioKernelMessageHeartbeat {
    fn from(value: &ChioKernelMessageHeartbeat) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallChunk`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio KernelMessage tool_call_chunk",
///  "type": "object",
///  "required": [
///    "chunk_index",
///    "data",
///    "id",
///    "type"
///  ],
///  "properties": {
///    "chunk_index": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "data": true,
///    "id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "type": {
///      "const": "tool_call_chunk"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageToolCallChunk {
    pub chunk_index: u64,
    pub data: ::serde_json::Value,
    pub id: ChioKernelMessageToolCallChunkId,
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioKernelMessageToolCallChunk>
for ChioKernelMessageToolCallChunk {
    fn from(value: &ChioKernelMessageToolCallChunk) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallChunkId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallChunkId(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallChunkId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallChunkId> for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallChunkId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallChunkId>
for ChioKernelMessageToolCallChunkId {
    fn from(value: &ChioKernelMessageToolCallChunkId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallChunkId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioKernelMessageToolCallChunkId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallChunkId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallChunkId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioKernelMessageToolCallChunkId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponse`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio KernelMessage tool_call_response",
///  "type": "object",
///  "required": [
///    "id",
///    "receipt",
///    "result",
///    "type"
///  ],
///  "properties": {
///    "id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "receipt": {
///      "type": "object",
///      "required": [
///        "action",
///        "capability_id",
///        "content_hash",
///        "decision",
///        "id",
///        "kernel_key",
///        "policy_hash",
///        "signature",
///        "timestamp",
///        "tool_name",
///        "tool_server"
///      ],
///      "properties": {
///        "action": {
///          "type": "object",
///          "required": [
///            "parameter_hash",
///            "parameters"
///          ],
///          "properties": {
///            "parameter_hash": {
///              "type": "string",
///              "pattern": "^[0-9a-f]{64}$"
///            },
///            "parameters": true
///          },
///          "additionalProperties": false
///        },
///        "capability_id": {
///          "type": "string",
///          "minLength": 1
///        },
///        "content_hash": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{64}$"
///        },
///        "decision": {
///          "oneOf": [
///            {
///              "type": "object",
///              "required": [
///                "verdict"
///              ],
///              "properties": {
///                "verdict": {
///                  "const": "allow"
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "guard",
///                "reason",
///                "verdict"
///              ],
///              "properties": {
///                "guard": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "reason": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "verdict": {
///                  "const": "deny"
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "reason",
///                "verdict"
///              ],
///              "properties": {
///                "reason": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "verdict": {
///                  "const": "cancelled"
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "reason",
///                "verdict"
///              ],
///              "properties": {
///                "reason": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "verdict": {
///                  "const": "incomplete"
///                }
///              },
///              "additionalProperties": false
///            }
///          ]
///        },
///        "evidence": {
///          "type": "array",
///          "items": {
///            "type": "object",
///            "required": [
///              "guard_name",
///              "verdict"
///            ],
///            "properties": {
///              "details": {
///                "type": "string"
///              },
///              "guard_name": {
///                "type": "string",
///                "minLength": 1
///              },
///              "verdict": {
///                "type": "boolean"
///              }
///            },
///            "additionalProperties": false
///          }
///        },
///        "id": {
///          "type": "string",
///          "minLength": 1
///        },
///        "kernel_key": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{64}$"
///        },
///        "metadata": true,
///        "policy_hash": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{64}$"
///        },
///        "signature": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{128}$"
///        },
///        "timestamp": {
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "tool_name": {
///          "type": "string",
///          "minLength": 1
///        },
///        "tool_server": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    },
///    "result": {
///      "oneOf": [
///        {
///          "type": "object",
///          "required": [
///            "status",
///            "value"
///          ],
///          "properties": {
///            "status": {
///              "const": "ok"
///            },
///            "value": true
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "status",
///            "total_chunks"
///          ],
///          "properties": {
///            "status": {
///              "const": "stream_complete"
///            },
///            "total_chunks": {
///              "type": "integer",
///              "minimum": 0.0
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "chunks_received",
///            "reason",
///            "status"
///          ],
///          "properties": {
///            "chunks_received": {
///              "type": "integer",
///              "minimum": 0.0
///            },
///            "reason": {
///              "type": "string",
///              "minLength": 1
///            },
///            "status": {
///              "const": "cancelled"
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "chunks_received",
///            "reason",
///            "status"
///          ],
///          "properties": {
///            "chunks_received": {
///              "type": "integer",
///              "minimum": 0.0
///            },
///            "reason": {
///              "type": "string",
///              "minLength": 1
///            },
///            "status": {
///              "const": "incomplete"
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "error",
///            "status"
///          ],
///          "properties": {
///            "error": {
///              "oneOf": [
///                {
///                  "type": "object",
///                  "required": [
///                    "code",
///                    "detail"
///                  ],
///                  "properties": {
///                    "code": {
///                      "const": "capability_denied"
///                    },
///                    "detail": {
///                      "type": "string",
///                      "minLength": 1
///                    }
///                  },
///                  "additionalProperties": false
///                },
///                {
///                  "type": "object",
///                  "required": [
///                    "code"
///                  ],
///                  "properties": {
///                    "code": {
///                      "const": "capability_expired"
///                    }
///                  },
///                  "additionalProperties": false
///                },
///                {
///                  "type": "object",
///                  "required": [
///                    "code"
///                  ],
///                  "properties": {
///                    "code": {
///                      "const": "capability_revoked"
///                    }
///                  },
///                  "additionalProperties": false
///                },
///                {
///                  "type": "object",
///                  "required": [
///                    "code",
///                    "detail"
///                  ],
///                  "properties": {
///                    "code": {
///                      "const": "policy_denied"
///                    },
///                    "detail": {
///                      "type": "object",
///                      "required": [
///                        "guard",
///                        "reason"
///                      ],
///                      "properties": {
///                        "guard": {
///                          "type": "string",
///                          "minLength": 1
///                        },
///                        "reason": {
///                          "type": "string",
///                          "minLength": 1
///                        }
///                      },
///                      "additionalProperties": false
///                    }
///                  },
///                  "additionalProperties": false
///                },
///                {
///                  "type": "object",
///                  "required": [
///                    "code",
///                    "detail"
///                  ],
///                  "properties": {
///                    "code": {
///                      "const": "tool_server_error"
///                    },
///                    "detail": {
///                      "type": "string",
///                      "minLength": 1
///                    }
///                  },
///                  "additionalProperties": false
///                },
///                {
///                  "type": "object",
///                  "required": [
///                    "code",
///                    "detail"
///                  ],
///                  "properties": {
///                    "code": {
///                      "const": "internal_error"
///                    },
///                    "detail": {
///                      "type": "string",
///                      "minLength": 1
///                    }
///                  },
///                  "additionalProperties": false
///                }
///              ]
///            },
///            "status": {
///              "const": "err"
///            }
///          },
///          "additionalProperties": false
///        }
///      ]
///    },
///    "type": {
///      "const": "tool_call_response"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageToolCallResponse {
    pub id: ChioKernelMessageToolCallResponseId,
    pub receipt: ChioKernelMessageToolCallResponseReceipt,
    pub result: ChioKernelMessageToolCallResponseResult,
    #[serde(rename = "type")]
    pub type_: ::serde_json::Value,
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponse>
for ChioKernelMessageToolCallResponse {
    fn from(value: &ChioKernelMessageToolCallResponse) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallResponseId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseId(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseId>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseId>
for ChioKernelMessageToolCallResponseId {
    fn from(value: &ChioKernelMessageToolCallResponseId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioKernelMessageToolCallResponseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioKernelMessageToolCallResponseId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceipt`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "action",
///    "capability_id",
///    "content_hash",
///    "decision",
///    "id",
///    "kernel_key",
///    "policy_hash",
///    "signature",
///    "timestamp",
///    "tool_name",
///    "tool_server"
///  ],
///  "properties": {
///    "action": {
///      "type": "object",
///      "required": [
///        "parameter_hash",
///        "parameters"
///      ],
///      "properties": {
///        "parameter_hash": {
///          "type": "string",
///          "pattern": "^[0-9a-f]{64}$"
///        },
///        "parameters": true
///      },
///      "additionalProperties": false
///    },
///    "capability_id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "content_hash": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "decision": {
///      "oneOf": [
///        {
///          "type": "object",
///          "required": [
///            "verdict"
///          ],
///          "properties": {
///            "verdict": {
///              "const": "allow"
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "guard",
///            "reason",
///            "verdict"
///          ],
///          "properties": {
///            "guard": {
///              "type": "string",
///              "minLength": 1
///            },
///            "reason": {
///              "type": "string",
///              "minLength": 1
///            },
///            "verdict": {
///              "const": "deny"
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "reason",
///            "verdict"
///          ],
///          "properties": {
///            "reason": {
///              "type": "string",
///              "minLength": 1
///            },
///            "verdict": {
///              "const": "cancelled"
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "reason",
///            "verdict"
///          ],
///          "properties": {
///            "reason": {
///              "type": "string",
///              "minLength": 1
///            },
///            "verdict": {
///              "const": "incomplete"
///            }
///          },
///          "additionalProperties": false
///        }
///      ]
///    },
///    "evidence": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "guard_name",
///          "verdict"
///        ],
///        "properties": {
///          "details": {
///            "type": "string"
///          },
///          "guard_name": {
///            "type": "string",
///            "minLength": 1
///          },
///          "verdict": {
///            "type": "boolean"
///          }
///        },
///        "additionalProperties": false
///      }
///    },
///    "id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "kernel_key": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "metadata": true,
///    "policy_hash": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "signature": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{128}$"
///    },
///    "timestamp": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "tool_name": {
///      "type": "string",
///      "minLength": 1
///    },
///    "tool_server": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageToolCallResponseReceipt {
    pub action: ChioKernelMessageToolCallResponseReceiptAction,
    pub capability_id: ChioKernelMessageToolCallResponseReceiptCapabilityId,
    pub content_hash: ChioKernelMessageToolCallResponseReceiptContentHash,
    pub decision: ChioKernelMessageToolCallResponseReceiptDecision,
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub evidence: ::std::vec::Vec<ChioKernelMessageToolCallResponseReceiptEvidenceItem>,
    pub id: ChioKernelMessageToolCallResponseReceiptId,
    pub kernel_key: ChioKernelMessageToolCallResponseReceiptKernelKey,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub metadata: ::std::option::Option<::serde_json::Value>,
    pub policy_hash: ChioKernelMessageToolCallResponseReceiptPolicyHash,
    pub signature: ChioKernelMessageToolCallResponseReceiptSignature,
    pub timestamp: u64,
    pub tool_name: ChioKernelMessageToolCallResponseReceiptToolName,
    pub tool_server: ChioKernelMessageToolCallResponseReceiptToolServer,
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceipt>
for ChioKernelMessageToolCallResponseReceipt {
    fn from(value: &ChioKernelMessageToolCallResponseReceipt) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallResponseReceiptAction`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "parameter_hash",
///    "parameters"
///  ],
///  "properties": {
///    "parameter_hash": {
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "parameters": true
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageToolCallResponseReceiptAction {
    pub parameter_hash: ChioKernelMessageToolCallResponseReceiptActionParameterHash,
    pub parameters: ::serde_json::Value,
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptAction>
for ChioKernelMessageToolCallResponseReceiptAction {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptAction) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallResponseReceiptActionParameterHash`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptActionParameterHash(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptActionParameterHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptActionParameterHash>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptActionParameterHash) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptActionParameterHash>
for ChioKernelMessageToolCallResponseReceiptActionParameterHash {
    fn from(
        value: &ChioKernelMessageToolCallResponseReceiptActionParameterHash,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageToolCallResponseReceiptActionParameterHash {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptActionParameterHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptActionParameterHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptActionParameterHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptActionParameterHash {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptCapabilityId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptCapabilityId(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptCapabilityId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptCapabilityId>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptCapabilityId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptCapabilityId>
for ChioKernelMessageToolCallResponseReceiptCapabilityId {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptCapabilityId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptCapabilityId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptCapabilityId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptContentHash`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptContentHash(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptContentHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptContentHash>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptContentHash) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptContentHash>
for ChioKernelMessageToolCallResponseReceiptContentHash {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptContentHash) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptContentHash {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptContentHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptContentHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptContentHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptContentHash {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptDecision`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "oneOf": [
///    {
///      "type": "object",
///      "required": [
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "allow"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "guard",
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "guard": {
///          "type": "string",
///          "minLength": 1
///        },
///        "reason": {
///          "type": "string",
///          "minLength": 1
///        },
///        "verdict": {
///          "const": "deny"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "reason": {
///          "type": "string",
///          "minLength": 1
///        },
///        "verdict": {
///          "const": "cancelled"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "reason": {
///          "type": "string",
///          "minLength": 1
///        },
///        "verdict": {
///          "const": "incomplete"
///        }
///      },
///      "additionalProperties": false
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(tag = "verdict", deny_unknown_fields)]
pub enum ChioKernelMessageToolCallResponseReceiptDecision {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny {
        guard: ChioKernelMessageToolCallResponseReceiptDecisionGuard,
        reason: ChioKernelMessageToolCallResponseReceiptDecisionReason,
    },
    #[serde(rename = "cancelled")]
    Cancelled { reason: ChioKernelMessageToolCallResponseReceiptDecisionReason },
    #[serde(rename = "incomplete")]
    Incomplete { reason: ChioKernelMessageToolCallResponseReceiptDecisionReason },
}
impl ::std::convert::From<&Self> for ChioKernelMessageToolCallResponseReceiptDecision {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptDecision) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallResponseReceiptDecisionGuard`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptDecisionGuard(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptDecisionGuard {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptDecisionGuard>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptDecisionGuard) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptDecisionGuard>
for ChioKernelMessageToolCallResponseReceiptDecisionGuard {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptDecisionGuard) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptDecisionGuard {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptDecisionGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptDecisionGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptDecisionGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptDecisionGuard {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptDecisionReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptDecisionReason(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptDecisionReason {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptDecisionReason>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptDecisionReason) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptDecisionReason>
for ChioKernelMessageToolCallResponseReceiptDecisionReason {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptDecisionReason) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptDecisionReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptDecisionReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptDecisionReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptDecisionReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptDecisionReason {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptEvidenceItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "guard_name",
///    "verdict"
///  ],
///  "properties": {
///    "details": {
///      "type": "string"
///    },
///    "guard_name": {
///      "type": "string",
///      "minLength": 1
///    },
///    "verdict": {
///      "type": "boolean"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioKernelMessageToolCallResponseReceiptEvidenceItem {
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub details: ::std::option::Option<::std::string::String>,
    pub guard_name: ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName,
    pub verdict: bool,
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptEvidenceItem>
for ChioKernelMessageToolCallResponseReceiptEvidenceItem {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptEvidenceItem) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName>
for ::std::string::String {
    fn from(
        value: ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName>
for ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName {
    fn from(
        value: &ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptEvidenceItemGuardName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptId(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptId>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptId>
for ChioKernelMessageToolCallResponseReceiptId {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioKernelMessageToolCallResponseReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioKernelMessageToolCallResponseReceiptId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptKernelKey`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptKernelKey(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptKernelKey {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptKernelKey>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptKernelKey) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptKernelKey>
for ChioKernelMessageToolCallResponseReceiptKernelKey {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptKernelKey) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptKernelKey {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptKernelKey {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptKernelKey {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptKernelKey {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptKernelKey {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptPolicyHash`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptPolicyHash(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptPolicyHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptPolicyHash>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptPolicyHash) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptPolicyHash>
for ChioKernelMessageToolCallResponseReceiptPolicyHash {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptPolicyHash) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptPolicyHash {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptPolicyHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptPolicyHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptPolicyHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptPolicyHash {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptSignature`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "pattern": "^[0-9a-f]{128}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptSignature(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptSignature>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptSignature) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptSignature>
for ChioKernelMessageToolCallResponseReceiptSignature {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptSignature) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{128}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{128}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptToolName`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptToolName(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptToolName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptToolName>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptToolName) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptToolName>
for ChioKernelMessageToolCallResponseReceiptToolName {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptToolName) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptToolName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioKernelMessageToolCallResponseReceiptToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptToolName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseReceiptToolServer`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseReceiptToolServer(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseReceiptToolServer {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseReceiptToolServer>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseReceiptToolServer) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseReceiptToolServer>
for ChioKernelMessageToolCallResponseReceiptToolServer {
    fn from(value: &ChioKernelMessageToolCallResponseReceiptToolServer) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseReceiptToolServer {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseReceiptToolServer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseReceiptToolServer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseReceiptToolServer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseReceiptToolServer {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseResult`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "oneOf": [
///    {
///      "type": "object",
///      "required": [
///        "status",
///        "value"
///      ],
///      "properties": {
///        "status": {
///          "const": "ok"
///        },
///        "value": true
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "status",
///        "total_chunks"
///      ],
///      "properties": {
///        "status": {
///          "const": "stream_complete"
///        },
///        "total_chunks": {
///          "type": "integer",
///          "minimum": 0.0
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "chunks_received",
///        "reason",
///        "status"
///      ],
///      "properties": {
///        "chunks_received": {
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "reason": {
///          "type": "string",
///          "minLength": 1
///        },
///        "status": {
///          "const": "cancelled"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "chunks_received",
///        "reason",
///        "status"
///      ],
///      "properties": {
///        "chunks_received": {
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "reason": {
///          "type": "string",
///          "minLength": 1
///        },
///        "status": {
///          "const": "incomplete"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "error",
///        "status"
///      ],
///      "properties": {
///        "error": {
///          "oneOf": [
///            {
///              "type": "object",
///              "required": [
///                "code",
///                "detail"
///              ],
///              "properties": {
///                "code": {
///                  "const": "capability_denied"
///                },
///                "detail": {
///                  "type": "string",
///                  "minLength": 1
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "code"
///              ],
///              "properties": {
///                "code": {
///                  "const": "capability_expired"
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "code"
///              ],
///              "properties": {
///                "code": {
///                  "const": "capability_revoked"
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "code",
///                "detail"
///              ],
///              "properties": {
///                "code": {
///                  "const": "policy_denied"
///                },
///                "detail": {
///                  "type": "object",
///                  "required": [
///                    "guard",
///                    "reason"
///                  ],
///                  "properties": {
///                    "guard": {
///                      "type": "string",
///                      "minLength": 1
///                    },
///                    "reason": {
///                      "type": "string",
///                      "minLength": 1
///                    }
///                  },
///                  "additionalProperties": false
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "code",
///                "detail"
///              ],
///              "properties": {
///                "code": {
///                  "const": "tool_server_error"
///                },
///                "detail": {
///                  "type": "string",
///                  "minLength": 1
///                }
///              },
///              "additionalProperties": false
///            },
///            {
///              "type": "object",
///              "required": [
///                "code",
///                "detail"
///              ],
///              "properties": {
///                "code": {
///                  "const": "internal_error"
///                },
///                "detail": {
///                  "type": "string",
///                  "minLength": 1
///                }
///              },
///              "additionalProperties": false
///            }
///          ]
///        },
///        "status": {
///          "const": "err"
///        }
///      },
///      "additionalProperties": false
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(tag = "status", deny_unknown_fields)]
pub enum ChioKernelMessageToolCallResponseResult {
    #[serde(rename = "ok")]
    Ok { value: ::serde_json::Value },
    #[serde(rename = "stream_complete")]
    StreamComplete { total_chunks: u64 },
    #[serde(rename = "cancelled")]
    Cancelled {
        chunks_received: u64,
        reason: ChioKernelMessageToolCallResponseResultReason,
    },
    #[serde(rename = "incomplete")]
    Incomplete {
        chunks_received: u64,
        reason: ChioKernelMessageToolCallResponseResultReason,
    },
    #[serde(rename = "err")]
    Err { error: ChioKernelMessageToolCallResponseResultError },
}
impl ::std::convert::From<&Self> for ChioKernelMessageToolCallResponseResult {
    fn from(value: &ChioKernelMessageToolCallResponseResult) -> Self {
        value.clone()
    }
}
///`ChioKernelMessageToolCallResponseResultError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "oneOf": [
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "capability_denied"
///        },
///        "detail": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code"
///      ],
///      "properties": {
///        "code": {
///          "const": "capability_expired"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code"
///      ],
///      "properties": {
///        "code": {
///          "const": "capability_revoked"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "policy_denied"
///        },
///        "detail": {
///          "type": "object",
///          "required": [
///            "guard",
///            "reason"
///          ],
///          "properties": {
///            "guard": {
///              "type": "string",
///              "minLength": 1
///            },
///            "reason": {
///              "type": "string",
///              "minLength": 1
///            }
///          },
///          "additionalProperties": false
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "tool_server_error"
///        },
///        "detail": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "internal_error"
///        },
///        "detail": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(tag = "code", content = "detail", deny_unknown_fields)]
pub enum ChioKernelMessageToolCallResponseResultError {
    #[serde(rename = "capability_denied")]
    CapabilityDenied(ChioKernelMessageToolCallResponseResultErrorCapabilityDenied),
    #[serde(rename = "capability_expired")]
    CapabilityExpired,
    #[serde(rename = "capability_revoked")]
    CapabilityRevoked,
    #[serde(rename = "policy_denied")]
    PolicyDenied {
        guard: ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard,
        reason: ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason,
    },
    #[serde(rename = "tool_server_error")]
    ToolServerError(ChioKernelMessageToolCallResponseResultErrorToolServerError),
    #[serde(rename = "internal_error")]
    InternalError(ChioKernelMessageToolCallResponseResultErrorInternalError),
}
impl ::std::convert::From<&Self> for ChioKernelMessageToolCallResponseResultError {
    fn from(value: &ChioKernelMessageToolCallResponseResultError) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorCapabilityDenied>
for ChioKernelMessageToolCallResponseResultError {
    fn from(
        value: ChioKernelMessageToolCallResponseResultErrorCapabilityDenied,
    ) -> Self {
        Self::CapabilityDenied(value)
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorToolServerError>
for ChioKernelMessageToolCallResponseResultError {
    fn from(value: ChioKernelMessageToolCallResponseResultErrorToolServerError) -> Self {
        Self::ToolServerError(value)
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorInternalError>
for ChioKernelMessageToolCallResponseResultError {
    fn from(value: ChioKernelMessageToolCallResponseResultErrorInternalError) -> Self {
        Self::InternalError(value)
    }
}
///`ChioKernelMessageToolCallResponseResultErrorCapabilityDenied`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseResultErrorCapabilityDenied(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseResultErrorCapabilityDenied {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorCapabilityDenied>
for ::std::string::String {
    fn from(
        value: ChioKernelMessageToolCallResponseResultErrorCapabilityDenied,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseResultErrorCapabilityDenied>
for ChioKernelMessageToolCallResponseResultErrorCapabilityDenied {
    fn from(
        value: &ChioKernelMessageToolCallResponseResultErrorCapabilityDenied,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageToolCallResponseResultErrorCapabilityDenied {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseResultErrorCapabilityDenied {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorCapabilityDenied {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorCapabilityDenied {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseResultErrorCapabilityDenied {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseResultErrorInternalError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseResultErrorInternalError(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseResultErrorInternalError {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorInternalError>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseResultErrorInternalError) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseResultErrorInternalError>
for ChioKernelMessageToolCallResponseResultErrorInternalError {
    fn from(value: &ChioKernelMessageToolCallResponseResultErrorInternalError) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseResultErrorInternalError {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseResultErrorInternalError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorInternalError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorInternalError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseResultErrorInternalError {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard>
for ::std::string::String {
    fn from(
        value: ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard {
    fn from(
        value: &ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedGuard {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason>
for ::std::string::String {
    fn from(
        value: ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason,
> for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason {
    fn from(
        value: &ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseResultErrorPolicyDeniedReason {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseResultErrorToolServerError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseResultErrorToolServerError(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseResultErrorToolServerError {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultErrorToolServerError>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseResultErrorToolServerError) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseResultErrorToolServerError>
for ChioKernelMessageToolCallResponseResultErrorToolServerError {
    fn from(
        value: &ChioKernelMessageToolCallResponseResultErrorToolServerError,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioKernelMessageToolCallResponseResultErrorToolServerError {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioKernelMessageToolCallResponseResultErrorToolServerError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorToolServerError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseResultErrorToolServerError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioKernelMessageToolCallResponseResultErrorToolServerError {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioKernelMessageToolCallResponseResultReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioKernelMessageToolCallResponseResultReason(::std::string::String);
impl ::std::ops::Deref for ChioKernelMessageToolCallResponseResultReason {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioKernelMessageToolCallResponseResultReason>
for ::std::string::String {
    fn from(value: ChioKernelMessageToolCallResponseResultReason) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioKernelMessageToolCallResponseResultReason>
for ChioKernelMessageToolCallResponseResultReason {
    fn from(value: &ChioKernelMessageToolCallResponseResultReason) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioKernelMessageToolCallResponseResultReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioKernelMessageToolCallResponseResultReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioKernelMessageToolCallResponseResultReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioKernelMessageToolCallResponseResultReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioKernelMessageToolCallResponseResultReason {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///One bundle of corroborating runtime attestation evidence statements that anchor a governed call-chain context to a verified runtime. Names the `chainId` it binds to (matching `provenance/context.schema.json`), the canonical evidence-class Chio resolved across the bundle, the unix-second `assembledAt` timestamp, and the ordered list of normalized statements. Each statement mirrors the `RuntimeAttestationEvidence` shape and is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json`; the family is inlined rather than `$ref`'d. Field names are camelCase to match `GovernedCallChainContext`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/provenance/attestation-bundle/v1",
///  "title": "Chio Provenance Attestation Bundle",
///  "description": "One bundle of corroborating runtime attestation evidence statements that anchor a governed call-chain context to a verified runtime. Names the `chainId` it binds to (matching `provenance/context.schema.json`), the canonical evidence-class Chio resolved across the bundle, the unix-second `assembledAt` timestamp, and the ordered list of normalized statements. Each statement mirrors the `RuntimeAttestationEvidence` shape and is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json`; the family is inlined rather than `$ref`'d. Field names are camelCase to match `GovernedCallChainContext`.",
///  "type": "object",
///  "required": [
///    "assembledAt",
///    "chainId",
///    "evidenceClass",
///    "statements"
///  ],
///  "properties": {
///    "assembledAt": {
///      "description": "Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "chainId": {
///      "description": "Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.",
///      "type": "string",
///      "minLength": 1
///    },
///    "evidenceClass": {
///      "description": "Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.",
///      "type": "string",
///      "enum": [
///        "asserted",
///        "observed",
///        "verified"
///      ]
///    },
///    "issuer": {
///      "description": "Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.",
///      "type": "string",
///      "minLength": 1
///    },
///    "statements": {
///      "description": "Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.",
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "evidence_sha256",
///          "expires_at",
///          "issued_at",
///          "schema",
///          "tier",
///          "verifier"
///        ],
///        "properties": {
///          "claims": {
///            "description": "Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`."
///          },
///          "evidence_sha256": {
///            "description": "Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
///            "type": "string",
///            "minLength": 1
///          },
///          "expires_at": {
///            "description": "Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.",
///            "type": "integer",
///            "minimum": 0.0
///          },
///          "issued_at": {
///            "description": "Unix timestamp (seconds) when this attestation was issued.",
///            "type": "integer",
///            "minimum": 0.0
///          },
///          "runtime_identity": {
///            "description": "Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.",
///            "type": "string",
///            "minLength": 1
///          },
///          "schema": {
///            "description": "Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
///            "type": "string",
///            "minLength": 1
///          },
///          "tier": {
///            "description": "Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).",
///            "type": "string",
///            "enum": [
///              "none",
///              "basic",
///              "attested",
///              "verified"
///            ]
///          },
///          "verifier": {
///            "description": "Attestation verifier or relying party that accepted the evidence.",
///            "type": "string",
///            "minLength": 1
///          },
///          "workload_identity": {
///            "description": "Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.",
///            "type": "object",
///            "required": [
///              "credentialKind",
///              "path",
///              "scheme",
///              "trustDomain",
///              "uri"
///            ],
///            "properties": {
///              "credentialKind": {
///                "description": "Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
///                "type": "string",
///                "enum": [
///                  "uri",
///                  "x509_svid",
///                  "jwt_svid"
///                ]
///              },
///              "path": {
///                "description": "Canonical workload path within the trust domain.",
///                "type": "string"
///              },
///              "scheme": {
///                "description": "Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
///                "type": "string",
///                "enum": [
///                  "spiffe"
///                ]
///              },
///              "trustDomain": {
///                "description": "Stable trust domain resolved from the identifier.",
///                "type": "string",
///                "minLength": 1
///              },
///              "uri": {
///                "description": "Canonical workload identifier URI.",
///                "type": "string",
///                "minLength": 1
///              }
///            },
///            "additionalProperties": false
///          }
///        },
///        "additionalProperties": false
///      },
///      "minItems": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioProvenanceAttestationBundle {
    ///Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.
    #[serde(rename = "assembledAt")]
    pub assembled_at: u64,
    ///Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.
    #[serde(rename = "chainId")]
    pub chain_id: ChioProvenanceAttestationBundleChainId,
    ///Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
    #[serde(rename = "evidenceClass")]
    pub evidence_class: ChioProvenanceAttestationBundleEvidenceClass,
    ///Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub issuer: ::std::option::Option<ChioProvenanceAttestationBundleIssuer>,
    ///Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.
    pub statements: ::std::vec::Vec<ChioProvenanceAttestationBundleStatementsItem>,
}
impl ::std::convert::From<&ChioProvenanceAttestationBundle>
for ChioProvenanceAttestationBundle {
    fn from(value: &ChioProvenanceAttestationBundle) -> Self {
        value.clone()
    }
}
///Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleChainId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceAttestationBundleChainId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceAttestationBundleChainId>
for ::std::string::String {
    fn from(value: ChioProvenanceAttestationBundleChainId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleChainId>
for ChioProvenanceAttestationBundleChainId {
    fn from(value: &ChioProvenanceAttestationBundleChainId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceAttestationBundleChainId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceAttestationBundleChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceAttestationBundleChainId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.",
///  "type": "string",
///  "enum": [
///    "asserted",
///    "observed",
///    "verified"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceAttestationBundleEvidenceClass {
    #[serde(rename = "asserted")]
    Asserted,
    #[serde(rename = "observed")]
    Observed,
    #[serde(rename = "verified")]
    Verified,
}
impl ::std::convert::From<&Self> for ChioProvenanceAttestationBundleEvidenceClass {
    fn from(value: &ChioProvenanceAttestationBundleEvidenceClass) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioProvenanceAttestationBundleEvidenceClass {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Asserted => f.write_str("asserted"),
            Self::Observed => f.write_str("observed"),
            Self::Verified => f.write_str("verified"),
        }
    }
}
impl ::std::str::FromStr for ChioProvenanceAttestationBundleEvidenceClass {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "asserted" => Ok(Self::Asserted),
            "observed" => Ok(Self::Observed),
            "verified" => Ok(Self::Verified),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceAttestationBundleEvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleEvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleEvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleIssuer(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceAttestationBundleIssuer {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceAttestationBundleIssuer>
for ::std::string::String {
    fn from(value: ChioProvenanceAttestationBundleIssuer) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleIssuer>
for ChioProvenanceAttestationBundleIssuer {
    fn from(value: &ChioProvenanceAttestationBundleIssuer) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceAttestationBundleIssuer {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceAttestationBundleIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleIssuer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceAttestationBundleIssuer {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioProvenanceAttestationBundleStatementsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "evidence_sha256",
///    "expires_at",
///    "issued_at",
///    "schema",
///    "tier",
///    "verifier"
///  ],
///  "properties": {
///    "claims": {
///      "description": "Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`."
///    },
///    "evidence_sha256": {
///      "description": "Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
///      "type": "string",
///      "minLength": 1
///    },
///    "expires_at": {
///      "description": "Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "issued_at": {
///      "description": "Unix timestamp (seconds) when this attestation was issued.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "runtime_identity": {
///      "description": "Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.",
///      "type": "string",
///      "minLength": 1
///    },
///    "schema": {
///      "description": "Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
///      "type": "string",
///      "minLength": 1
///    },
///    "tier": {
///      "description": "Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).",
///      "type": "string",
///      "enum": [
///        "none",
///        "basic",
///        "attested",
///        "verified"
///      ]
///    },
///    "verifier": {
///      "description": "Attestation verifier or relying party that accepted the evidence.",
///      "type": "string",
///      "minLength": 1
///    },
///    "workload_identity": {
///      "description": "Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.",
///      "type": "object",
///      "required": [
///        "credentialKind",
///        "path",
///        "scheme",
///        "trustDomain",
///        "uri"
///      ],
///      "properties": {
///        "credentialKind": {
///          "description": "Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
///          "type": "string",
///          "enum": [
///            "uri",
///            "x509_svid",
///            "jwt_svid"
///          ]
///        },
///        "path": {
///          "description": "Canonical workload path within the trust domain.",
///          "type": "string"
///        },
///        "scheme": {
///          "description": "Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
///          "type": "string",
///          "enum": [
///            "spiffe"
///          ]
///        },
///        "trustDomain": {
///          "description": "Stable trust domain resolved from the identifier.",
///          "type": "string",
///          "minLength": 1
///        },
///        "uri": {
///          "description": "Canonical workload identifier URI.",
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioProvenanceAttestationBundleStatementsItem {
    ///Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub claims: ::std::option::Option<::serde_json::Value>,
    ///Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
    pub evidence_sha256: ChioProvenanceAttestationBundleStatementsItemEvidenceSha256,
    ///Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.
    pub expires_at: u64,
    ///Unix timestamp (seconds) when this attestation was issued.
    pub issued_at: u64,
    ///Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub runtime_identity: ::std::option::Option<
        ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity,
    >,
    ///Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
    pub schema: ChioProvenanceAttestationBundleStatementsItemSchema,
    ///Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).
    pub tier: ChioProvenanceAttestationBundleStatementsItemTier,
    ///Attestation verifier or relying party that accepted the evidence.
    pub verifier: ChioProvenanceAttestationBundleStatementsItemVerifier,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub workload_identity: ::std::option::Option<
        ChioProvenanceAttestationBundleStatementsItemWorkloadIdentity,
    >,
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleStatementsItem>
for ChioProvenanceAttestationBundleStatementsItem {
    fn from(value: &ChioProvenanceAttestationBundleStatementsItem) -> Self {
        value.clone()
    }
}
///Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleStatementsItemEvidenceSha256(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioProvenanceAttestationBundleStatementsItemEvidenceSha256 {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceAttestationBundleStatementsItemEvidenceSha256>
for ::std::string::String {
    fn from(value: ChioProvenanceAttestationBundleStatementsItemEvidenceSha256) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleStatementsItemEvidenceSha256>
for ChioProvenanceAttestationBundleStatementsItemEvidenceSha256 {
    fn from(
        value: &ChioProvenanceAttestationBundleStatementsItemEvidenceSha256,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioProvenanceAttestationBundleStatementsItemEvidenceSha256 {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemEvidenceSha256 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemEvidenceSha256 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemEvidenceSha256 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceAttestationBundleStatementsItemEvidenceSha256 {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity>
for ::std::string::String {
    fn from(
        value: ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity>
for ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity {
    fn from(
        value: &ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceAttestationBundleStatementsItemRuntimeIdentity {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleStatementsItemSchema(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceAttestationBundleStatementsItemSchema {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceAttestationBundleStatementsItemSchema>
for ::std::string::String {
    fn from(value: ChioProvenanceAttestationBundleStatementsItemSchema) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleStatementsItemSchema>
for ChioProvenanceAttestationBundleStatementsItemSchema {
    fn from(value: &ChioProvenanceAttestationBundleStatementsItemSchema) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceAttestationBundleStatementsItemSchema {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemSchema {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemSchema {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemSchema {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceAttestationBundleStatementsItemSchema {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).",
///  "type": "string",
///  "enum": [
///    "none",
///    "basic",
///    "attested",
///    "verified"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceAttestationBundleStatementsItemTier {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "basic")]
    Basic,
    #[serde(rename = "attested")]
    Attested,
    #[serde(rename = "verified")]
    Verified,
}
impl ::std::convert::From<&Self> for ChioProvenanceAttestationBundleStatementsItemTier {
    fn from(value: &ChioProvenanceAttestationBundleStatementsItemTier) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioProvenanceAttestationBundleStatementsItemTier {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::None => f.write_str("none"),
            Self::Basic => f.write_str("basic"),
            Self::Attested => f.write_str("attested"),
            Self::Verified => f.write_str("verified"),
        }
    }
}
impl ::std::str::FromStr for ChioProvenanceAttestationBundleStatementsItemTier {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "none" => Ok(Self::None),
            "basic" => Ok(Self::Basic),
            "attested" => Ok(Self::Attested),
            "verified" => Ok(Self::Verified),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemTier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemTier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemTier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Attestation verifier or relying party that accepted the evidence.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Attestation verifier or relying party that accepted the evidence.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleStatementsItemVerifier(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceAttestationBundleStatementsItemVerifier {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceAttestationBundleStatementsItemVerifier>
for ::std::string::String {
    fn from(value: ChioProvenanceAttestationBundleStatementsItemVerifier) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleStatementsItemVerifier>
for ChioProvenanceAttestationBundleStatementsItemVerifier {
    fn from(value: &ChioProvenanceAttestationBundleStatementsItemVerifier) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceAttestationBundleStatementsItemVerifier {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemVerifier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemVerifier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemVerifier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceAttestationBundleStatementsItemVerifier {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.",
///  "type": "object",
///  "required": [
///    "credentialKind",
///    "path",
///    "scheme",
///    "trustDomain",
///    "uri"
///  ],
///  "properties": {
///    "credentialKind": {
///      "description": "Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
///      "type": "string",
///      "enum": [
///        "uri",
///        "x509_svid",
///        "jwt_svid"
///      ]
///    },
///    "path": {
///      "description": "Canonical workload path within the trust domain.",
///      "type": "string"
///    },
///    "scheme": {
///      "description": "Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
///      "type": "string",
///      "enum": [
///        "spiffe"
///      ]
///    },
///    "trustDomain": {
///      "description": "Stable trust domain resolved from the identifier.",
///      "type": "string",
///      "minLength": 1
///    },
///    "uri": {
///      "description": "Canonical workload identifier URI.",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioProvenanceAttestationBundleStatementsItemWorkloadIdentity {
    ///Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
    #[serde(rename = "credentialKind")]
    pub credential_kind: ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind,
    ///Canonical workload path within the trust domain.
    pub path: ::std::string::String,
    ///Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
    pub scheme: ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme,
    ///Stable trust domain resolved from the identifier.
    #[serde(rename = "trustDomain")]
    pub trust_domain: ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain,
    ///Canonical workload identifier URI.
    pub uri: ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri,
}
impl ::std::convert::From<&ChioProvenanceAttestationBundleStatementsItemWorkloadIdentity>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentity {
    fn from(
        value: &ChioProvenanceAttestationBundleStatementsItemWorkloadIdentity,
    ) -> Self {
        value.clone()
    }
}
///Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
///  "type": "string",
///  "enum": [
///    "uri",
///    "x509_svid",
///    "jwt_svid"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind {
    #[serde(rename = "uri")]
    Uri,
    #[serde(rename = "x509_svid")]
    X509Svid,
    #[serde(rename = "jwt_svid")]
    JwtSvid,
}
impl ::std::convert::From<&Self>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind {
    fn from(
        value: &ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Uri => f.write_str("uri"),
            Self::X509Svid => f.write_str("x509_svid"),
            Self::JwtSvid => f.write_str("jwt_svid"),
        }
    }
}
impl ::std::str::FromStr
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "uri" => Ok(Self::Uri),
            "x509_svid" => Ok(Self::X509Svid),
            "jwt_svid" => Ok(Self::JwtSvid),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityCredentialKind {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
///  "type": "string",
///  "enum": [
///    "spiffe"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme {
    #[serde(rename = "spiffe")]
    Spiffe,
}
impl ::std::convert::From<&Self>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme {
    fn from(
        value: &ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Spiffe => f.write_str("spiffe"),
        }
    }
}
impl ::std::str::FromStr
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "spiffe" => Ok(Self::Spiffe),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityScheme {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Stable trust domain resolved from the identifier.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable trust domain resolved from the identifier.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain,
> for ::std::string::String {
    fn from(
        value: ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain,
> for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain {
    fn from(
        value: &ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityTrustDomain {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Canonical workload identifier URI.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Canonical workload identifier URI.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri,
> for ::std::string::String {
    fn from(
        value: ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri,
> for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri {
    fn from(
        value: &ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceAttestationBundleStatementsItemWorkloadIdentityUri {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///One delegated call-chain context bound into a governed Chio request. The context names the stable `chainId` that identifies the delegated transaction, the upstream `parentRequestId` inside the trusted domain, the optional `parentReceiptId` when the upstream parent receipt is already available, the root `originSubject` that started the chain, and the immediate `delegatorSubject` that handed control to the current subject. Chio binds this shape into governed transactions and promotes it through the provenance evidence classes (`asserted`, `observed`, `verified`) defined in `crates/chio-core-types/src/capability.rs` (`GovernedProvenanceEvidenceClass`, lines 1303-1314). Mirrors the `GovernedCallChainContext` struct in `crates/chio-core-types/src/capability.rs` (lines 952-967). The struct uses `serde(rename_all = camelCase)` so wire field names are camelCase.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/provenance/context/v1",
///  "title": "Chio Provenance Call-Chain Context",
///  "description": "One delegated call-chain context bound into a governed Chio request. The context names the stable `chainId` that identifies the delegated transaction, the upstream `parentRequestId` inside the trusted domain, the optional `parentReceiptId` when the upstream parent receipt is already available, the root `originSubject` that started the chain, and the immediate `delegatorSubject` that handed control to the current subject. Chio binds this shape into governed transactions and promotes it through the provenance evidence classes (`asserted`, `observed`, `verified`) defined in `crates/chio-core-types/src/capability.rs` (`GovernedProvenanceEvidenceClass`, lines 1303-1314). Mirrors the `GovernedCallChainContext` struct in `crates/chio-core-types/src/capability.rs` (lines 952-967). The struct uses `serde(rename_all = camelCase)` so wire field names are camelCase.",
///  "type": "object",
///  "required": [
///    "chainId",
///    "delegatorSubject",
///    "originSubject",
///    "parentRequestId"
///  ],
///  "properties": {
///    "chainId": {
///      "description": "Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.",
///      "type": "string",
///      "minLength": 1
///    },
///    "delegatorSubject": {
///      "description": "Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.",
///      "type": "string",
///      "minLength": 1
///    },
///    "originSubject": {
///      "description": "Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).",
///      "type": "string",
///      "minLength": 1
///    },
///    "parentReceiptId": {
///      "description": "Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.",
///      "type": "string",
///      "minLength": 1
///    },
///    "parentRequestId": {
///      "description": "Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioProvenanceCallChainContext {
    ///Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.
    #[serde(rename = "chainId")]
    pub chain_id: ChioProvenanceCallChainContextChainId,
    ///Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.
    #[serde(rename = "delegatorSubject")]
    pub delegator_subject: ChioProvenanceCallChainContextDelegatorSubject,
    ///Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).
    #[serde(rename = "originSubject")]
    pub origin_subject: ChioProvenanceCallChainContextOriginSubject,
    ///Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.
    #[serde(
        rename = "parentReceiptId",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub parent_receipt_id: ::std::option::Option<
        ChioProvenanceCallChainContextParentReceiptId,
    >,
    ///Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.
    #[serde(rename = "parentRequestId")]
    pub parent_request_id: ChioProvenanceCallChainContextParentRequestId,
}
impl ::std::convert::From<&ChioProvenanceCallChainContext>
for ChioProvenanceCallChainContext {
    fn from(value: &ChioProvenanceCallChainContext) -> Self {
        value.clone()
    }
}
///Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceCallChainContextChainId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceCallChainContextChainId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceCallChainContextChainId>
for ::std::string::String {
    fn from(value: ChioProvenanceCallChainContextChainId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceCallChainContextChainId>
for ChioProvenanceCallChainContextChainId {
    fn from(value: &ChioProvenanceCallChainContextChainId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceCallChainContextChainId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceCallChainContextChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceCallChainContextChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceCallChainContextChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceCallChainContextChainId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceCallChainContextDelegatorSubject(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceCallChainContextDelegatorSubject {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceCallChainContextDelegatorSubject>
for ::std::string::String {
    fn from(value: ChioProvenanceCallChainContextDelegatorSubject) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceCallChainContextDelegatorSubject>
for ChioProvenanceCallChainContextDelegatorSubject {
    fn from(value: &ChioProvenanceCallChainContextDelegatorSubject) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceCallChainContextDelegatorSubject {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceCallChainContextDelegatorSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceCallChainContextDelegatorSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceCallChainContextDelegatorSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceCallChainContextDelegatorSubject {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceCallChainContextOriginSubject(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceCallChainContextOriginSubject {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceCallChainContextOriginSubject>
for ::std::string::String {
    fn from(value: ChioProvenanceCallChainContextOriginSubject) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceCallChainContextOriginSubject>
for ChioProvenanceCallChainContextOriginSubject {
    fn from(value: &ChioProvenanceCallChainContextOriginSubject) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceCallChainContextOriginSubject {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceCallChainContextOriginSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceCallChainContextOriginSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceCallChainContextOriginSubject {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceCallChainContextOriginSubject {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceCallChainContextParentReceiptId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceCallChainContextParentReceiptId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceCallChainContextParentReceiptId>
for ::std::string::String {
    fn from(value: ChioProvenanceCallChainContextParentReceiptId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceCallChainContextParentReceiptId>
for ChioProvenanceCallChainContextParentReceiptId {
    fn from(value: &ChioProvenanceCallChainContextParentReceiptId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceCallChainContextParentReceiptId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceCallChainContextParentReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceCallChainContextParentReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceCallChainContextParentReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceCallChainContextParentReceiptId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceCallChainContextParentRequestId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceCallChainContextParentRequestId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceCallChainContextParentRequestId>
for ::std::string::String {
    fn from(value: ChioProvenanceCallChainContextParentRequestId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceCallChainContextParentRequestId>
for ChioProvenanceCallChainContextParentRequestId {
    fn from(value: &ChioProvenanceCallChainContextParentRequestId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceCallChainContextParentRequestId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceCallChainContextParentRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceCallChainContextParentRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceCallChainContextParentRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceCallChainContextParentRequestId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///One provenance stamp attached by a Chio provider adapter to every tool-call response. Names the upstream `provider`, the upstream `request_id`, the wire `api_version`, the `principal` Chio resolved as the calling subject, and the unix-second `received_at` timestamp. Field names are snake_case to match `RuntimeAttestationEvidence`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/provenance/stamp/v1",
///  "title": "Chio Provenance Stamp",
///  "description": "One provenance stamp attached by a Chio provider adapter to every tool-call response. Names the upstream `provider`, the upstream `request_id`, the wire `api_version`, the `principal` Chio resolved as the calling subject, and the unix-second `received_at` timestamp. Field names are snake_case to match `RuntimeAttestationEvidence`.",
///  "type": "object",
///  "required": [
///    "api_version",
///    "principal",
///    "provider",
///    "received_at",
///    "request_id"
///  ],
///  "properties": {
///    "api_version": {
///      "description": "Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.",
///      "type": "string",
///      "minLength": 1
///    },
///    "principal": {
///      "description": "Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.",
///      "type": "string",
///      "minLength": 1
///    },
///    "provider": {
///      "description": "Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`). M07 owns the canonical adapter identifier registry.",
///      "type": "string",
///      "minLength": 1
///    },
///    "received_at": {
///      "description": "Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; M07 fails closed if the value is in the future relative to the kernel clock.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "request_id": {
///      "description": "Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioProvenanceStamp {
    ///Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.
    pub api_version: ChioProvenanceStampApiVersion,
    ///Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.
    pub principal: ChioProvenanceStampPrincipal,
    ///Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`). M07 owns the canonical adapter identifier registry.
    pub provider: ChioProvenanceStampProvider,
    ///Unix timestamp (seconds) at which Chio observed the provider response. Monotonic with respect to receipts emitted from the same kernel; M07 fails closed if the value is in the future relative to the kernel clock.
    pub received_at: u64,
    ///Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.
    pub request_id: ChioProvenanceStampRequestId,
}
impl ::std::convert::From<&ChioProvenanceStamp> for ChioProvenanceStamp {
    fn from(value: &ChioProvenanceStamp) -> Self {
        value.clone()
    }
}
///Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Wire version of the upstream provider API that served the call. Free-form per provider (for example `2024-08-01-preview` for Azure OpenAI, `v1` for Anthropic). Frozen per stamp; bumps require a new stamp.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceStampApiVersion(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceStampApiVersion {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceStampApiVersion> for ::std::string::String {
    fn from(value: ChioProvenanceStampApiVersion) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceStampApiVersion>
for ChioProvenanceStampApiVersion {
    fn from(value: &ChioProvenanceStampApiVersion) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceStampApiVersion {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceStampApiVersion {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioProvenanceStampApiVersion {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioProvenanceStampApiVersion {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceStampApiVersion {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Calling subject Chio resolved at the kernel boundary, in the same canonical form used by capability tokens (subject public key or normalized workload identity). Bound into the provenance graph alongside the receipt principal.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceStampPrincipal(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceStampPrincipal {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceStampPrincipal> for ::std::string::String {
    fn from(value: ChioProvenanceStampPrincipal) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceStampPrincipal>
for ChioProvenanceStampPrincipal {
    fn from(value: &ChioProvenanceStampPrincipal) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceStampPrincipal {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceStampPrincipal {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioProvenanceStampPrincipal {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioProvenanceStampPrincipal {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceStampPrincipal {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`). M07 owns the canonical adapter identifier registry.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier of the upstream provider adapter that handled the tool call (for example `openai`, `anthropic`, `google-vertex`). M07 owns the canonical adapter identifier registry.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceStampProvider(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceStampProvider {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceStampProvider> for ::std::string::String {
    fn from(value: ChioProvenanceStampProvider) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceStampProvider> for ChioProvenanceStampProvider {
    fn from(value: &ChioProvenanceStampProvider) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceStampProvider {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceStampProvider {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioProvenanceStampProvider {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioProvenanceStampProvider {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceStampProvider {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Upstream request identifier returned by the provider for this call. Opaque to Chio; preserved verbatim so operators can correlate Chio receipts with provider-side logs.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceStampRequestId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceStampRequestId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceStampRequestId> for ::std::string::String {
    fn from(value: ChioProvenanceStampRequestId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceStampRequestId>
for ChioProvenanceStampRequestId {
    fn from(value: &ChioProvenanceStampRequestId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceStampRequestId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceStampRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioProvenanceStampRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioProvenanceStampRequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioProvenanceStampRequestId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///One link binding a Chio policy verdict to the provenance graph. The link names the `verdict` decision that Chio's policy engine returned (`allow`, `deny`, `cancel`, `incomplete`), the `requestId` and optional `receiptId` the verdict applies to, and the `chainId` that ties the verdict back to a delegated call-chain context. Verdict-specific required fields are enforced via `oneOf` so the wire shape stays in lock-step with the HTTP verdict union in `spec/schemas/chio-http/v1/verdict.schema.json`: `deny` requires both `reason` and `guard`; `cancel` and `incomplete` require `reason`; `allow` rejects either. The verdict vocabulary mirrors the HTTP verdict tagged union and the per-step verdict family `StepVerdictKind` in `crates/chio-core-types/src/plan.rs` (lines 110-138). NOTE: there is no live `VerdictLink` Rust struct on this branch; the link is drafted as the wire form of the verdict-to-provenance edge that M07's tool-call fabric and the M01 receipt-record schema reference indirectly today. The dedicated Rust struct is expected to land alongside the M07 phase that wires the tool-call fabric to the provenance graph and the schema will be re-pinned to that serde shape at that time. Field names are camelCase to match the `GovernedCallChainContext` family this link binds to.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/provenance/verdict-link/v1",
///  "title": "Chio Provenance Verdict Link",
///  "description": "One link binding a Chio policy verdict to the provenance graph. The link names the `verdict` decision that Chio's policy engine returned (`allow`, `deny`, `cancel`, `incomplete`), the `requestId` and optional `receiptId` the verdict applies to, and the `chainId` that ties the verdict back to a delegated call-chain context. Verdict-specific required fields are enforced via `oneOf` so the wire shape stays in lock-step with the HTTP verdict union in `spec/schemas/chio-http/v1/verdict.schema.json`: `deny` requires both `reason` and `guard`; `cancel` and `incomplete` require `reason`; `allow` rejects either. The verdict vocabulary mirrors the HTTP verdict tagged union and the per-step verdict family `StepVerdictKind` in `crates/chio-core-types/src/plan.rs` (lines 110-138). NOTE: there is no live `VerdictLink` Rust struct on this branch; the link is drafted as the wire form of the verdict-to-provenance edge that M07's tool-call fabric and the M01 receipt-record schema reference indirectly today. The dedicated Rust struct is expected to land alongside the M07 phase that wires the tool-call fabric to the provenance graph and the schema will be re-pinned to that serde shape at that time. Field names are camelCase to match the `GovernedCallChainContext` family this link binds to.",
///  "type": "object",
///  "oneOf": [
///    {
///      "title": "allow",
///      "description": "Allow verdicts MUST NOT carry `reason` or `guard`; the policy engine emits these fields only on rejection.",
///      "not": {
///        "anyOf": [
///          {
///            "required": [
///              "reason"
///            ]
///          },
///          {
///            "required": [
///              "guard"
///            ]
///          }
///        ]
///      },
///      "required": [
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "allow"
///        }
///      }
///    },
///    {
///      "title": "deny",
///      "description": "Deny verdicts MUST carry both a human-readable `reason` and the `guard` identifier that produced the denial. Mirrors the deny branch of `chio-http/v1/verdict.schema.json`.",
///      "required": [
///        "guard",
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "deny"
///        }
///      }
///    },
///    {
///      "title": "cancel",
///      "description": "Cancel verdicts MUST carry `reason` (operator or transport cancellation rationale) and MUST NOT carry `guard`.",
///      "not": {
///        "required": [
///          "guard"
///        ]
///      },
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "cancel"
///        }
///      }
///    },
///    {
///      "title": "incomplete",
///      "description": "Incomplete verdicts MUST carry `reason` describing the terminal failure mode (for example interrupted upstream stream) and MUST NOT carry `guard`.",
///      "not": {
///        "required": [
///          "guard"
///        ]
///      },
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "incomplete"
///        }
///      }
///    }
///  ],
///  "required": [
///    "chainId",
///    "renderedAt",
///    "requestId",
///    "verdict"
///  ],
///  "properties": {
///    "chainId": {
///      "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///      "type": "string",
///      "minLength": 1
///    },
///    "evidenceClass": {
///      "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///      "type": "string",
///      "enum": [
///        "asserted",
///        "observed",
///        "verified"
///      ]
///    },
///    "guard": {
///      "description": "Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
///      "type": "string"
///    },
///    "reason": {
///      "description": "Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
///      "type": "string"
///    },
///    "receiptId": {
///      "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///      "type": "string",
///      "minLength": 1
///    },
///    "renderedAt": {
///      "description": "Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "requestId": {
///      "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///      "type": "string",
///      "minLength": 1
///    },
///    "verdict": {
///      "description": "Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
///      "type": "string",
///      "enum": [
///        "allow",
///        "deny",
///        "cancel",
///        "incomplete"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ChioProvenanceVerdictLink {
    Variant0(ChioProvenanceVerdictLinkVariant0),
    Variant1 {
        #[serde(
            flatten,
            default,
            skip_serializing_if = "::std::option::Option::is_none"
        )]
        subtype_0: ::std::option::Option<ChioProvenanceVerdictLinkVariant1Subtype0>,
        #[serde(
            flatten,
            default,
            skip_serializing_if = "::std::option::Option::is_none"
        )]
        subtype_1: ::std::option::Option<ChioProvenanceVerdictLinkVariant1Subtype1>,
    },
    Variant2(ChioProvenanceVerdictLinkVariant2),
    Variant3(ChioProvenanceVerdictLinkVariant3),
}
impl ::std::convert::From<&Self> for ChioProvenanceVerdictLink {
    fn from(value: &ChioProvenanceVerdictLink) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant0>
for ChioProvenanceVerdictLink {
    fn from(value: ChioProvenanceVerdictLinkVariant0) -> Self {
        Self::Variant0(value)
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant2>
for ChioProvenanceVerdictLink {
    fn from(value: ChioProvenanceVerdictLinkVariant2) -> Self {
        Self::Variant2(value)
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant3>
for ChioProvenanceVerdictLink {
    fn from(value: ChioProvenanceVerdictLinkVariant3) -> Self {
        Self::Variant3(value)
    }
}
///`ChioProvenanceVerdictLinkVariant0`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "allOf": [
///    {
///      "type": "object",
///      "required": [
///        "chainId",
///        "renderedAt",
///        "requestId",
///        "verdict"
///      ],
///      "properties": {
///        "chainId": {
///          "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///          "type": "string",
///          "minLength": 1
///        },
///        "evidenceClass": {
///          "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///          "type": "string",
///          "enum": [
///            "asserted",
///            "observed",
///            "verified"
///          ]
///        },
///        "guard": {
///          "description": "Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
///          "type": "string"
///        },
///        "reason": {
///          "description": "Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
///          "type": "string"
///        },
///        "receiptId": {
///          "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///          "type": "string",
///          "minLength": 1
///        },
///        "renderedAt": {
///          "description": "Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "requestId": {
///          "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///          "type": "string",
///          "minLength": 1
///        },
///        "verdict": {
///          "description": "Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
///          "type": "string",
///          "enum": [
///            "allow",
///            "deny",
///            "cancel",
///            "incomplete"
///          ]
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "title": "allow",
///      "description": "Allow verdicts MUST NOT carry `reason` or `guard`; the policy engine emits these fields only on rejection.",
///      "not": {
///        "anyOf": [
///          {
///            "required": [
///              "reason"
///            ]
///          },
///          {
///            "required": [
///              "guard"
///            ]
///          }
///        ]
///      },
///      "required": [
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "allow"
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "deny",
///        "description": "Deny verdicts MUST carry both a human-readable `reason` and the `guard` identifier that produced the denial. Mirrors the deny branch of `chio-http/v1/verdict.schema.json`.",
///        "required": [
///          "guard",
///          "reason",
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "deny"
///          }
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "cancel",
///        "description": "Cancel verdicts MUST carry `reason` (operator or transport cancellation rationale) and MUST NOT carry `guard`.",
///        "not": {
///          "required": [
///            "guard"
///          ]
///        },
///        "required": [
///          "reason",
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "cancel"
///          }
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "incomplete",
///        "description": "Incomplete verdicts MUST carry `reason` describing the terminal failure mode (for example interrupted upstream stream) and MUST NOT carry `guard`.",
///        "not": {
///          "required": [
///            "guard"
///          ]
///        },
///        "required": [
///          "reason",
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "incomplete"
///          }
///        }
///      }
///    }
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
#[serde(deny_unknown_fields)]
pub enum ChioProvenanceVerdictLinkVariant0 {}
impl ::std::convert::From<&Self> for ChioProvenanceVerdictLinkVariant0 {
    fn from(value: &ChioProvenanceVerdictLinkVariant0) -> Self {
        value.clone()
    }
}
///`ChioProvenanceVerdictLinkVariant1Subtype0`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "chainId",
///    "guard",
///    "reason",
///    "renderedAt",
///    "requestId",
///    "verdict"
///  ],
///  "properties": {
///    "chainId": {
///      "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///      "type": "string",
///      "minLength": 1
///    },
///    "evidenceClass": {
///      "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///      "type": "string",
///      "enum": [
///        "asserted",
///        "observed",
///        "verified"
///      ]
///    },
///    "guard": {
///      "description": "Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
///      "type": "string"
///    },
///    "reason": {
///      "description": "Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
///      "type": "string"
///    },
///    "receiptId": {
///      "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///      "type": "string",
///      "minLength": 1
///    },
///    "renderedAt": {
///      "description": "Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "requestId": {
///      "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///      "type": "string",
///      "minLength": 1
///    },
///    "verdict": {
///      "type": "string",
///      "enum": [
///        "deny"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype0 {
    ///Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.
    #[serde(rename = "chainId")]
    pub chain_id: ChioProvenanceVerdictLinkVariant1Subtype0ChainId,
    ///Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.
    #[serde(
        rename = "evidenceClass",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub evidence_class: ::std::option::Option<
        ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass,
    >,
    ///Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.
    pub guard: ::std::string::String,
    ///Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.
    pub reason: ::std::string::String,
    ///Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.
    #[serde(
        rename = "receiptId",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub receipt_id: ::std::option::Option<
        ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId,
    >,
    ///Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.
    #[serde(rename = "renderedAt")]
    pub rendered_at: u64,
    ///Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).
    #[serde(rename = "requestId")]
    pub request_id: ChioProvenanceVerdictLinkVariant1Subtype0RequestId,
    pub verdict: ChioProvenanceVerdictLinkVariant1Subtype0Verdict,
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype0>
for ChioProvenanceVerdictLinkVariant1Subtype0 {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype0) -> Self {
        value.clone()
    }
}
///Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype0ChainId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceVerdictLinkVariant1Subtype0ChainId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant1Subtype0ChainId>
for ::std::string::String {
    fn from(value: ChioProvenanceVerdictLinkVariant1Subtype0ChainId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype0ChainId>
for ChioProvenanceVerdictLinkVariant1Subtype0ChainId {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype0ChainId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype0ChainId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceVerdictLinkVariant1Subtype0ChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0ChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0ChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceVerdictLinkVariant1Subtype0ChainId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///  "type": "string",
///  "enum": [
///    "asserted",
///    "observed",
///    "verified"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass {
    #[serde(rename = "asserted")]
    Asserted,
    #[serde(rename = "observed")]
    Observed,
    #[serde(rename = "verified")]
    Verified,
}
impl ::std::convert::From<&Self>
for ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Asserted => f.write_str("asserted"),
            Self::Observed => f.write_str("observed"),
            Self::Verified => f.write_str("verified"),
        }
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "asserted" => Ok(Self::Asserted),
            "observed" => Ok(Self::Observed),
            "verified" => Ok(Self::Verified),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0EvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId>
for ::std::string::String {
    fn from(value: ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId>
for ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceVerdictLinkVariant1Subtype0ReceiptId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype0RequestId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceVerdictLinkVariant1Subtype0RequestId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant1Subtype0RequestId>
for ::std::string::String {
    fn from(value: ChioProvenanceVerdictLinkVariant1Subtype0RequestId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype0RequestId>
for ChioProvenanceVerdictLinkVariant1Subtype0RequestId {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype0RequestId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype0RequestId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceVerdictLinkVariant1Subtype0RequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0RequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0RequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceVerdictLinkVariant1Subtype0RequestId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioProvenanceVerdictLinkVariant1Subtype0Verdict`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "deny"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceVerdictLinkVariant1Subtype0Verdict {
    #[serde(rename = "deny")]
    Deny,
}
impl ::std::convert::From<&Self> for ChioProvenanceVerdictLinkVariant1Subtype0Verdict {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype0Verdict) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioProvenanceVerdictLinkVariant1Subtype0Verdict {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Deny => f.write_str("deny"),
        }
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype0Verdict {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "deny" => Ok(Self::Deny),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceVerdictLinkVariant1Subtype0Verdict {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0Verdict {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype0Verdict {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioProvenanceVerdictLinkVariant1Subtype1`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "chainId",
///    "guard",
///    "reason",
///    "renderedAt",
///    "requestId",
///    "verdict"
///  ],
///  "properties": {
///    "chainId": {
///      "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///      "type": "string",
///      "minLength": 1
///    },
///    "evidenceClass": {
///      "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///      "type": "string",
///      "enum": [
///        "asserted",
///        "observed",
///        "verified"
///      ]
///    },
///    "guard": {
///      "description": "Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
///      "type": "string"
///    },
///    "reason": {
///      "description": "Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
///      "type": "string"
///    },
///    "receiptId": {
///      "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///      "type": "string",
///      "minLength": 1
///    },
///    "renderedAt": {
///      "description": "Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "requestId": {
///      "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///      "type": "string",
///      "minLength": 1
///    },
///    "verdict": {
///      "type": "string",
///      "enum": [
///        "deny"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype1 {
    ///Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.
    #[serde(rename = "chainId")]
    pub chain_id: ChioProvenanceVerdictLinkVariant1Subtype1ChainId,
    ///Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.
    #[serde(
        rename = "evidenceClass",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub evidence_class: ::std::option::Option<
        ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass,
    >,
    ///Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.
    pub guard: ::std::string::String,
    ///Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.
    pub reason: ::std::string::String,
    ///Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.
    #[serde(
        rename = "receiptId",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub receipt_id: ::std::option::Option<
        ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId,
    >,
    ///Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.
    #[serde(rename = "renderedAt")]
    pub rendered_at: u64,
    ///Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).
    #[serde(rename = "requestId")]
    pub request_id: ChioProvenanceVerdictLinkVariant1Subtype1RequestId,
    pub verdict: ChioProvenanceVerdictLinkVariant1Subtype1Verdict,
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype1>
for ChioProvenanceVerdictLinkVariant1Subtype1 {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype1) -> Self {
        value.clone()
    }
}
///Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype1ChainId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceVerdictLinkVariant1Subtype1ChainId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant1Subtype1ChainId>
for ::std::string::String {
    fn from(value: ChioProvenanceVerdictLinkVariant1Subtype1ChainId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype1ChainId>
for ChioProvenanceVerdictLinkVariant1Subtype1ChainId {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype1ChainId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype1ChainId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceVerdictLinkVariant1Subtype1ChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1ChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1ChainId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceVerdictLinkVariant1Subtype1ChainId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///  "type": "string",
///  "enum": [
///    "asserted",
///    "observed",
///    "verified"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass {
    #[serde(rename = "asserted")]
    Asserted,
    #[serde(rename = "observed")]
    Observed,
    #[serde(rename = "verified")]
    Verified,
}
impl ::std::convert::From<&Self>
for ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Asserted => f.write_str("asserted"),
            Self::Observed => f.write_str("observed"),
            Self::Verified => f.write_str("verified"),
        }
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "asserted" => Ok(Self::Asserted),
            "observed" => Ok(Self::Observed),
            "verified" => Ok(Self::Verified),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1EvidenceClass {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId>
for ::std::string::String {
    fn from(value: ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId>
for ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceVerdictLinkVariant1Subtype1ReceiptId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioProvenanceVerdictLinkVariant1Subtype1RequestId(::std::string::String);
impl ::std::ops::Deref for ChioProvenanceVerdictLinkVariant1Subtype1RequestId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioProvenanceVerdictLinkVariant1Subtype1RequestId>
for ::std::string::String {
    fn from(value: ChioProvenanceVerdictLinkVariant1Subtype1RequestId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioProvenanceVerdictLinkVariant1Subtype1RequestId>
for ChioProvenanceVerdictLinkVariant1Subtype1RequestId {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype1RequestId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype1RequestId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioProvenanceVerdictLinkVariant1Subtype1RequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1RequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1RequestId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioProvenanceVerdictLinkVariant1Subtype1RequestId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioProvenanceVerdictLinkVariant1Subtype1Verdict`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "enum": [
///    "deny"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioProvenanceVerdictLinkVariant1Subtype1Verdict {
    #[serde(rename = "deny")]
    Deny,
}
impl ::std::convert::From<&Self> for ChioProvenanceVerdictLinkVariant1Subtype1Verdict {
    fn from(value: &ChioProvenanceVerdictLinkVariant1Subtype1Verdict) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioProvenanceVerdictLinkVariant1Subtype1Verdict {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Deny => f.write_str("deny"),
        }
    }
}
impl ::std::str::FromStr for ChioProvenanceVerdictLinkVariant1Subtype1Verdict {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "deny" => Ok(Self::Deny),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioProvenanceVerdictLinkVariant1Subtype1Verdict {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1Verdict {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioProvenanceVerdictLinkVariant1Subtype1Verdict {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`ChioProvenanceVerdictLinkVariant2`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "allOf": [
///    {
///      "type": "object",
///      "required": [
///        "chainId",
///        "renderedAt",
///        "requestId",
///        "verdict"
///      ],
///      "properties": {
///        "chainId": {
///          "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///          "type": "string",
///          "minLength": 1
///        },
///        "evidenceClass": {
///          "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///          "type": "string",
///          "enum": [
///            "asserted",
///            "observed",
///            "verified"
///          ]
///        },
///        "guard": {
///          "description": "Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
///          "type": "string"
///        },
///        "reason": {
///          "description": "Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
///          "type": "string"
///        },
///        "receiptId": {
///          "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///          "type": "string",
///          "minLength": 1
///        },
///        "renderedAt": {
///          "description": "Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "requestId": {
///          "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///          "type": "string",
///          "minLength": 1
///        },
///        "verdict": {
///          "description": "Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
///          "type": "string",
///          "enum": [
///            "allow",
///            "deny",
///            "cancel",
///            "incomplete"
///          ]
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "title": "cancel",
///      "description": "Cancel verdicts MUST carry `reason` (operator or transport cancellation rationale) and MUST NOT carry `guard`.",
///      "not": {
///        "required": [
///          "guard"
///        ]
///      },
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "cancel"
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "allow",
///        "description": "Allow verdicts MUST NOT carry `reason` or `guard`; the policy engine emits these fields only on rejection.",
///        "not": {
///          "anyOf": [
///            {
///              "required": [
///                "reason"
///              ]
///            },
///            {
///              "required": [
///                "guard"
///              ]
///            }
///          ]
///        },
///        "required": [
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "allow"
///          }
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "deny",
///        "description": "Deny verdicts MUST carry both a human-readable `reason` and the `guard` identifier that produced the denial. Mirrors the deny branch of `chio-http/v1/verdict.schema.json`.",
///        "required": [
///          "guard",
///          "reason",
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "deny"
///          }
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "incomplete",
///        "description": "Incomplete verdicts MUST carry `reason` describing the terminal failure mode (for example interrupted upstream stream) and MUST NOT carry `guard`.",
///        "not": {
///          "required": [
///            "guard"
///          ]
///        },
///        "required": [
///          "reason",
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "incomplete"
///          }
///        }
///      }
///    }
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
#[serde(deny_unknown_fields)]
pub enum ChioProvenanceVerdictLinkVariant2 {}
impl ::std::convert::From<&Self> for ChioProvenanceVerdictLinkVariant2 {
    fn from(value: &ChioProvenanceVerdictLinkVariant2) -> Self {
        value.clone()
    }
}
///`ChioProvenanceVerdictLinkVariant3`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "allOf": [
///    {
///      "type": "object",
///      "required": [
///        "chainId",
///        "renderedAt",
///        "requestId",
///        "verdict"
///      ],
///      "properties": {
///        "chainId": {
///          "description": "Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
///          "type": "string",
///          "minLength": 1
///        },
///        "evidenceClass": {
///          "description": "Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314). Omitted when the verdict was rendered without consulting the provenance graph.",
///          "type": "string",
///          "enum": [
///            "asserted",
///            "observed",
///            "verified"
///          ]
///        },
///        "guard": {
///          "description": "Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
///          "type": "string"
///        },
///        "reason": {
///          "description": "Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
///          "type": "string"
///        },
///        "receiptId": {
///          "description": "Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
///          "type": "string",
///          "minLength": 1
///        },
///        "renderedAt": {
///          "description": "Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
///          "type": "integer",
///          "minimum": 0.0
///        },
///        "requestId": {
///          "description": "Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `crates/chio-core-types/src/session.rs` (`RequestLineageMode`, lines 717-768).",
///          "type": "string",
///          "minLength": 1
///        },
///        "verdict": {
///          "description": "Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
///          "type": "string",
///          "enum": [
///            "allow",
///            "deny",
///            "cancel",
///            "incomplete"
///          ]
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "title": "incomplete",
///      "description": "Incomplete verdicts MUST carry `reason` describing the terminal failure mode (for example interrupted upstream stream) and MUST NOT carry `guard`.",
///      "not": {
///        "required": [
///          "guard"
///        ]
///      },
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "incomplete"
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "allow",
///        "description": "Allow verdicts MUST NOT carry `reason` or `guard`; the policy engine emits these fields only on rejection.",
///        "not": {
///          "anyOf": [
///            {
///              "required": [
///                "reason"
///              ]
///            },
///            {
///              "required": [
///                "guard"
///              ]
///            }
///          ]
///        },
///        "required": [
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "allow"
///          }
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "deny",
///        "description": "Deny verdicts MUST carry both a human-readable `reason` and the `guard` identifier that produced the denial. Mirrors the deny branch of `chio-http/v1/verdict.schema.json`.",
///        "required": [
///          "guard",
///          "reason",
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "deny"
///          }
///        }
///      }
///    },
///    {
///      "not": {
///        "title": "cancel",
///        "description": "Cancel verdicts MUST carry `reason` (operator or transport cancellation rationale) and MUST NOT carry `guard`.",
///        "not": {
///          "required": [
///            "guard"
///          ]
///        },
///        "required": [
///          "reason",
///          "verdict"
///        ],
///        "properties": {
///          "verdict": {
///            "const": "cancel"
///          }
///        }
///      }
///    }
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
#[serde(deny_unknown_fields)]
pub enum ChioProvenanceVerdictLinkVariant3 {}
impl ::std::convert::From<&Self> for ChioProvenanceVerdictLinkVariant3 {
    fn from(value: &ChioProvenanceVerdictLinkVariant3) -> Self {
        value.clone()
    }
}
///Merkle inclusion proof for a single receipt leaf in a receipt-log Merkle tree. Mirrors the serde shape of `MerkleProof` in `crates/chio-core-types/src/merkle.rs`. The proof allows an auditor, holding only the published Merkle root and the original leaf bytes, to verify that the leaf was included in a tree of the given size at the given position. The audit path is the ordered list of sibling hashes encountered when walking from the leaf up to the root; siblings whose subtree was carried upward without pairing (the right-edge of an unbalanced level) are omitted. M04 deterministic-replay consumes this schema as the contract for golden-bundle inclusion artifacts under `tests/replay/goldens/<family>/<name>/`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/receipt/inclusion-proof/v1",
///  "title": "Chio Receipt Merkle Inclusion Proof",
///  "description": "Merkle inclusion proof for a single receipt leaf in a receipt-log Merkle tree. Mirrors the serde shape of `MerkleProof` in `crates/chio-core-types/src/merkle.rs`. The proof allows an auditor, holding only the published Merkle root and the original leaf bytes, to verify that the leaf was included in a tree of the given size at the given position. The audit path is the ordered list of sibling hashes encountered when walking from the leaf up to the root; siblings whose subtree was carried upward without pairing (the right-edge of an unbalanced level) are omitted. M04 deterministic-replay consumes this schema as the contract for golden-bundle inclusion artifacts under `tests/replay/goldens/<family>/<name>/`.",
///  "type": "object",
///  "required": [
///    "audit_path",
///    "leaf_index",
///    "tree_size"
///  ],
///  "properties": {
///    "audit_path": {
///      "description": "Ordered sibling hashes from leaf-level up to (but not including) the root. Siblings that were carried upward without pairing on the right edge of an unbalanced level are omitted, so the path length is not strictly `ceil(log2(tree_size))`. Each entry is a `chio-core-types::Hash` serialized via its transparent serde adapter (32-byte SHA-256 digest, hex-encoded with a `0x` prefix).",
///      "type": "array",
///      "items": {
///        "description": "Sibling hash. 32 bytes, lowercase hex with `0x` prefix.",
///        "type": "string",
///        "pattern": "^0x[0-9a-f]{64}$"
///      }
///    },
///    "leaf_index": {
///      "description": "Zero-based index of the leaf being proved. MUST satisfy `leaf_index < tree_size`.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "tree_size": {
///      "description": "Total number of leaves in the Merkle tree at the time the proof was issued.",
///      "type": "integer",
///      "minimum": 1.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioReceiptMerkleInclusionProof {
    ///Ordered sibling hashes from leaf-level up to (but not including) the root. Siblings that were carried upward without pairing on the right edge of an unbalanced level are omitted, so the path length is not strictly `ceil(log2(tree_size))`. Each entry is a `chio-core-types::Hash` serialized via its transparent serde adapter (32-byte SHA-256 digest, hex-encoded with a `0x` prefix).
    pub audit_path: ::std::vec::Vec<ChioReceiptMerkleInclusionProofAuditPathItem>,
    ///Zero-based index of the leaf being proved. MUST satisfy `leaf_index < tree_size`.
    pub leaf_index: u64,
    ///Total number of leaves in the Merkle tree at the time the proof was issued.
    pub tree_size: ::std::num::NonZeroU64,
}
impl ::std::convert::From<&ChioReceiptMerkleInclusionProof>
for ChioReceiptMerkleInclusionProof {
    fn from(value: &ChioReceiptMerkleInclusionProof) -> Self {
        value.clone()
    }
}
///Sibling hash. 32 bytes, lowercase hex with `0x` prefix.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Sibling hash. 32 bytes, lowercase hex with `0x` prefix.",
///  "type": "string",
///  "pattern": "^0x[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptMerkleInclusionProofAuditPathItem(::std::string::String);
impl ::std::ops::Deref for ChioReceiptMerkleInclusionProofAuditPathItem {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptMerkleInclusionProofAuditPathItem>
for ::std::string::String {
    fn from(value: ChioReceiptMerkleInclusionProofAuditPathItem) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptMerkleInclusionProofAuditPathItem>
for ChioReceiptMerkleInclusionProofAuditPathItem {
    fn from(value: &ChioReceiptMerkleInclusionProofAuditPathItem) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptMerkleInclusionProofAuditPathItem {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^0x[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^0x[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptMerkleInclusionProofAuditPathItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioReceiptMerkleInclusionProofAuditPathItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioReceiptMerkleInclusionProofAuditPathItem {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptMerkleInclusionProofAuditPathItem {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///A signed Chio receipt: proof that a tool call was evaluated by the Kernel. Mirrors the serde shape of `ChioReceipt` in `crates/chio-core-types/src/receipt.rs`. The `signature` field covers the canonical JSON of `ChioReceiptBody` (every field below except `algorithm` and `signature`). The `algorithm` envelope field is informational (verification dispatches off the self-describing hex prefix on the signature itself) and is omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Optional fields (`evidence`, `metadata`, `trust_level`, `tenant_id`, `algorithm`) are skipped on the wire when set to their default or unset values.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/receipt/record/v1",
///  "title": "Chio Receipt Record",
///  "description": "A signed Chio receipt: proof that a tool call was evaluated by the Kernel. Mirrors the serde shape of `ChioReceipt` in `crates/chio-core-types/src/receipt.rs`. The `signature` field covers the canonical JSON of `ChioReceiptBody` (every field below except `algorithm` and `signature`). The `algorithm` envelope field is informational (verification dispatches off the self-describing hex prefix on the signature itself) and is omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Optional fields (`evidence`, `metadata`, `trust_level`, `tenant_id`, `algorithm`) are skipped on the wire when set to their default or unset values.",
///  "type": "object",
///  "required": [
///    "action",
///    "capability_id",
///    "content_hash",
///    "decision",
///    "id",
///    "kernel_key",
///    "policy_hash",
///    "signature",
///    "timestamp",
///    "tool_name",
///    "tool_server"
///  ],
///  "properties": {
///    "action": {
///      "$ref": "#/$defs/toolCallAction"
///    },
///    "algorithm": {
///      "description": "Signing algorithm envelope hint. Omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.",
///      "type": "string",
///      "enum": [
///        "ed25519",
///        "p256",
///        "p384"
///      ]
///    },
///    "capability_id": {
///      "description": "ID of the capability token that was exercised (or presented).",
///      "type": "string",
///      "minLength": 1
///    },
///    "content_hash": {
///      "description": "SHA-256 hex hash of the evaluated content for this receipt.",
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "decision": {
///      "$ref": "#/$defs/decision"
///    },
///    "evidence": {
///      "description": "Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = \"Vec::is_empty\")]`).",
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/guardEvidence"
///      }
///    },
///    "id": {
///      "description": "Unique receipt ID. UUIDv7 recommended.",
///      "type": "string",
///      "minLength": 1
///    },
///    "kernel_key": {
///      "description": "Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/chio-core-types/src/crypto.rs`.",
///      "type": "string",
///      "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///    },
///    "metadata": {
///      "description": "Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`)."
///    },
///    "policy_hash": {
///      "description": "SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.",
///      "type": "string",
///      "minLength": 1
///    },
///    "signature": {
///      "description": "Hex-encoded signature over the canonical JSON of the receipt body. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.",
///      "type": "string",
///      "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$"
///    },
///    "tenant_id": {
///      "description": "Phase 1.5 multi-tenant receipt isolation: tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields. Omitted from the wire when unset so single-tenant receipts remain byte-identical.",
///      "type": "string",
///      "minLength": 1
///    },
///    "timestamp": {
///      "description": "Unix timestamp (seconds) when the receipt was created.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "tool_name": {
///      "description": "Tool that was invoked (or attempted).",
///      "type": "string",
///      "minLength": 1
///    },
///    "tool_server": {
///      "description": "Tool server that handled the invocation.",
///      "type": "string",
///      "minLength": 1
///    },
///    "trust_level": {
///      "description": "Strength of kernel mediation that produced this receipt. Defaults to `mediated`. Older receipts that omit this field deserialize to `mediated` for backward compatibility.",
///      "type": "string",
///      "enum": [
///        "mediated",
///        "verified",
///        "advisory"
///      ]
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioReceiptRecord {
    pub action: ToolCallAction,
    ///Signing algorithm envelope hint. Omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub algorithm: ::std::option::Option<ChioReceiptRecordAlgorithm>,
    ///ID of the capability token that was exercised (or presented).
    pub capability_id: ChioReceiptRecordCapabilityId,
    ///SHA-256 hex hash of the evaluated content for this receipt.
    pub content_hash: ChioReceiptRecordContentHash,
    pub decision: Decision,
    ///Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub evidence: ::std::vec::Vec<GuardEvidence>,
    ///Unique receipt ID. UUIDv7 recommended.
    pub id: ChioReceiptRecordId,
    ///Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/chio-core-types/src/crypto.rs`.
    pub kernel_key: ChioReceiptRecordKernelKey,
    ///Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub metadata: ::std::option::Option<::serde_json::Value>,
    ///SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
    pub policy_hash: ChioReceiptRecordPolicyHash,
    ///Hex-encoded signature over the canonical JSON of the receipt body. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
    pub signature: ChioReceiptRecordSignature,
    ///Phase 1.5 multi-tenant receipt isolation: tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields. Omitted from the wire when unset so single-tenant receipts remain byte-identical.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub tenant_id: ::std::option::Option<ChioReceiptRecordTenantId>,
    ///Unix timestamp (seconds) when the receipt was created.
    pub timestamp: u64,
    ///Tool that was invoked (or attempted).
    pub tool_name: ChioReceiptRecordToolName,
    ///Tool server that handled the invocation.
    pub tool_server: ChioReceiptRecordToolServer,
    ///Strength of kernel mediation that produced this receipt. Defaults to `mediated`. Older receipts that omit this field deserialize to `mediated` for backward compatibility.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub trust_level: ::std::option::Option<ChioReceiptRecordTrustLevel>,
}
impl ::std::convert::From<&ChioReceiptRecord> for ChioReceiptRecord {
    fn from(value: &ChioReceiptRecord) -> Self {
        value.clone()
    }
}
///Signing algorithm envelope hint. Omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Signing algorithm envelope hint. Omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.",
///  "type": "string",
///  "enum": [
///    "ed25519",
///    "p256",
///    "p384"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioReceiptRecordAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "p256")]
    P256,
    #[serde(rename = "p384")]
    P384,
}
impl ::std::convert::From<&Self> for ChioReceiptRecordAlgorithm {
    fn from(value: &ChioReceiptRecordAlgorithm) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioReceiptRecordAlgorithm {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Ed25519 => f.write_str("ed25519"),
            Self::P256 => f.write_str("p256"),
            Self::P384 => f.write_str("p384"),
        }
    }
}
impl ::std::str::FromStr for ChioReceiptRecordAlgorithm {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "ed25519" => Ok(Self::Ed25519),
            "p256" => Ok(Self::P256),
            "p384" => Ok(Self::P384),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordAlgorithm {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordAlgorithm {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordAlgorithm {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///ID of the capability token that was exercised (or presented).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "ID of the capability token that was exercised (or presented).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordCapabilityId(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordCapabilityId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordCapabilityId> for ::std::string::String {
    fn from(value: ChioReceiptRecordCapabilityId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordCapabilityId>
for ChioReceiptRecordCapabilityId {
    fn from(value: &ChioReceiptRecordCapabilityId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordCapabilityId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordCapabilityId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///SHA-256 hex hash of the evaluated content for this receipt.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "SHA-256 hex hash of the evaluated content for this receipt.",
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordContentHash(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordContentHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordContentHash> for ::std::string::String {
    fn from(value: ChioReceiptRecordContentHash) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordContentHash>
for ChioReceiptRecordContentHash {
    fn from(value: &ChioReceiptRecordContentHash) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordContentHash {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordContentHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordContentHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordContentHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordContentHash {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Unique receipt ID. UUIDv7 recommended.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Unique receipt ID. UUIDv7 recommended.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordId(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordId> for ::std::string::String {
    fn from(value: ChioReceiptRecordId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordId> for ChioReceiptRecordId {
    fn from(value: &ChioReceiptRecordId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/chio-core-types/src/crypto.rs`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/chio-core-types/src/crypto.rs`.",
///  "type": "string",
///  "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordKernelKey(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordKernelKey {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordKernelKey> for ::std::string::String {
    fn from(value: ChioReceiptRecordKernelKey) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordKernelKey> for ChioReceiptRecordKernelKey {
    fn from(value: &ChioReceiptRecordKernelKey) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordKernelKey {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new(
                    "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$",
                )
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordKernelKey {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordKernelKey {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordKernelKey {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordKernelKey {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordPolicyHash(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordPolicyHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordPolicyHash> for ::std::string::String {
    fn from(value: ChioReceiptRecordPolicyHash) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordPolicyHash> for ChioReceiptRecordPolicyHash {
    fn from(value: &ChioReceiptRecordPolicyHash) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordPolicyHash {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordPolicyHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordPolicyHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordPolicyHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordPolicyHash {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Hex-encoded signature over the canonical JSON of the receipt body. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Hex-encoded signature over the canonical JSON of the receipt body. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.",
///  "type": "string",
///  "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordSignature(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordSignature> for ::std::string::String {
    fn from(value: ChioReceiptRecordSignature) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordSignature> for ChioReceiptRecordSignature {
    fn from(value: &ChioReceiptRecordSignature) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new("^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$")
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Phase 1.5 multi-tenant receipt isolation: tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields. Omitted from the wire when unset so single-tenant receipts remain byte-identical.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Phase 1.5 multi-tenant receipt isolation: tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields. Omitted from the wire when unset so single-tenant receipts remain byte-identical.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordTenantId(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordTenantId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordTenantId> for ::std::string::String {
    fn from(value: ChioReceiptRecordTenantId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordTenantId> for ChioReceiptRecordTenantId {
    fn from(value: &ChioReceiptRecordTenantId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordTenantId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordTenantId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordTenantId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordTenantId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordTenantId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Tool that was invoked (or attempted).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Tool that was invoked (or attempted).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordToolName(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordToolName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordToolName> for ::std::string::String {
    fn from(value: ChioReceiptRecordToolName) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordToolName> for ChioReceiptRecordToolName {
    fn from(value: &ChioReceiptRecordToolName) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordToolName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordToolName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Tool server that handled the invocation.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Tool server that handled the invocation.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioReceiptRecordToolServer(::std::string::String);
impl ::std::ops::Deref for ChioReceiptRecordToolServer {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioReceiptRecordToolServer> for ::std::string::String {
    fn from(value: ChioReceiptRecordToolServer) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioReceiptRecordToolServer> for ChioReceiptRecordToolServer {
    fn from(value: &ChioReceiptRecordToolServer) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioReceiptRecordToolServer {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordToolServer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordToolServer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordToolServer {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioReceiptRecordToolServer {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Strength of kernel mediation that produced this receipt. Defaults to `mediated`. Older receipts that omit this field deserialize to `mediated` for backward compatibility.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Strength of kernel mediation that produced this receipt. Defaults to `mediated`. Older receipts that omit this field deserialize to `mediated` for backward compatibility.",
///  "type": "string",
///  "enum": [
///    "mediated",
///    "verified",
///    "advisory"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioReceiptRecordTrustLevel {
    #[serde(rename = "mediated")]
    Mediated,
    #[serde(rename = "verified")]
    Verified,
    #[serde(rename = "advisory")]
    Advisory,
}
impl ::std::convert::From<&Self> for ChioReceiptRecordTrustLevel {
    fn from(value: &ChioReceiptRecordTrustLevel) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioReceiptRecordTrustLevel {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Mediated => f.write_str("mediated"),
            Self::Verified => f.write_str("verified"),
            Self::Advisory => f.write_str("advisory"),
        }
    }
}
impl ::std::str::FromStr for ChioReceiptRecordTrustLevel {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "mediated" => Ok(Self::Mediated),
            "verified" => Ok(Self::Verified),
            "advisory" => Ok(Self::Advisory),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioReceiptRecordTrustLevel {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ChioReceiptRecordTrustLevel {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ChioReceiptRecordTrustLevel {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.",
///  "type": "object",
///  "properties": {
///    "grants": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/toolGrant"
///      }
///    },
///    "prompt_grants": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/promptGrant"
///      }
///    },
///    "resource_grants": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/resourceGrant"
///      }
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioScope {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub grants: ::std::vec::Vec<ToolGrant>,
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub prompt_grants: ::std::vec::Vec<PromptGrant>,
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub resource_grants: ::std::vec::Vec<ResourceGrant>,
}
impl ::std::convert::From<&ChioScope> for ChioScope {
    fn from(value: &ChioScope) -> Self {
        value.clone()
    }
}
impl ::std::default::Default for ChioScope {
    fn default() -> Self {
        Self {
            grants: Default::default(),
            prompt_grants: Default::default(),
            resource_grants: Default::default(),
        }
    }
}
///`ChioToolCallErrorCapabilityDenied`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallError capability_denied",
///  "type": "object",
///  "required": [
///    "code",
///    "detail"
///  ],
///  "properties": {
///    "code": {
///      "const": "capability_denied"
///    },
///    "detail": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallErrorCapabilityDenied {
    pub code: ::serde_json::Value,
    pub detail: ChioToolCallErrorCapabilityDeniedDetail,
}
impl ::std::convert::From<&ChioToolCallErrorCapabilityDenied>
for ChioToolCallErrorCapabilityDenied {
    fn from(value: &ChioToolCallErrorCapabilityDenied) -> Self {
        value.clone()
    }
}
///`ChioToolCallErrorCapabilityDeniedDetail`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallErrorCapabilityDeniedDetail(::std::string::String);
impl ::std::ops::Deref for ChioToolCallErrorCapabilityDeniedDetail {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallErrorCapabilityDeniedDetail>
for ::std::string::String {
    fn from(value: ChioToolCallErrorCapabilityDeniedDetail) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallErrorCapabilityDeniedDetail>
for ChioToolCallErrorCapabilityDeniedDetail {
    fn from(value: &ChioToolCallErrorCapabilityDeniedDetail) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallErrorCapabilityDeniedDetail {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallErrorCapabilityDeniedDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallErrorCapabilityDeniedDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallErrorCapabilityDeniedDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallErrorCapabilityDeniedDetail {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallErrorCapabilityExpired`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallError capability_expired",
///  "type": "object",
///  "required": [
///    "code"
///  ],
///  "properties": {
///    "code": {
///      "const": "capability_expired"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallErrorCapabilityExpired {
    pub code: ::serde_json::Value,
}
impl ::std::convert::From<&ChioToolCallErrorCapabilityExpired>
for ChioToolCallErrorCapabilityExpired {
    fn from(value: &ChioToolCallErrorCapabilityExpired) -> Self {
        value.clone()
    }
}
///`ChioToolCallErrorCapabilityRevoked`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallError capability_revoked",
///  "type": "object",
///  "required": [
///    "code"
///  ],
///  "properties": {
///    "code": {
///      "const": "capability_revoked"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallErrorCapabilityRevoked {
    pub code: ::serde_json::Value,
}
impl ::std::convert::From<&ChioToolCallErrorCapabilityRevoked>
for ChioToolCallErrorCapabilityRevoked {
    fn from(value: &ChioToolCallErrorCapabilityRevoked) -> Self {
        value.clone()
    }
}
///`ChioToolCallErrorInternalError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallError internal_error",
///  "type": "object",
///  "required": [
///    "code",
///    "detail"
///  ],
///  "properties": {
///    "code": {
///      "const": "internal_error"
///    },
///    "detail": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallErrorInternalError {
    pub code: ::serde_json::Value,
    pub detail: ChioToolCallErrorInternalErrorDetail,
}
impl ::std::convert::From<&ChioToolCallErrorInternalError>
for ChioToolCallErrorInternalError {
    fn from(value: &ChioToolCallErrorInternalError) -> Self {
        value.clone()
    }
}
///`ChioToolCallErrorInternalErrorDetail`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallErrorInternalErrorDetail(::std::string::String);
impl ::std::ops::Deref for ChioToolCallErrorInternalErrorDetail {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallErrorInternalErrorDetail>
for ::std::string::String {
    fn from(value: ChioToolCallErrorInternalErrorDetail) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallErrorInternalErrorDetail>
for ChioToolCallErrorInternalErrorDetail {
    fn from(value: &ChioToolCallErrorInternalErrorDetail) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallErrorInternalErrorDetail {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallErrorInternalErrorDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallErrorInternalErrorDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallErrorInternalErrorDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallErrorInternalErrorDetail {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallErrorPolicyDenied`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallError policy_denied",
///  "type": "object",
///  "required": [
///    "code",
///    "detail"
///  ],
///  "properties": {
///    "code": {
///      "const": "policy_denied"
///    },
///    "detail": {
///      "type": "object",
///      "required": [
///        "guard",
///        "reason"
///      ],
///      "properties": {
///        "guard": {
///          "type": "string",
///          "minLength": 1
///        },
///        "reason": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallErrorPolicyDenied {
    pub code: ::serde_json::Value,
    pub detail: ChioToolCallErrorPolicyDeniedDetail,
}
impl ::std::convert::From<&ChioToolCallErrorPolicyDenied>
for ChioToolCallErrorPolicyDenied {
    fn from(value: &ChioToolCallErrorPolicyDenied) -> Self {
        value.clone()
    }
}
///`ChioToolCallErrorPolicyDeniedDetail`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "guard",
///    "reason"
///  ],
///  "properties": {
///    "guard": {
///      "type": "string",
///      "minLength": 1
///    },
///    "reason": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallErrorPolicyDeniedDetail {
    pub guard: ChioToolCallErrorPolicyDeniedDetailGuard,
    pub reason: ChioToolCallErrorPolicyDeniedDetailReason,
}
impl ::std::convert::From<&ChioToolCallErrorPolicyDeniedDetail>
for ChioToolCallErrorPolicyDeniedDetail {
    fn from(value: &ChioToolCallErrorPolicyDeniedDetail) -> Self {
        value.clone()
    }
}
///`ChioToolCallErrorPolicyDeniedDetailGuard`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallErrorPolicyDeniedDetailGuard(::std::string::String);
impl ::std::ops::Deref for ChioToolCallErrorPolicyDeniedDetailGuard {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallErrorPolicyDeniedDetailGuard>
for ::std::string::String {
    fn from(value: ChioToolCallErrorPolicyDeniedDetailGuard) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallErrorPolicyDeniedDetailGuard>
for ChioToolCallErrorPolicyDeniedDetailGuard {
    fn from(value: &ChioToolCallErrorPolicyDeniedDetailGuard) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallErrorPolicyDeniedDetailGuard {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallErrorPolicyDeniedDetailGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallErrorPolicyDeniedDetailGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallErrorPolicyDeniedDetailGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallErrorPolicyDeniedDetailGuard {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallErrorPolicyDeniedDetailReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallErrorPolicyDeniedDetailReason(::std::string::String);
impl ::std::ops::Deref for ChioToolCallErrorPolicyDeniedDetailReason {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallErrorPolicyDeniedDetailReason>
for ::std::string::String {
    fn from(value: ChioToolCallErrorPolicyDeniedDetailReason) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallErrorPolicyDeniedDetailReason>
for ChioToolCallErrorPolicyDeniedDetailReason {
    fn from(value: &ChioToolCallErrorPolicyDeniedDetailReason) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallErrorPolicyDeniedDetailReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallErrorPolicyDeniedDetailReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallErrorPolicyDeniedDetailReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallErrorPolicyDeniedDetailReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallErrorPolicyDeniedDetailReason {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallErrorToolServerError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallError tool_server_error",
///  "type": "object",
///  "required": [
///    "code",
///    "detail"
///  ],
///  "properties": {
///    "code": {
///      "const": "tool_server_error"
///    },
///    "detail": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallErrorToolServerError {
    pub code: ::serde_json::Value,
    pub detail: ChioToolCallErrorToolServerErrorDetail,
}
impl ::std::convert::From<&ChioToolCallErrorToolServerError>
for ChioToolCallErrorToolServerError {
    fn from(value: &ChioToolCallErrorToolServerError) -> Self {
        value.clone()
    }
}
///`ChioToolCallErrorToolServerErrorDetail`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallErrorToolServerErrorDetail(::std::string::String);
impl ::std::ops::Deref for ChioToolCallErrorToolServerErrorDetail {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallErrorToolServerErrorDetail>
for ::std::string::String {
    fn from(value: ChioToolCallErrorToolServerErrorDetail) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallErrorToolServerErrorDetail>
for ChioToolCallErrorToolServerErrorDetail {
    fn from(value: &ChioToolCallErrorToolServerErrorDetail) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallErrorToolServerErrorDetail {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallErrorToolServerErrorDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallErrorToolServerErrorDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallErrorToolServerErrorDetail {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallErrorToolServerErrorDetail {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultCancelled`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallResult cancelled",
///  "type": "object",
///  "required": [
///    "chunks_received",
///    "reason",
///    "status"
///  ],
///  "properties": {
///    "chunks_received": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "reason": {
///      "type": "string",
///      "minLength": 1
///    },
///    "status": {
///      "const": "cancelled"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallResultCancelled {
    pub chunks_received: u64,
    pub reason: ChioToolCallResultCancelledReason,
    pub status: ::serde_json::Value,
}
impl ::std::convert::From<&ChioToolCallResultCancelled> for ChioToolCallResultCancelled {
    fn from(value: &ChioToolCallResultCancelled) -> Self {
        value.clone()
    }
}
///`ChioToolCallResultCancelledReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallResultCancelledReason(::std::string::String);
impl ::std::ops::Deref for ChioToolCallResultCancelledReason {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallResultCancelledReason> for ::std::string::String {
    fn from(value: ChioToolCallResultCancelledReason) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallResultCancelledReason>
for ChioToolCallResultCancelledReason {
    fn from(value: &ChioToolCallResultCancelledReason) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallResultCancelledReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallResultCancelledReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallResultCancelledReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallResultCancelledReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallResultCancelledReason {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultErr`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallResult err",
///  "type": "object",
///  "required": [
///    "error",
///    "status"
///  ],
///  "properties": {
///    "error": {
///      "oneOf": [
///        {
///          "type": "object",
///          "required": [
///            "code",
///            "detail"
///          ],
///          "properties": {
///            "code": {
///              "const": "capability_denied"
///            },
///            "detail": {
///              "type": "string",
///              "minLength": 1
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "code"
///          ],
///          "properties": {
///            "code": {
///              "const": "capability_expired"
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "code"
///          ],
///          "properties": {
///            "code": {
///              "const": "capability_revoked"
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "code",
///            "detail"
///          ],
///          "properties": {
///            "code": {
///              "const": "policy_denied"
///            },
///            "detail": {
///              "type": "object",
///              "required": [
///                "guard",
///                "reason"
///              ],
///              "properties": {
///                "guard": {
///                  "type": "string",
///                  "minLength": 1
///                },
///                "reason": {
///                  "type": "string",
///                  "minLength": 1
///                }
///              },
///              "additionalProperties": false
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "code",
///            "detail"
///          ],
///          "properties": {
///            "code": {
///              "const": "tool_server_error"
///            },
///            "detail": {
///              "type": "string",
///              "minLength": 1
///            }
///          },
///          "additionalProperties": false
///        },
///        {
///          "type": "object",
///          "required": [
///            "code",
///            "detail"
///          ],
///          "properties": {
///            "code": {
///              "const": "internal_error"
///            },
///            "detail": {
///              "type": "string",
///              "minLength": 1
///            }
///          },
///          "additionalProperties": false
///        }
///      ]
///    },
///    "status": {
///      "const": "err"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallResultErr {
    pub error: ChioToolCallResultErrError,
    pub status: ::serde_json::Value,
}
impl ::std::convert::From<&ChioToolCallResultErr> for ChioToolCallResultErr {
    fn from(value: &ChioToolCallResultErr) -> Self {
        value.clone()
    }
}
///`ChioToolCallResultErrError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "oneOf": [
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "capability_denied"
///        },
///        "detail": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code"
///      ],
///      "properties": {
///        "code": {
///          "const": "capability_expired"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code"
///      ],
///      "properties": {
///        "code": {
///          "const": "capability_revoked"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "policy_denied"
///        },
///        "detail": {
///          "type": "object",
///          "required": [
///            "guard",
///            "reason"
///          ],
///          "properties": {
///            "guard": {
///              "type": "string",
///              "minLength": 1
///            },
///            "reason": {
///              "type": "string",
///              "minLength": 1
///            }
///          },
///          "additionalProperties": false
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "tool_server_error"
///        },
///        "detail": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "type": "object",
///      "required": [
///        "code",
///        "detail"
///      ],
///      "properties": {
///        "code": {
///          "const": "internal_error"
///        },
///        "detail": {
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    }
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(tag = "code", content = "detail", deny_unknown_fields)]
pub enum ChioToolCallResultErrError {
    #[serde(rename = "capability_denied")]
    CapabilityDenied(ChioToolCallResultErrErrorCapabilityDenied),
    #[serde(rename = "capability_expired")]
    CapabilityExpired,
    #[serde(rename = "capability_revoked")]
    CapabilityRevoked,
    #[serde(rename = "policy_denied")]
    PolicyDenied {
        guard: ChioToolCallResultErrErrorPolicyDeniedGuard,
        reason: ChioToolCallResultErrErrorPolicyDeniedReason,
    },
    #[serde(rename = "tool_server_error")]
    ToolServerError(ChioToolCallResultErrErrorToolServerError),
    #[serde(rename = "internal_error")]
    InternalError(ChioToolCallResultErrErrorInternalError),
}
impl ::std::convert::From<&Self> for ChioToolCallResultErrError {
    fn from(value: &ChioToolCallResultErrError) -> Self {
        value.clone()
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorCapabilityDenied>
for ChioToolCallResultErrError {
    fn from(value: ChioToolCallResultErrErrorCapabilityDenied) -> Self {
        Self::CapabilityDenied(value)
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorToolServerError>
for ChioToolCallResultErrError {
    fn from(value: ChioToolCallResultErrErrorToolServerError) -> Self {
        Self::ToolServerError(value)
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorInternalError>
for ChioToolCallResultErrError {
    fn from(value: ChioToolCallResultErrErrorInternalError) -> Self {
        Self::InternalError(value)
    }
}
///`ChioToolCallResultErrErrorCapabilityDenied`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallResultErrErrorCapabilityDenied(::std::string::String);
impl ::std::ops::Deref for ChioToolCallResultErrErrorCapabilityDenied {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorCapabilityDenied>
for ::std::string::String {
    fn from(value: ChioToolCallResultErrErrorCapabilityDenied) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallResultErrErrorCapabilityDenied>
for ChioToolCallResultErrErrorCapabilityDenied {
    fn from(value: &ChioToolCallResultErrErrorCapabilityDenied) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallResultErrErrorCapabilityDenied {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallResultErrErrorCapabilityDenied {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallResultErrErrorCapabilityDenied {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallResultErrErrorCapabilityDenied {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallResultErrErrorCapabilityDenied {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultErrErrorInternalError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallResultErrErrorInternalError(::std::string::String);
impl ::std::ops::Deref for ChioToolCallResultErrErrorInternalError {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorInternalError>
for ::std::string::String {
    fn from(value: ChioToolCallResultErrErrorInternalError) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallResultErrErrorInternalError>
for ChioToolCallResultErrErrorInternalError {
    fn from(value: &ChioToolCallResultErrErrorInternalError) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallResultErrErrorInternalError {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallResultErrErrorInternalError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallResultErrErrorInternalError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallResultErrErrorInternalError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallResultErrErrorInternalError {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultErrErrorPolicyDeniedGuard`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallResultErrErrorPolicyDeniedGuard(::std::string::String);
impl ::std::ops::Deref for ChioToolCallResultErrErrorPolicyDeniedGuard {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorPolicyDeniedGuard>
for ::std::string::String {
    fn from(value: ChioToolCallResultErrErrorPolicyDeniedGuard) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallResultErrErrorPolicyDeniedGuard>
for ChioToolCallResultErrErrorPolicyDeniedGuard {
    fn from(value: &ChioToolCallResultErrErrorPolicyDeniedGuard) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallResultErrErrorPolicyDeniedGuard {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallResultErrErrorPolicyDeniedGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallResultErrErrorPolicyDeniedGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallResultErrErrorPolicyDeniedGuard {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallResultErrErrorPolicyDeniedGuard {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultErrErrorPolicyDeniedReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallResultErrErrorPolicyDeniedReason(::std::string::String);
impl ::std::ops::Deref for ChioToolCallResultErrErrorPolicyDeniedReason {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorPolicyDeniedReason>
for ::std::string::String {
    fn from(value: ChioToolCallResultErrErrorPolicyDeniedReason) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallResultErrErrorPolicyDeniedReason>
for ChioToolCallResultErrErrorPolicyDeniedReason {
    fn from(value: &ChioToolCallResultErrErrorPolicyDeniedReason) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallResultErrErrorPolicyDeniedReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallResultErrErrorPolicyDeniedReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallResultErrErrorPolicyDeniedReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallResultErrErrorPolicyDeniedReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallResultErrErrorPolicyDeniedReason {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultErrErrorToolServerError`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallResultErrErrorToolServerError(::std::string::String);
impl ::std::ops::Deref for ChioToolCallResultErrErrorToolServerError {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallResultErrErrorToolServerError>
for ::std::string::String {
    fn from(value: ChioToolCallResultErrErrorToolServerError) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallResultErrErrorToolServerError>
for ChioToolCallResultErrErrorToolServerError {
    fn from(value: &ChioToolCallResultErrErrorToolServerError) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallResultErrErrorToolServerError {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallResultErrErrorToolServerError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallResultErrErrorToolServerError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallResultErrErrorToolServerError {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallResultErrErrorToolServerError {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultIncomplete`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallResult incomplete",
///  "type": "object",
///  "required": [
///    "chunks_received",
///    "reason",
///    "status"
///  ],
///  "properties": {
///    "chunks_received": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "reason": {
///      "type": "string",
///      "minLength": 1
///    },
///    "status": {
///      "const": "incomplete"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallResultIncomplete {
    pub chunks_received: u64,
    pub reason: ChioToolCallResultIncompleteReason,
    pub status: ::serde_json::Value,
}
impl ::std::convert::From<&ChioToolCallResultIncomplete>
for ChioToolCallResultIncomplete {
    fn from(value: &ChioToolCallResultIncomplete) -> Self {
        value.clone()
    }
}
///`ChioToolCallResultIncompleteReason`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioToolCallResultIncompleteReason(::std::string::String);
impl ::std::ops::Deref for ChioToolCallResultIncompleteReason {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioToolCallResultIncompleteReason> for ::std::string::String {
    fn from(value: ChioToolCallResultIncompleteReason) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioToolCallResultIncompleteReason>
for ChioToolCallResultIncompleteReason {
    fn from(value: &ChioToolCallResultIncompleteReason) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioToolCallResultIncompleteReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioToolCallResultIncompleteReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioToolCallResultIncompleteReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioToolCallResultIncompleteReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioToolCallResultIncompleteReason {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`ChioToolCallResultOk`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallResult ok",
///  "type": "object",
///  "required": [
///    "status",
///    "value"
///  ],
///  "properties": {
///    "status": {
///      "const": "ok"
///    },
///    "value": true
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallResultOk {
    pub status: ::serde_json::Value,
    pub value: ::serde_json::Value,
}
impl ::std::convert::From<&ChioToolCallResultOk> for ChioToolCallResultOk {
    fn from(value: &ChioToolCallResultOk) -> Self {
        value.clone()
    }
}
///`ChioToolCallResultStreamComplete`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "title": "Chio ToolCallResult stream_complete",
///  "type": "object",
///  "required": [
///    "status",
///    "total_chunks"
///  ],
///  "properties": {
///    "status": {
///      "const": "stream_complete"
///    },
///    "total_chunks": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioToolCallResultStreamComplete {
    pub status: ::serde_json::Value,
    pub total_chunks: u64,
}
impl ::std::convert::From<&ChioToolCallResultStreamComplete>
for ChioToolCallResultStreamComplete {
    fn from(value: &ChioToolCallResultStreamComplete) -> Self {
        value.clone()
    }
}
///One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-second expiry plus configured TTL that bound the lease's continued validity. Mirrors the `ClusterAuthorityLeaseView` serde shape in `crates/chio-cli/src/trust_control/service_types.rs` (lines 1837-1848). The view uses `serde(rename_all = camelCase)` so wire field names are camelCase. The shape is constructed in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (`cluster_authority_lease_view_locked`, lines 841-862) from the live cluster consensus view; `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future. NOTE: `leaseExpiresAt` and `termStartedAt` are unix **seconds** (computed in `cluster_and_reports.rs` lines 1580-1606 as `unix_timestamp_now() + lease_ttl_ms / 1000`), even though `leaseTtlMs` itself is in milliseconds. The asymmetry mirrors the live runtime shape and is preserved on the wire so consumers do not have to re-scale by 1000.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/trust-control/lease/v1",
///  "title": "Chio Trust-Control Authority Lease",
///  "description": "One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-second expiry plus configured TTL that bound the lease's continued validity. Mirrors the `ClusterAuthorityLeaseView` serde shape in `crates/chio-cli/src/trust_control/service_types.rs` (lines 1837-1848). The view uses `serde(rename_all = camelCase)` so wire field names are camelCase. The shape is constructed in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (`cluster_authority_lease_view_locked`, lines 841-862) from the live cluster consensus view; `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future. NOTE: `leaseExpiresAt` and `termStartedAt` are unix **seconds** (computed in `cluster_and_reports.rs` lines 1580-1606 as `unix_timestamp_now() + lease_ttl_ms / 1000`), even though `leaseTtlMs` itself is in milliseconds. The asymmetry mirrors the live runtime shape and is preserved on the wire so consumers do not have to re-scale by 1000.",
///  "type": "object",
///  "required": [
///    "authorityId",
///    "leaderUrl",
///    "leaseEpoch",
///    "leaseExpiresAt",
///    "leaseId",
///    "leaseTtlMs",
///    "leaseValid",
///    "term"
///  ],
///  "properties": {
///    "authorityId": {
///      "description": "Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.",
///      "type": "string",
///      "minLength": 1
///    },
///    "leaderUrl": {
///      "description": "Normalized URL of the cluster node that currently holds the authority lease.",
///      "type": "string",
///      "minLength": 1
///    },
///    "leaseEpoch": {
///      "description": "Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "leaseExpiresAt": {
///      "description": "Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + lease_ttl_ms / 1000` in `cluster_and_reports.rs` lines 1580-1606. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "leaseId": {
///      "description": "Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.",
///      "type": "string",
///      "minLength": 1
///    },
///    "leaseTtlMs": {
///      "description": "Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms by `authority_lease_ttl` (cluster_and_reports.rs lines 832-839). NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "leaseValid": {
///      "description": "True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false.",
///      "type": "boolean"
///    },
///    "term": {
///      "description": "Cluster election term that minted this lease. Monotonically non-decreasing.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "termStartedAt": {
///      "description": "Optional unix-second timestamp at which the current term began on this leader. Captured via `unix_timestamp_now()` in `cluster_and_reports.rs` line 1603. Omitted via `serde(skip_serializing_if = Option::is_none)` when unknown (no quorum or no leader).",
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioTrustControlAuthorityLease {
    ///Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.
    #[serde(rename = "authorityId")]
    pub authority_id: ChioTrustControlAuthorityLeaseAuthorityId,
    ///Normalized URL of the cluster node that currently holds the authority lease.
    #[serde(rename = "leaderUrl")]
    pub leader_url: ChioTrustControlAuthorityLeaseLeaderUrl,
    ///Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.
    #[serde(rename = "leaseEpoch")]
    pub lease_epoch: u64,
    ///Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + lease_ttl_ms / 1000` in `cluster_and_reports.rs` lines 1580-1606. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.
    #[serde(rename = "leaseExpiresAt")]
    pub lease_expires_at: u64,
    ///Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.
    #[serde(rename = "leaseId")]
    pub lease_id: ChioTrustControlAuthorityLeaseLeaseId,
    ///Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms by `authority_lease_ttl` (cluster_and_reports.rs lines 832-839). NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.
    #[serde(rename = "leaseTtlMs")]
    pub lease_ttl_ms: u64,
    ///True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false.
    #[serde(rename = "leaseValid")]
    pub lease_valid: bool,
    ///Cluster election term that minted this lease. Monotonically non-decreasing.
    pub term: u64,
    ///Optional unix-second timestamp at which the current term began on this leader. Captured via `unix_timestamp_now()` in `cluster_and_reports.rs` line 1603. Omitted via `serde(skip_serializing_if = Option::is_none)` when unknown (no quorum or no leader).
    #[serde(
        rename = "termStartedAt",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub term_started_at: ::std::option::Option<u64>,
}
impl ::std::convert::From<&ChioTrustControlAuthorityLease>
for ChioTrustControlAuthorityLease {
    fn from(value: &ChioTrustControlAuthorityLease) -> Self {
        value.clone()
    }
}
///Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlAuthorityLeaseAuthorityId(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlAuthorityLeaseAuthorityId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlAuthorityLeaseAuthorityId>
for ::std::string::String {
    fn from(value: ChioTrustControlAuthorityLeaseAuthorityId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlAuthorityLeaseAuthorityId>
for ChioTrustControlAuthorityLeaseAuthorityId {
    fn from(value: &ChioTrustControlAuthorityLeaseAuthorityId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlAuthorityLeaseAuthorityId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlAuthorityLeaseAuthorityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlAuthorityLeaseAuthorityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlAuthorityLeaseAuthorityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioTrustControlAuthorityLeaseAuthorityId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Normalized URL of the cluster node that currently holds the authority lease.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Normalized URL of the cluster node that currently holds the authority lease.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlAuthorityLeaseLeaderUrl(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlAuthorityLeaseLeaderUrl {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlAuthorityLeaseLeaderUrl>
for ::std::string::String {
    fn from(value: ChioTrustControlAuthorityLeaseLeaderUrl) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlAuthorityLeaseLeaderUrl>
for ChioTrustControlAuthorityLeaseLeaderUrl {
    fn from(value: &ChioTrustControlAuthorityLeaseLeaderUrl) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlAuthorityLeaseLeaderUrl {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlAuthorityLeaseLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlAuthorityLeaseLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlAuthorityLeaseLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioTrustControlAuthorityLeaseLeaderUrl {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlAuthorityLeaseLeaseId(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlAuthorityLeaseLeaseId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlAuthorityLeaseLeaseId>
for ::std::string::String {
    fn from(value: ChioTrustControlAuthorityLeaseLeaseId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlAuthorityLeaseLeaseId>
for ChioTrustControlAuthorityLeaseLeaseId {
    fn from(value: &ChioTrustControlAuthorityLeaseLeaseId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlAuthorityLeaseLeaseId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlAuthorityLeaseLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlAuthorityLeaseLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlAuthorityLeaseLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioTrustControlAuthorityLeaseLeaseId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///One trust-control heartbeat used to refresh a held authority lease before it expires. The heartbeat names the lease being refreshed (`leaseId` plus `leaseEpoch`), the leader URL claiming continued ownership, and the unix-millisecond observation timestamp at which the heartbeat was issued. Drafted from `spec/PROTOCOL.md` section 9 prose around `/v1/internal/cluster/status` and the cluster lease lifecycle described in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 832-877). NOTE: this schema is drafted from prose plus the `ClusterAuthorityLeaseView` shape; there is no dedicated `LeaseHeartbeatRequest` Rust struct in the live trust-control surface yet, so wire field names follow the same `serde(rename_all = camelCase)` convention used by the lease projection. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/trust-control/heartbeat/v1",
///  "title": "Chio Trust-Control Lease Heartbeat",
///  "description": "One trust-control heartbeat used to refresh a held authority lease before it expires. The heartbeat names the lease being refreshed (`leaseId` plus `leaseEpoch`), the leader URL claiming continued ownership, and the unix-millisecond observation timestamp at which the heartbeat was issued. Drafted from `spec/PROTOCOL.md` section 9 prose around `/v1/internal/cluster/status` and the cluster lease lifecycle described in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 832-877). NOTE: this schema is drafted from prose plus the `ClusterAuthorityLeaseView` shape; there is no dedicated `LeaseHeartbeatRequest` Rust struct in the live trust-control surface yet, so wire field names follow the same `serde(rename_all = camelCase)` convention used by the lease projection. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3.",
///  "type": "object",
///  "required": [
///    "leaderUrl",
///    "leaseEpoch",
///    "leaseId",
///    "observedAt"
///  ],
///  "properties": {
///    "leaderUrl": {
///      "description": "Normalized URL of the leader claiming continued ownership of the lease.",
///      "type": "string",
///      "minLength": 1
///    },
///    "leaseEpoch": {
///      "description": "Lease epoch carried alongside `leaseId`. Trust-control fails closed if the heartbeat targets a stale epoch.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "leaseId": {
///      "description": "Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.",
///      "type": "string",
///      "minLength": 1
///    },
///    "observedAt": {
///      "description": "Unix-millisecond timestamp at which the leader observed the cluster state that motivated this heartbeat.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "proposedExpiresAt": {
///      "description": "Optional unix-millisecond timestamp the leader proposes for the refreshed `leaseExpiresAt`. Trust-control may clamp this to the policy-bounded TTL.",
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioTrustControlLeaseHeartbeat {
    ///Normalized URL of the leader claiming continued ownership of the lease.
    #[serde(rename = "leaderUrl")]
    pub leader_url: ChioTrustControlLeaseHeartbeatLeaderUrl,
    ///Lease epoch carried alongside `leaseId`. Trust-control fails closed if the heartbeat targets a stale epoch.
    #[serde(rename = "leaseEpoch")]
    pub lease_epoch: u64,
    ///Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.
    #[serde(rename = "leaseId")]
    pub lease_id: ChioTrustControlLeaseHeartbeatLeaseId,
    ///Unix-millisecond timestamp at which the leader observed the cluster state that motivated this heartbeat.
    #[serde(rename = "observedAt")]
    pub observed_at: u64,
    ///Optional unix-millisecond timestamp the leader proposes for the refreshed `leaseExpiresAt`. Trust-control may clamp this to the policy-bounded TTL.
    #[serde(
        rename = "proposedExpiresAt",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub proposed_expires_at: ::std::option::Option<u64>,
}
impl ::std::convert::From<&ChioTrustControlLeaseHeartbeat>
for ChioTrustControlLeaseHeartbeat {
    fn from(value: &ChioTrustControlLeaseHeartbeat) -> Self {
        value.clone()
    }
}
///Normalized URL of the leader claiming continued ownership of the lease.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Normalized URL of the leader claiming continued ownership of the lease.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlLeaseHeartbeatLeaderUrl(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlLeaseHeartbeatLeaderUrl {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlLeaseHeartbeatLeaderUrl>
for ::std::string::String {
    fn from(value: ChioTrustControlLeaseHeartbeatLeaderUrl) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlLeaseHeartbeatLeaderUrl>
for ChioTrustControlLeaseHeartbeatLeaderUrl {
    fn from(value: &ChioTrustControlLeaseHeartbeatLeaderUrl) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlLeaseHeartbeatLeaderUrl {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlLeaseHeartbeatLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlLeaseHeartbeatLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlLeaseHeartbeatLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioTrustControlLeaseHeartbeatLeaderUrl {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlLeaseHeartbeatLeaseId(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlLeaseHeartbeatLeaseId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlLeaseHeartbeatLeaseId>
for ::std::string::String {
    fn from(value: ChioTrustControlLeaseHeartbeatLeaseId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlLeaseHeartbeatLeaseId>
for ChioTrustControlLeaseHeartbeatLeaseId {
    fn from(value: &ChioTrustControlLeaseHeartbeatLeaseId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlLeaseHeartbeatLeaseId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlLeaseHeartbeatLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlLeaseHeartbeatLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlLeaseHeartbeatLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioTrustControlLeaseHeartbeatLeaseId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///One trust-control termination request that voluntarily releases a held authority lease before its TTL expires. Termination names the lease being released (`leaseId` plus `leaseEpoch`), the leader URL releasing it, and a typed `reason` so operators can distinguish leader handoff from quorum loss or operator-initiated stepdown. Drafted from `spec/PROTOCOL.md` section 9 prose plus the lease invalidation paths in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 1595-1611) where loss of quorum or a leader change clears `lease_expires_at` and bumps the election term. NOTE: this schema is drafted from prose; there is no dedicated `LeaseTerminateRequest` Rust struct in the live trust-control surface yet. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3. Wire field names follow the `serde(rename_all = camelCase)` convention used by the sibling lease projection so the families stay consistent on the wire.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/trust-control/terminate/v1",
///  "title": "Chio Trust-Control Lease Termination",
///  "description": "One trust-control termination request that voluntarily releases a held authority lease before its TTL expires. Termination names the lease being released (`leaseId` plus `leaseEpoch`), the leader URL releasing it, and a typed `reason` so operators can distinguish leader handoff from quorum loss or operator-initiated stepdown. Drafted from `spec/PROTOCOL.md` section 9 prose plus the lease invalidation paths in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 1595-1611) where loss of quorum or a leader change clears `lease_expires_at` and bumps the election term. NOTE: this schema is drafted from prose; there is no dedicated `LeaseTerminateRequest` Rust struct in the live trust-control surface yet. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3. Wire field names follow the `serde(rename_all = camelCase)` convention used by the sibling lease projection so the families stay consistent on the wire.",
///  "type": "object",
///  "required": [
///    "leaderUrl",
///    "leaseEpoch",
///    "leaseId",
///    "observedAt",
///    "reason"
///  ],
///  "properties": {
///    "leaderUrl": {
///      "description": "Normalized URL of the leader releasing the lease.",
///      "type": "string",
///      "minLength": 1
///    },
///    "leaseEpoch": {
///      "description": "Lease epoch carried alongside `leaseId`.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "leaseId": {
///      "description": "Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.",
///      "type": "string",
///      "minLength": 1
///    },
///    "observedAt": {
///      "description": "Unix-millisecond timestamp at which the releasing leader observed the condition that motivated termination.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "reason": {
///      "description": "Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.",
///      "type": "string",
///      "enum": [
///        "leader_handoff",
///        "quorum_lost",
///        "operator_stepdown",
///        "term_advanced"
///      ]
///    },
///    "successorLeaderUrl": {
///      "description": "Optional normalized URL of the successor leader, when termination is part of a planned handoff.",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioTrustControlLeaseTermination {
    ///Normalized URL of the leader releasing the lease.
    #[serde(rename = "leaderUrl")]
    pub leader_url: ChioTrustControlLeaseTerminationLeaderUrl,
    ///Lease epoch carried alongside `leaseId`.
    #[serde(rename = "leaseEpoch")]
    pub lease_epoch: u64,
    ///Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.
    #[serde(rename = "leaseId")]
    pub lease_id: ChioTrustControlLeaseTerminationLeaseId,
    ///Unix-millisecond timestamp at which the releasing leader observed the condition that motivated termination.
    #[serde(rename = "observedAt")]
    pub observed_at: u64,
    ///Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.
    pub reason: ChioTrustControlLeaseTerminationReason,
    ///Optional normalized URL of the successor leader, when termination is part of a planned handoff.
    #[serde(
        rename = "successorLeaderUrl",
        default,
        skip_serializing_if = "::std::option::Option::is_none"
    )]
    pub successor_leader_url: ::std::option::Option<
        ChioTrustControlLeaseTerminationSuccessorLeaderUrl,
    >,
}
impl ::std::convert::From<&ChioTrustControlLeaseTermination>
for ChioTrustControlLeaseTermination {
    fn from(value: &ChioTrustControlLeaseTermination) -> Self {
        value.clone()
    }
}
///Normalized URL of the leader releasing the lease.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Normalized URL of the leader releasing the lease.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlLeaseTerminationLeaderUrl(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlLeaseTerminationLeaderUrl {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlLeaseTerminationLeaderUrl>
for ::std::string::String {
    fn from(value: ChioTrustControlLeaseTerminationLeaderUrl) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlLeaseTerminationLeaderUrl>
for ChioTrustControlLeaseTerminationLeaderUrl {
    fn from(value: &ChioTrustControlLeaseTerminationLeaderUrl) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlLeaseTerminationLeaderUrl {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlLeaseTerminationLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlLeaseTerminationLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlLeaseTerminationLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioTrustControlLeaseTerminationLeaderUrl {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlLeaseTerminationLeaseId(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlLeaseTerminationLeaseId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlLeaseTerminationLeaseId>
for ::std::string::String {
    fn from(value: ChioTrustControlLeaseTerminationLeaseId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlLeaseTerminationLeaseId>
for ChioTrustControlLeaseTerminationLeaseId {
    fn from(value: &ChioTrustControlLeaseTerminationLeaseId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlLeaseTerminationLeaseId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlLeaseTerminationLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlLeaseTerminationLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlLeaseTerminationLeaseId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ChioTrustControlLeaseTerminationLeaseId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.",
///  "type": "string",
///  "enum": [
///    "leader_handoff",
///    "quorum_lost",
///    "operator_stepdown",
///    "term_advanced"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioTrustControlLeaseTerminationReason {
    #[serde(rename = "leader_handoff")]
    LeaderHandoff,
    #[serde(rename = "quorum_lost")]
    QuorumLost,
    #[serde(rename = "operator_stepdown")]
    OperatorStepdown,
    #[serde(rename = "term_advanced")]
    TermAdvanced,
}
impl ::std::convert::From<&Self> for ChioTrustControlLeaseTerminationReason {
    fn from(value: &ChioTrustControlLeaseTerminationReason) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioTrustControlLeaseTerminationReason {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::LeaderHandoff => f.write_str("leader_handoff"),
            Self::QuorumLost => f.write_str("quorum_lost"),
            Self::OperatorStepdown => f.write_str("operator_stepdown"),
            Self::TermAdvanced => f.write_str("term_advanced"),
        }
    }
}
impl ::std::str::FromStr for ChioTrustControlLeaseTerminationReason {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "leader_handoff" => Ok(Self::LeaderHandoff),
            "quorum_lost" => Ok(Self::QuorumLost),
            "operator_stepdown" => Ok(Self::OperatorStepdown),
            "term_advanced" => Ok(Self::TermAdvanced),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlLeaseTerminationReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlLeaseTerminationReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlLeaseTerminationReason {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Optional normalized URL of the successor leader, when termination is part of a planned handoff.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional normalized URL of the successor leader, when termination is part of a planned handoff.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlLeaseTerminationSuccessorLeaderUrl(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlLeaseTerminationSuccessorLeaderUrl {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlLeaseTerminationSuccessorLeaderUrl>
for ::std::string::String {
    fn from(value: ChioTrustControlLeaseTerminationSuccessorLeaderUrl) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlLeaseTerminationSuccessorLeaderUrl>
for ChioTrustControlLeaseTerminationSuccessorLeaderUrl {
    fn from(value: &ChioTrustControlLeaseTerminationSuccessorLeaderUrl) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlLeaseTerminationSuccessorLeaderUrl {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlLeaseTerminationSuccessorLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlLeaseTerminationSuccessorLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlLeaseTerminationSuccessorLeaderUrl {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioTrustControlLeaseTerminationSuccessorLeaderUrl {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/chio-control-plane/src/attestation.rs` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "$id": "https://chio-protocol.dev/schemas/chio-wire/v1/trust-control/attestation/v1",
///  "title": "Chio Trust-Control Runtime Attestation Evidence",
///  "description": "One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/chio-control-plane/src/attestation.rs` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).",
///  "type": "object",
///  "required": [
///    "evidence_sha256",
///    "expires_at",
///    "issued_at",
///    "schema",
///    "tier",
///    "verifier"
///  ],
///  "properties": {
///    "claims": {
///      "description": "Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims."
///    },
///    "evidence_sha256": {
///      "description": "Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
///      "type": "string",
///      "minLength": 1
///    },
///    "expires_at": {
///      "description": "Unix timestamp (seconds) when this attestation expires. Trust-control fails closed when `now < issued_at` or `now >= expires_at`.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "issued_at": {
///      "description": "Unix timestamp (seconds) when this attestation was issued.",
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "runtime_identity": {
///      "description": "Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.",
///      "type": "string",
///      "minLength": 1
///    },
///    "schema": {
///      "description": "Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
///      "type": "string",
///      "minLength": 1
///    },
///    "tier": {
///      "description": "Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240) which uses `serde(rename_all = snake_case)`.",
///      "type": "string",
///      "enum": [
///        "none",
///        "basic",
///        "attested",
///        "verified"
///      ]
///    },
///    "verifier": {
///      "description": "Attestation verifier or relying party that accepted the evidence.",
///      "type": "string",
///      "minLength": 1
///    },
///    "workload_identity": {
///      "description": "Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.",
///      "type": "object",
///      "required": [
///        "credentialKind",
///        "path",
///        "scheme",
///        "trustDomain",
///        "uri"
///      ],
///      "properties": {
///        "credentialKind": {
///          "description": "Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
///          "type": "string",
///          "enum": [
///            "uri",
///            "x509_svid",
///            "jwt_svid"
///          ]
///        },
///        "path": {
///          "description": "Canonical workload path within the trust domain.",
///          "type": "string"
///        },
///        "scheme": {
///          "description": "Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
///          "type": "string",
///          "enum": [
///            "spiffe"
///          ]
///        },
///        "trustDomain": {
///          "description": "Stable trust domain resolved from the identifier.",
///          "type": "string",
///          "minLength": 1
///        },
///        "uri": {
///          "description": "Canonical workload identifier URI.",
///          "type": "string",
///          "minLength": 1
///        }
///      },
///      "additionalProperties": false
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioTrustControlRuntimeAttestationEvidence {
    ///Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub claims: ::std::option::Option<::serde_json::Value>,
    ///Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
    pub evidence_sha256: ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256,
    ///Unix timestamp (seconds) when this attestation expires. Trust-control fails closed when `now < issued_at` or `now >= expires_at`.
    pub expires_at: u64,
    ///Unix timestamp (seconds) when this attestation was issued.
    pub issued_at: u64,
    ///Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub runtime_identity: ::std::option::Option<
        ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity,
    >,
    ///Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
    pub schema: ChioTrustControlRuntimeAttestationEvidenceSchema,
    ///Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240) which uses `serde(rename_all = snake_case)`.
    pub tier: ChioTrustControlRuntimeAttestationEvidenceTier,
    ///Attestation verifier or relying party that accepted the evidence.
    pub verifier: ChioTrustControlRuntimeAttestationEvidenceVerifier,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub workload_identity: ::std::option::Option<
        ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentity,
    >,
}
impl ::std::convert::From<&ChioTrustControlRuntimeAttestationEvidence>
for ChioTrustControlRuntimeAttestationEvidence {
    fn from(value: &ChioTrustControlRuntimeAttestationEvidence) -> Self {
        value.clone()
    }
}
///Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256 {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256>
for ::std::string::String {
    fn from(value: ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256>
for ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256 {
    fn from(value: &ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256 {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256 {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioTrustControlRuntimeAttestationEvidenceEvidenceSha256 {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity(
    ::std::string::String,
);
impl ::std::ops::Deref for ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity>
for ::std::string::String {
    fn from(value: ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity>
for ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity {
    fn from(value: &ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioTrustControlRuntimeAttestationEvidenceRuntimeIdentity {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlRuntimeAttestationEvidenceSchema(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlRuntimeAttestationEvidenceSchema {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlRuntimeAttestationEvidenceSchema>
for ::std::string::String {
    fn from(value: ChioTrustControlRuntimeAttestationEvidenceSchema) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlRuntimeAttestationEvidenceSchema>
for ChioTrustControlRuntimeAttestationEvidenceSchema {
    fn from(value: &ChioTrustControlRuntimeAttestationEvidenceSchema) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlRuntimeAttestationEvidenceSchema {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlRuntimeAttestationEvidenceSchema {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceSchema {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceSchema {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioTrustControlRuntimeAttestationEvidenceSchema {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240) which uses `serde(rename_all = snake_case)`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240) which uses `serde(rename_all = snake_case)`.",
///  "type": "string",
///  "enum": [
///    "none",
///    "basic",
///    "attested",
///    "verified"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioTrustControlRuntimeAttestationEvidenceTier {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "basic")]
    Basic,
    #[serde(rename = "attested")]
    Attested,
    #[serde(rename = "verified")]
    Verified,
}
impl ::std::convert::From<&Self> for ChioTrustControlRuntimeAttestationEvidenceTier {
    fn from(value: &ChioTrustControlRuntimeAttestationEvidenceTier) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for ChioTrustControlRuntimeAttestationEvidenceTier {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::None => f.write_str("none"),
            Self::Basic => f.write_str("basic"),
            Self::Attested => f.write_str("attested"),
            Self::Verified => f.write_str("verified"),
        }
    }
}
impl ::std::str::FromStr for ChioTrustControlRuntimeAttestationEvidenceTier {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "none" => Ok(Self::None),
            "basic" => Ok(Self::Basic),
            "attested" => Ok(Self::Attested),
            "verified" => Ok(Self::Verified),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for ChioTrustControlRuntimeAttestationEvidenceTier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceTier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceTier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Attestation verifier or relying party that accepted the evidence.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Attestation verifier or relying party that accepted the evidence.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlRuntimeAttestationEvidenceVerifier(::std::string::String);
impl ::std::ops::Deref for ChioTrustControlRuntimeAttestationEvidenceVerifier {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlRuntimeAttestationEvidenceVerifier>
for ::std::string::String {
    fn from(value: ChioTrustControlRuntimeAttestationEvidenceVerifier) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlRuntimeAttestationEvidenceVerifier>
for ChioTrustControlRuntimeAttestationEvidenceVerifier {
    fn from(value: &ChioTrustControlRuntimeAttestationEvidenceVerifier) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ChioTrustControlRuntimeAttestationEvidenceVerifier {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlRuntimeAttestationEvidenceVerifier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceVerifier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceVerifier {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioTrustControlRuntimeAttestationEvidenceVerifier {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.",
///  "type": "object",
///  "required": [
///    "credentialKind",
///    "path",
///    "scheme",
///    "trustDomain",
///    "uri"
///  ],
///  "properties": {
///    "credentialKind": {
///      "description": "Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
///      "type": "string",
///      "enum": [
///        "uri",
///        "x509_svid",
///        "jwt_svid"
///      ]
///    },
///    "path": {
///      "description": "Canonical workload path within the trust domain.",
///      "type": "string"
///    },
///    "scheme": {
///      "description": "Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
///      "type": "string",
///      "enum": [
///        "spiffe"
///      ]
///    },
///    "trustDomain": {
///      "description": "Stable trust domain resolved from the identifier.",
///      "type": "string",
///      "minLength": 1
///    },
///    "uri": {
///      "description": "Canonical workload identifier URI.",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentity {
    ///Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
    #[serde(rename = "credentialKind")]
    pub credential_kind: ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind,
    ///Canonical workload path within the trust domain.
    pub path: ::std::string::String,
    ///Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
    pub scheme: ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme,
    ///Stable trust domain resolved from the identifier.
    #[serde(rename = "trustDomain")]
    pub trust_domain: ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain,
    ///Canonical workload identifier URI.
    pub uri: ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri,
}
impl ::std::convert::From<&ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentity>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentity {
    fn from(value: &ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentity) -> Self {
        value.clone()
    }
}
///Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
///  "type": "string",
///  "enum": [
///    "uri",
///    "x509_svid",
///    "jwt_svid"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind {
    #[serde(rename = "uri")]
    Uri,
    #[serde(rename = "x509_svid")]
    X509Svid,
    #[serde(rename = "jwt_svid")]
    JwtSvid,
}
impl ::std::convert::From<&Self>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind {
    fn from(
        value: &ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Uri => f.write_str("uri"),
            Self::X509Svid => f.write_str("x509_svid"),
            Self::JwtSvid => f.write_str("jwt_svid"),
        }
    }
}
impl ::std::str::FromStr
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "uri" => Ok(Self::Uri),
            "x509_svid" => Ok(Self::X509Svid),
            "jwt_svid" => Ok(Self::JwtSvid),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityCredentialKind {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
///  "type": "string",
///  "enum": [
///    "spiffe"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme {
    #[serde(rename = "spiffe")]
    Spiffe,
}
impl ::std::convert::From<&Self>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme {
    fn from(
        value: &ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme,
    ) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Spiffe => f.write_str("spiffe"),
        }
    }
}
impl ::std::str::FromStr
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "spiffe" => Ok(Self::Spiffe),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityScheme {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Stable trust domain resolved from the identifier.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Stable trust domain resolved from the identifier.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<
    ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain,
> for ::std::string::String {
    fn from(
        value: ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<
    &ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain,
> for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain {
    fn from(
        value: &ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityTrustDomain {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Canonical workload identifier URI.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Canonical workload identifier URI.",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri(
    ::std::string::String,
);
impl ::std::ops::Deref
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri>
for ::std::string::String {
    fn from(
        value: ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri,
    ) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri {
    fn from(
        value: &ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri,
    ) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de>
for ChioTrustControlRuntimeAttestationEvidenceWorkloadIdentityUri {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.",
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "type": "string",
///      "minLength": 1
///    },
///    "value": true
///  }
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
pub struct Constraint {
    #[serde(rename = "type")]
    pub type_: ConstraintType,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub value: ::std::option::Option<::serde_json::Value>,
}
impl ::std::convert::From<&Constraint> for Constraint {
    fn from(value: &Constraint) -> Self {
        value.clone()
    }
}
///Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.",
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "type": "string",
///      "minLength": 1
///    },
///    "value": true
///  }
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
pub struct Constraint {
    #[serde(rename = "type")]
    pub type_: ConstraintType,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub value: ::std::option::Option<::serde_json::Value>,
}
impl ::std::convert::From<&Constraint> for Constraint {
    fn from(value: &Constraint) -> Self {
        value.clone()
    }
}
///`ConstraintType`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ConstraintType(::std::string::String);
impl ::std::ops::Deref for ConstraintType {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ConstraintType> for ::std::string::String {
    fn from(value: ConstraintType) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ConstraintType> for ConstraintType {
    fn from(value: &ConstraintType) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ConstraintType {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ConstraintType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ConstraintType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ConstraintType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ConstraintType {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = \"verdict\", rename_all = \"snake_case\")]`).",
///  "type": "object",
///  "oneOf": [
///    {
///      "required": [
///        "verdict"
///      ],
///      "properties": {
///        "verdict": {
///          "const": "allow"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "required": [
///        "guard",
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "guard": {
///          "description": "The guard or validation step that triggered the denial.",
///          "type": "string"
///        },
///        "reason": {
///          "description": "Human-readable reason for the denial.",
///          "type": "string"
///        },
///        "verdict": {
///          "const": "deny"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "reason": {
///          "description": "Human-readable reason for the cancellation.",
///          "type": "string"
///        },
///        "verdict": {
///          "const": "cancelled"
///        }
///      },
///      "additionalProperties": false
///    },
///    {
///      "required": [
///        "reason",
///        "verdict"
///      ],
///      "properties": {
///        "reason": {
///          "description": "Human-readable reason for the incomplete terminal state.",
///          "type": "string"
///        },
///        "verdict": {
///          "const": "incomplete"
///        }
///      },
///      "additionalProperties": false
///    }
///  ],
///  "required": [
///    "verdict"
///  ]
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(untagged, deny_unknown_fields)]
pub enum Decision {
    Variant0 { verdict: ::serde_json::Value },
    Variant1 {
        ///The guard or validation step that triggered the denial.
        guard: ::std::string::String,
        ///Human-readable reason for the denial.
        reason: ::std::string::String,
        verdict: ::serde_json::Value,
    },
    Variant2 {
        ///Human-readable reason for the cancellation.
        reason: ::std::string::String,
        verdict: ::serde_json::Value,
    },
    Variant3 {
        ///Human-readable reason for the incomplete terminal state.
        reason: ::std::string::String,
        verdict: ::serde_json::Value,
    },
}
impl ::std::convert::From<&Self> for Decision {
    fn from(value: &Decision) -> Self {
        value.clone()
    }
}
///A single link in a delegation chain. Mirrors `DelegationLink`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "A single link in a delegation chain. Mirrors `DelegationLink`.",
///  "type": "object",
///  "required": [
///    "capability_id",
///    "delegatee",
///    "delegator",
///    "signature",
///    "timestamp"
///  ],
///  "properties": {
///    "attenuations": {
///      "type": "array",
///      "items": {
///        "type": "object",
///        "required": [
///          "type"
///        ],
///        "properties": {
///          "type": {
///            "type": "string",
///            "minLength": 1
///          }
///        }
///      }
///    },
///    "capability_id": {
///      "type": "string",
///      "minLength": 1
///    },
///    "delegatee": {
///      "description": "Receiving public key. Same encoding as the token-level `issuer`/`subject`.",
///      "type": "string",
///      "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///    },
///    "delegator": {
///      "description": "Delegating public key. Same encoding as the token-level `issuer`/`subject`.",
///      "type": "string",
///      "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///    },
///    "signature": {
///      "description": "Delegation-link signature. Same encoding as the token-level `signature`.",
///      "type": "string",
///      "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$"
///    },
///    "timestamp": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct DelegationLink {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub attenuations: ::std::vec::Vec<DelegationLinkAttenuationsItem>,
    pub capability_id: DelegationLinkCapabilityId,
    ///Receiving public key. Same encoding as the token-level `issuer`/`subject`.
    pub delegatee: DelegationLinkDelegatee,
    ///Delegating public key. Same encoding as the token-level `issuer`/`subject`.
    pub delegator: DelegationLinkDelegator,
    ///Delegation-link signature. Same encoding as the token-level `signature`.
    pub signature: DelegationLinkSignature,
    pub timestamp: u64,
}
impl ::std::convert::From<&DelegationLink> for DelegationLink {
    fn from(value: &DelegationLink) -> Self {
        value.clone()
    }
}
///`DelegationLinkAttenuationsItem`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "object",
///  "required": [
///    "type"
///  ],
///  "properties": {
///    "type": {
///      "type": "string",
///      "minLength": 1
///    }
///  }
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
pub struct DelegationLinkAttenuationsItem {
    #[serde(rename = "type")]
    pub type_: DelegationLinkAttenuationsItemType,
}
impl ::std::convert::From<&DelegationLinkAttenuationsItem>
for DelegationLinkAttenuationsItem {
    fn from(value: &DelegationLinkAttenuationsItem) -> Self {
        value.clone()
    }
}
///`DelegationLinkAttenuationsItemType`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct DelegationLinkAttenuationsItemType(::std::string::String);
impl ::std::ops::Deref for DelegationLinkAttenuationsItemType {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<DelegationLinkAttenuationsItemType> for ::std::string::String {
    fn from(value: DelegationLinkAttenuationsItemType) -> Self {
        value.0
    }
}
impl ::std::convert::From<&DelegationLinkAttenuationsItemType>
for DelegationLinkAttenuationsItemType {
    fn from(value: &DelegationLinkAttenuationsItemType) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for DelegationLinkAttenuationsItemType {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for DelegationLinkAttenuationsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String>
for DelegationLinkAttenuationsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String>
for DelegationLinkAttenuationsItemType {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for DelegationLinkAttenuationsItemType {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`DelegationLinkCapabilityId`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct DelegationLinkCapabilityId(::std::string::String);
impl ::std::ops::Deref for DelegationLinkCapabilityId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<DelegationLinkCapabilityId> for ::std::string::String {
    fn from(value: DelegationLinkCapabilityId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&DelegationLinkCapabilityId> for DelegationLinkCapabilityId {
    fn from(value: &DelegationLinkCapabilityId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for DelegationLinkCapabilityId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for DelegationLinkCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for DelegationLinkCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for DelegationLinkCapabilityId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for DelegationLinkCapabilityId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Receiving public key. Same encoding as the token-level `issuer`/`subject`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Receiving public key. Same encoding as the token-level `issuer`/`subject`.",
///  "type": "string",
///  "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct DelegationLinkDelegatee(::std::string::String);
impl ::std::ops::Deref for DelegationLinkDelegatee {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<DelegationLinkDelegatee> for ::std::string::String {
    fn from(value: DelegationLinkDelegatee) -> Self {
        value.0
    }
}
impl ::std::convert::From<&DelegationLinkDelegatee> for DelegationLinkDelegatee {
    fn from(value: &DelegationLinkDelegatee) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for DelegationLinkDelegatee {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new(
                    "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$",
                )
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for DelegationLinkDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for DelegationLinkDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for DelegationLinkDelegatee {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for DelegationLinkDelegatee {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Delegating public key. Same encoding as the token-level `issuer`/`subject`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Delegating public key. Same encoding as the token-level `issuer`/`subject`.",
///  "type": "string",
///  "pattern": "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct DelegationLinkDelegator(::std::string::String);
impl ::std::ops::Deref for DelegationLinkDelegator {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<DelegationLinkDelegator> for ::std::string::String {
    fn from(value: DelegationLinkDelegator) -> Self {
        value.0
    }
}
impl ::std::convert::From<&DelegationLinkDelegator> for DelegationLinkDelegator {
    fn from(value: &DelegationLinkDelegator) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for DelegationLinkDelegator {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new(
                    "^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$",
                )
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for DelegationLinkDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for DelegationLinkDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for DelegationLinkDelegator {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for DelegationLinkDelegator {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Delegation-link signature. Same encoding as the token-level `signature`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Delegation-link signature. Same encoding as the token-level `signature`.",
///  "type": "string",
///  "pattern": "^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct DelegationLinkSignature(::std::string::String);
impl ::std::ops::Deref for DelegationLinkSignature {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<DelegationLinkSignature> for ::std::string::String {
    fn from(value: DelegationLinkSignature) -> Self {
        value.0
    }
}
impl ::std::convert::From<&DelegationLinkSignature> for DelegationLinkSignature {
    fn from(value: &DelegationLinkSignature) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for DelegationLinkSignature {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        {
            ::regress::Regex::new("^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$")
                .unwrap()
        });
        if PATTERN.find(value).is_none() {
            return Err(
                "doesn't match pattern \"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$\""
                    .into(),
            );
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for DelegationLinkSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for DelegationLinkSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for DelegationLinkSignature {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for DelegationLinkSignature {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.",
///  "type": "object",
///  "required": [
///    "guard_name",
///    "verdict"
///  ],
///  "properties": {
///    "details": {
///      "description": "Optional details about the guard's decision.",
///      "type": "string"
///    },
///    "guard_name": {
///      "description": "Name of the guard (e.g. `ForbiddenPathGuard`).",
///      "type": "string",
///      "minLength": 1
///    },
///    "verdict": {
///      "description": "Whether the guard passed (true) or denied (false).",
///      "type": "boolean"
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct GuardEvidence {
    ///Optional details about the guard's decision.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub details: ::std::option::Option<::std::string::String>,
    ///Name of the guard (e.g. `ForbiddenPathGuard`).
    pub guard_name: GuardEvidenceGuardName,
    ///Whether the guard passed (true) or denied (false).
    pub verdict: bool,
}
impl ::std::convert::From<&GuardEvidence> for GuardEvidence {
    fn from(value: &GuardEvidence) -> Self {
        value.clone()
    }
}
///Name of the guard (e.g. `ForbiddenPathGuard`).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Name of the guard (e.g. `ForbiddenPathGuard`).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct GuardEvidenceGuardName(::std::string::String);
impl ::std::ops::Deref for GuardEvidenceGuardName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<GuardEvidenceGuardName> for ::std::string::String {
    fn from(value: GuardEvidenceGuardName) -> Self {
        value.0
    }
}
impl ::std::convert::From<&GuardEvidenceGuardName> for GuardEvidenceGuardName {
    fn from(value: &GuardEvidenceGuardName) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for GuardEvidenceGuardName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for GuardEvidenceGuardName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for GuardEvidenceGuardName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for GuardEvidenceGuardName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for GuardEvidenceGuardName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.",
///  "type": "object",
///  "required": [
///    "currency",
///    "units"
///  ],
///  "properties": {
///    "currency": {
///      "type": "string",
///      "minLength": 1
///    },
///    "units": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct MonetaryAmount {
    pub currency: MonetaryAmountCurrency,
    pub units: u64,
}
impl ::std::convert::From<&MonetaryAmount> for MonetaryAmount {
    fn from(value: &MonetaryAmount) -> Self {
        value.clone()
    }
}
///A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.",
///  "type": "object",
///  "required": [
///    "currency",
///    "units"
///  ],
///  "properties": {
///    "currency": {
///      "type": "string",
///      "minLength": 1
///    },
///    "units": {
///      "type": "integer",
///      "minimum": 0.0
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct MonetaryAmount {
    pub currency: MonetaryAmountCurrency,
    pub units: u64,
}
impl ::std::convert::From<&MonetaryAmount> for MonetaryAmount {
    fn from(value: &MonetaryAmount) -> Self {
        value.clone()
    }
}
///`MonetaryAmountCurrency`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct MonetaryAmountCurrency(::std::string::String);
impl ::std::ops::Deref for MonetaryAmountCurrency {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<MonetaryAmountCurrency> for ::std::string::String {
    fn from(value: MonetaryAmountCurrency) -> Self {
        value.0
    }
}
impl ::std::convert::From<&MonetaryAmountCurrency> for MonetaryAmountCurrency {
    fn from(value: &MonetaryAmountCurrency) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for MonetaryAmountCurrency {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for MonetaryAmountCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for MonetaryAmountCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for MonetaryAmountCurrency {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for MonetaryAmountCurrency {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///`Operation`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum Operation {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self> for Operation {
    fn from(value: &Operation) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for Operation {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr for Operation {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for Operation {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for Operation {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for Operation {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///`Operation`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "enum": [
///    "invoke",
///    "read_result",
///    "read",
///    "subscribe",
///    "get",
///    "delegate"
///  ]
///}
/// ```
/// </details>
#[derive(
    ::serde::Deserialize,
    ::serde::Serialize,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd
)]
pub enum Operation {
    #[serde(rename = "invoke")]
    Invoke,
    #[serde(rename = "read_result")]
    ReadResult,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "get")]
    Get,
    #[serde(rename = "delegate")]
    Delegate,
}
impl ::std::convert::From<&Self> for Operation {
    fn from(value: &Operation) -> Self {
        value.clone()
    }
}
impl ::std::fmt::Display for Operation {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match *self {
            Self::Invoke => f.write_str("invoke"),
            Self::ReadResult => f.write_str("read_result"),
            Self::Read => f.write_str("read"),
            Self::Subscribe => f.write_str("subscribe"),
            Self::Get => f.write_str("get"),
            Self::Delegate => f.write_str("delegate"),
        }
    }
}
impl ::std::str::FromStr for Operation {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        match value {
            "invoke" => Ok(Self::Invoke),
            "read_result" => Ok(Self::ReadResult),
            "read" => Ok(Self::Read),
            "subscribe" => Ok(Self::Subscribe),
            "get" => Ok(Self::Get),
            "delegate" => Ok(Self::Delegate),
            _ => Err("invalid value".into()),
        }
    }
}
impl ::std::convert::TryFrom<&str> for Operation {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for Operation {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for Operation {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
///Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.",
///  "type": "object",
///  "required": [
///    "operations",
///    "prompt_name"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/operation"
///      },
///      "minItems": 1
///    },
///    "prompt_name": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PromptGrant {
    pub operations: ::std::vec::Vec<Operation>,
    pub prompt_name: PromptGrantPromptName,
}
impl ::std::convert::From<&PromptGrant> for PromptGrant {
    fn from(value: &PromptGrant) -> Self {
        value.clone()
    }
}
///Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.",
///  "type": "object",
///  "required": [
///    "operations",
///    "prompt_name"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/operation"
///      },
///      "minItems": 1
///    },
///    "prompt_name": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PromptGrant {
    pub operations: ::std::vec::Vec<Operation>,
    pub prompt_name: PromptGrantPromptName,
}
impl ::std::convert::From<&PromptGrant> for PromptGrant {
    fn from(value: &PromptGrant) -> Self {
        value.clone()
    }
}
///`PromptGrantPromptName`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct PromptGrantPromptName(::std::string::String);
impl ::std::ops::Deref for PromptGrantPromptName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<PromptGrantPromptName> for ::std::string::String {
    fn from(value: PromptGrantPromptName) -> Self {
        value.0
    }
}
impl ::std::convert::From<&PromptGrantPromptName> for PromptGrantPromptName {
    fn from(value: &PromptGrantPromptName) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for PromptGrantPromptName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for PromptGrantPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for PromptGrantPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for PromptGrantPromptName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for PromptGrantPromptName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.",
///  "type": "object",
///  "required": [
///    "operations",
///    "uri_pattern"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/operation"
///      },
///      "minItems": 1
///    },
///    "uri_pattern": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ResourceGrant {
    pub operations: ::std::vec::Vec<Operation>,
    pub uri_pattern: ResourceGrantUriPattern,
}
impl ::std::convert::From<&ResourceGrant> for ResourceGrant {
    fn from(value: &ResourceGrant) -> Self {
        value.clone()
    }
}
///Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.",
///  "type": "object",
///  "required": [
///    "operations",
///    "uri_pattern"
///  ],
///  "properties": {
///    "operations": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/operation"
///      },
///      "minItems": 1
///    },
///    "uri_pattern": {
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ResourceGrant {
    pub operations: ::std::vec::Vec<Operation>,
    pub uri_pattern: ResourceGrantUriPattern,
}
impl ::std::convert::From<&ResourceGrant> for ResourceGrant {
    fn from(value: &ResourceGrant) -> Self {
        value.clone()
    }
}
///`ResourceGrantUriPattern`
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ResourceGrantUriPattern(::std::string::String);
impl ::std::ops::Deref for ResourceGrantUriPattern {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ResourceGrantUriPattern> for ::std::string::String {
    fn from(value: ResourceGrantUriPattern) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ResourceGrantUriPattern> for ResourceGrantUriPattern {
    fn from(value: &ResourceGrantUriPattern) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ResourceGrantUriPattern {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ResourceGrantUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ResourceGrantUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ResourceGrantUriPattern {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ResourceGrantUriPattern {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Describes the tool call that was evaluated. Mirrors `ToolCallAction`.",
///  "type": "object",
///  "required": [
///    "parameter_hash",
///    "parameters"
///  ],
///  "properties": {
///    "parameter_hash": {
///      "description": "SHA-256 hex hash of the canonical JSON of `parameters`.",
///      "type": "string",
///      "pattern": "^[0-9a-f]{64}$"
///    },
///    "parameters": {
///      "description": "The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`)."
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ToolCallAction {
    ///SHA-256 hex hash of the canonical JSON of `parameters`.
    pub parameter_hash: ToolCallActionParameterHash,
    ///The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).
    pub parameters: ::serde_json::Value,
}
impl ::std::convert::From<&ToolCallAction> for ToolCallAction {
    fn from(value: &ToolCallAction) -> Self {
        value.clone()
    }
}
///SHA-256 hex hash of the canonical JSON of `parameters`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "SHA-256 hex hash of the canonical JSON of `parameters`.",
///  "type": "string",
///  "pattern": "^[0-9a-f]{64}$"
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ToolCallActionParameterHash(::std::string::String);
impl ::std::ops::Deref for ToolCallActionParameterHash {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ToolCallActionParameterHash> for ::std::string::String {
    fn from(value: ToolCallActionParameterHash) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ToolCallActionParameterHash> for ToolCallActionParameterHash {
    fn from(value: &ToolCallActionParameterHash) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ToolCallActionParameterHash {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        static PATTERN: ::std::sync::LazyLock<::regress::Regex> = ::std::sync::LazyLock::new(||
        { ::regress::Regex::new("^[0-9a-f]{64}$").unwrap() });
        if PATTERN.find(value).is_none() {
            return Err("doesn't match pattern \"^[0-9a-f]{64}$\"".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ToolCallActionParameterHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ToolCallActionParameterHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ToolCallActionParameterHash {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ToolCallActionParameterHash {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Authorization to invoke a single tool. Mirrors `ToolGrant`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Authorization to invoke a single tool. Mirrors `ToolGrant`.",
///  "type": "object",
///  "required": [
///    "operations",
///    "server_id",
///    "tool_name"
///  ],
///  "properties": {
///    "constraints": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/constraint"
///      }
///    },
///    "dpop_required": {
///      "description": "If true, the kernel requires a valid DPoP proof for every invocation under this grant.",
///      "type": "boolean"
///    },
///    "max_cost_per_invocation": {
///      "$ref": "#/$defs/monetaryAmount"
///    },
///    "max_invocations": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "max_total_cost": {
///      "$ref": "#/$defs/monetaryAmount"
///    },
///    "operations": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/operation"
///      },
///      "minItems": 1
///    },
///    "server_id": {
///      "description": "Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).",
///      "type": "string",
///      "minLength": 1
///    },
///    "tool_name": {
///      "description": "Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub constraints: ::std::vec::Vec<Constraint>,
    ///If true, the kernel requires a valid DPoP proof for every invocation under this grant.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub dpop_required: ::std::option::Option<bool>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_cost_per_invocation: ::std::option::Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_invocations: ::std::option::Option<u64>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_total_cost: ::std::option::Option<MonetaryAmount>,
    pub operations: ::std::vec::Vec<Operation>,
    ///Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).
    pub server_id: ToolGrantServerId,
    ///Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).
    pub tool_name: ToolGrantToolName,
}
impl ::std::convert::From<&ToolGrant> for ToolGrant {
    fn from(value: &ToolGrant) -> Self {
        value.clone()
    }
}
///Authorization to invoke a single tool. Mirrors `ToolGrant`.
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Authorization to invoke a single tool. Mirrors `ToolGrant`.",
///  "type": "object",
///  "required": [
///    "operations",
///    "server_id",
///    "tool_name"
///  ],
///  "properties": {
///    "constraints": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/constraint"
///      }
///    },
///    "dpop_required": {
///      "description": "If true, the kernel requires a valid DPoP proof for every invocation under this grant.",
///      "type": "boolean"
///    },
///    "max_cost_per_invocation": {
///      "$ref": "#/$defs/monetaryAmount"
///    },
///    "max_invocations": {
///      "type": "integer",
///      "minimum": 0.0
///    },
///    "max_total_cost": {
///      "$ref": "#/$defs/monetaryAmount"
///    },
///    "operations": {
///      "type": "array",
///      "items": {
///        "$ref": "#/$defs/operation"
///      },
///      "minItems": 1
///    },
///    "server_id": {
///      "description": "Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).",
///      "type": "string",
///      "minLength": 1
///    },
///    "tool_name": {
///      "description": "Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).",
///      "type": "string",
///      "minLength": 1
///    }
///  },
///  "additionalProperties": false
///}
/// ```
/// </details>
#[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    #[serde(default, skip_serializing_if = "::std::vec::Vec::is_empty")]
    pub constraints: ::std::vec::Vec<Constraint>,
    ///If true, the kernel requires a valid DPoP proof for every invocation under this grant.
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub dpop_required: ::std::option::Option<bool>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_cost_per_invocation: ::std::option::Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_invocations: ::std::option::Option<u64>,
    #[serde(default, skip_serializing_if = "::std::option::Option::is_none")]
    pub max_total_cost: ::std::option::Option<MonetaryAmount>,
    pub operations: ::std::vec::Vec<Operation>,
    ///Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).
    pub server_id: ToolGrantServerId,
    ///Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).
    pub tool_name: ToolGrantToolName,
}
impl ::std::convert::From<&ToolGrant> for ToolGrant {
    fn from(value: &ToolGrant) -> Self {
        value.clone()
    }
}
///Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ToolGrantServerId(::std::string::String);
impl ::std::ops::Deref for ToolGrantServerId {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ToolGrantServerId> for ::std::string::String {
    fn from(value: ToolGrantServerId) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ToolGrantServerId> for ToolGrantServerId {
    fn from(value: &ToolGrantServerId) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ToolGrantServerId {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ToolGrantServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ToolGrantServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ToolGrantServerId {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ToolGrantServerId {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
///Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).
///
/// <details><summary>JSON schema</summary>
///
/// ```json
///{
///  "description": "Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).",
///  "type": "string",
///  "minLength": 1
///}
/// ```
/// </details>
#[derive(::serde::Serialize, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct ToolGrantToolName(::std::string::String);
impl ::std::ops::Deref for ToolGrantToolName {
    type Target = ::std::string::String;
    fn deref(&self) -> &::std::string::String {
        &self.0
    }
}
impl ::std::convert::From<ToolGrantToolName> for ::std::string::String {
    fn from(value: ToolGrantToolName) -> Self {
        value.0
    }
}
impl ::std::convert::From<&ToolGrantToolName> for ToolGrantToolName {
    fn from(value: &ToolGrantToolName) -> Self {
        value.clone()
    }
}
impl ::std::str::FromStr for ToolGrantToolName {
    type Err = self::error::ConversionError;
    fn from_str(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        if value.chars().count() < 1usize {
            return Err("shorter than 1 characters".into());
        }
        Ok(Self(value.to_string()))
    }
}
impl ::std::convert::TryFrom<&str> for ToolGrantToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &str,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<&::std::string::String> for ToolGrantToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: &::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl ::std::convert::TryFrom<::std::string::String> for ToolGrantToolName {
    type Error = self::error::ConversionError;
    fn try_from(
        value: ::std::string::String,
    ) -> ::std::result::Result<Self, self::error::ConversionError> {
        value.parse()
    }
}
impl<'de> ::serde::Deserialize<'de> for ToolGrantToolName {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::std::string::String::deserialize(deserializer)?
            .parse()
            .map_err(|e: self::error::ConversionError| {
                <D::Error as ::serde::de::Error>::custom(e.to_string())
            })
    }
}
