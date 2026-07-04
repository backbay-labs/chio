use std::env;

use crate::bedrock::bedrock_caller_identity;
use crate::cli::ProviderArg;
use crate::RecordError;

#[derive(Debug)]
pub(crate) enum Credentials {
    OpenAi {
        api_key: String,
        org_id: String,
    },
    Anthropic {
        api_key: String,
        workspace_id: String,
    },
    Bedrock {
        profile: Option<String>,
        caller_arn: String,
        account_id: String,
        assumed_role_session_arn: Option<String>,
    },
}

pub(crate) fn credentials_for(provider: ProviderArg) -> Result<Credentials, RecordError> {
    match provider {
        ProviderArg::OpenAi => {
            let api_key = required_env("OPENAI_API_KEY").ok_or(RecordError::MissingEnv {
                provider: "openai",
                vars: "OPENAI_API_KEY and OPENAI_ORGANIZATION",
            })?;
            let org_id = required_env("OPENAI_ORGANIZATION").ok_or(RecordError::MissingEnv {
                provider: "openai",
                vars: "OPENAI_API_KEY and OPENAI_ORGANIZATION",
            })?;
            Ok(Credentials::OpenAi { api_key, org_id })
        }
        ProviderArg::Anthropic => {
            let api_key = required_env("ANTHROPIC_API_KEY").ok_or(RecordError::MissingEnv {
                provider: "anthropic",
                vars: "ANTHROPIC_API_KEY and CHIO_ANTHROPIC_WORKSPACE_ID",
            })?;
            let workspace_id =
                required_env("CHIO_ANTHROPIC_WORKSPACE_ID").ok_or(RecordError::MissingEnv {
                    provider: "anthropic",
                    vars: "ANTHROPIC_API_KEY and CHIO_ANTHROPIC_WORKSPACE_ID",
                })?;
            Ok(Credentials::Anthropic {
                api_key,
                workspace_id,
            })
        }
        ProviderArg::Bedrock => {
            let profile = required_env("AWS_PROFILE");
            let has_static_credentials = required_env("AWS_ACCESS_KEY_ID").is_some()
                && required_env("AWS_SECRET_ACCESS_KEY").is_some();
            if profile.is_none() && !has_static_credentials {
                return Err(RecordError::MissingEnv {
                    provider: "bedrock",
                    vars: "AWS_PROFILE or AWS_ACCESS_KEY_ID plus AWS_SECRET_ACCESS_KEY",
                });
            }
            let identity = bedrock_caller_identity(profile.as_deref())?;
            Ok(Credentials::Bedrock {
                profile,
                caller_arn: identity.caller_arn,
                account_id: identity.account_id,
                assumed_role_session_arn: identity.assumed_role_session_arn,
            })
        }
    }
}

fn required_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
