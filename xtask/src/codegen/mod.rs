use crate::XtaskError;

mod go;
mod python;
mod rust;
mod ts;

pub(crate) use rust::errors_regen;
#[cfg(test)]
pub(crate) use ts::{normalize_ts_chunk, pascal_case, ts_header, ts_namespace_name};

/// Relative path (from workspace root) of the chio-wire/v1 schema directory.
const CHIO_WIRE_V1_SCHEMAS: &str = "spec/schemas/chio-wire/v1";

pub(crate) fn run_codegen(args: Vec<String>) -> Result<(), XtaskError> {
    // Accepted forms:
    //   cargo xtask codegen rust [--check]
    //   cargo xtask codegen --lang rust [--check]
    let mut lang: Option<String> = None;
    let mut check_only = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--check" => check_only = true,
            "--lang" => match iter.next() {
                Some(value) => lang = Some(value),
                None => {
                    return Err(XtaskError::Usage(
                        "codegen: --lang requires an argument (e.g. --lang rust)".into(),
                    ));
                }
            },
            "rust" | "python" | "ts" | "go" => {
                if lang.is_none() {
                    lang = Some(arg);
                } else {
                    return Err(XtaskError::Usage(format!(
                        "codegen: language already specified; unexpected argument: {arg}"
                    )));
                }
            }
            other => {
                return Err(XtaskError::Usage(format!(
                    "codegen: unknown argument: {other}"
                )));
            }
        }
    }

    let lang = match lang {
        Some(lang) => lang,
        None if check_only => "rust".to_string(),
        None => {
            return Err(XtaskError::Usage(
                "codegen: language is required (rust|python|ts|go)".into(),
            ));
        }
    };

    match lang.as_str() {
        "rust" => rust::codegen_rust(check_only),
        "ts" => ts::codegen_ts(check_only),
        "go" => go::codegen_go(check_only),
        "python" => python::codegen_python(check_only),
        other => Err(XtaskError::Usage(format!(
            "codegen: unknown language: {other} (expected rust|python|ts|go)"
        ))),
    }
}
