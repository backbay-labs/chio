use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cli::ItfToRegressionArgs;
use crate::formal::itf::ItfTrace;
use crate::formal::receipt_before_allow_trace::{
    decode_receipt_before_allow, ReceiptBeforeAllowWitness,
};
use crate::support::digest_to_hex;
use crate::{display_path, XtaskError};

const MAX_TRACE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
enum ReplayFamily {
    ReceiptBeforeAllow,
}

impl ReplayFamily {
    fn parse(value: &str) -> Result<Self, XtaskError> {
        match value {
            "ReceiptBeforeAllow" | "receipt-before-allow" | "receipt_before_allow" => {
                Ok(Self::ReceiptBeforeAllow)
            }
            _ => Err(XtaskError::Validation(format!(
                "no completed replay mapping is registered for {value}"
            ))),
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::ReceiptBeforeAllow => "receipt_before_allow",
        }
    }

    fn replay_function(self) -> &'static str {
        match self {
            Self::ReceiptBeforeAllow => "replay_receipt_before_allow",
        }
    }
}

pub(crate) fn run(args: &ItfToRegressionArgs) -> Result<(), XtaskError> {
    let family = ReplayFamily::parse(&args.family)?;
    let trace_path = canonical_trace_path(&args.trace)?;
    let trace_bytes = read_trace(&trace_path)?;
    let trace = ItfTrace::parse(&trace_bytes, &display_path(&trace_path))?;
    let witness = family.decode(&trace)?;
    let digest = digest_to_hex(&Sha256::digest(&trace_bytes));

    fs::create_dir_all(&args.out)
        .map_err(|error| XtaskError::Io(display_path(&args.out), error))?;
    let output_dir = fs::canonicalize(&args.out)
        .map_err(|error| XtaskError::Io(display_path(&args.out), error))?;
    let include_path = relative_path(&output_dir, &trace_path)?;
    let source = render_source(&trace, family, &witness, &digest, &include_path)?;
    let output = output_dir.join(format!(
        "regression_formal_{}_{}.rs",
        family.slug(),
        &digest[..12]
    ));
    write_output(&output, source.as_bytes())?;
    println!("{}", output.display());
    Ok(())
}

impl ReplayFamily {
    fn decode(self, trace: &ItfTrace) -> Result<ReceiptBeforeAllowWitness, XtaskError> {
        match self {
            Self::ReceiptBeforeAllow => decode_receipt_before_allow(&trace.vars, &trace.states)
                .map_err(|error| XtaskError::Validation(error.to_string())),
        }
    }
}

fn canonical_trace_path(path: &Path) -> Result<PathBuf, XtaskError> {
    let name = path.file_name().and_then(|value| value.to_str());
    if !name.is_some_and(|value| value.ends_with(".itf.json")) {
        return Err(XtaskError::Validation(
            "trace path must end in .itf.json".to_string(),
        ));
    }
    fs::canonicalize(path).map_err(|error| XtaskError::Io(display_path(path), error))
}

fn read_trace(path: &Path) -> Result<Vec<u8>, XtaskError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|error| XtaskError::Io(display_path(path), error))?;
    let metadata = file
        .metadata()
        .map_err(|error| XtaskError::Io(display_path(path), error))?;
    if !metadata.file_type().is_file() {
        return Err(XtaskError::Validation(
            "trace path must name a regular file".to_string(),
        ));
    }
    if metadata.len() > MAX_TRACE_BYTES {
        return Err(XtaskError::Validation(format!(
            "trace exceeds the {MAX_TRACE_BYTES}-byte input limit"
        )));
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_TRACE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| XtaskError::Io(display_path(path), error))?;
    if bytes.len() as u64 > MAX_TRACE_BYTES {
        return Err(XtaskError::Validation(format!(
            "trace exceeds the {MAX_TRACE_BYTES}-byte input limit"
        )));
    }
    Ok(bytes)
}

fn relative_path(from: &Path, to: &Path) -> Result<String, XtaskError> {
    let from_components: Vec<Component<'_>> = from.components().collect();
    let to_components: Vec<Component<'_>> = to.components().collect();
    let common = from_components
        .iter()
        .zip(&to_components)
        .take_while(|(left, right)| left == right)
        .count();
    if common == 0 {
        return Err(XtaskError::Validation(
            "trace and output directory have no common filesystem root".to_string(),
        ));
    }

    let mut relative = PathBuf::new();
    for _ in &from_components[common..] {
        relative.push("..");
    }
    for component in &to_components[common..] {
        relative.push(component.as_os_str());
    }
    let value = relative.to_str().ok_or_else(|| {
        XtaskError::Validation("trace include path is not valid UTF-8".to_string())
    })?;
    Ok(value.replace(std::path::MAIN_SEPARATOR, "/"))
}

fn render_source(
    trace: &ItfTrace,
    family: ReplayFamily,
    witness: &ReceiptBeforeAllowWitness,
    digest: &str,
    include_path: &str,
) -> Result<String, XtaskError> {
    let slug = family.slug();
    let short_digest = &digest[..12];
    let mut source = String::new();
    source.push_str(
        "use chio_formal_diff_tests::counterexample::{assert_trace_shape, ExpectedStep};\n",
    );
    source.push_str("#[cfg(not(target_arch = \"wasm32\"))]\n");
    source.push_str("use chio_formal_diff_tests::counterexample::");
    source.push_str(family.replay_function());
    source.push_str(";\n\n");
    source.push_str("const TRACE_JSON: &str = include_str!(");
    source.push_str(&rust_string(include_path));
    source.push_str(");\n");
    source.push_str("const TRACE_SHA256: &str = ");
    source.push_str(&rust_string(digest));
    source.push_str(";\n");
    source.push_str("#[cfg(not(target_arch = \"wasm32\"))]\n");
    source.push_str("const WITNESS_AUTHORITY: &str = ");
    source.push_str(&rust_string(&witness.authority));
    source.push_str(";\n");
    source.push_str("#[cfg(not(target_arch = \"wasm32\"))]\n");
    source.push_str("const WITNESS_CAPABILITY: &str = ");
    source.push_str(&rust_string(&witness.capability));
    source.push_str(";\n");
    source.push_str("const VARIABLES: &[&str] = &[\n");
    for variable in &trace.vars {
        source.push_str("    ");
        source.push_str(&rust_string(variable));
        source.push_str(",\n");
    }
    source.push_str("];\n");
    source.push_str("const LOOP_START: Option<usize> = ");
    match trace.loop_start {
        Some(index) => source.push_str(&format!("Some({index})")),
        None => source.push_str("None"),
    }
    source.push_str(";\n\nconst STEPS: &[ExpectedStep<'_>] = &[\n");
    for (index, state) in trace.states.iter().enumerate() {
        source.push_str("    ExpectedStep {\n");
        source.push_str(&format!("        index: {index},\n"));
        source.push_str("        action_hint: ");
        source.push_str(&rust_string(&action_hint(trace, index)));
        source.push_str(",\n        expected: &[\n");
        for variable in &trace.vars {
            let value = state.get(variable).ok_or_else(|| {
                XtaskError::Validation(format!("validated state {index} lost variable {variable}"))
            })?;
            let encoded = serde_json::to_string(value).map_err(|error| {
                XtaskError::Json(format!("state {index} variable {variable}"), error)
            })?;
            source.push_str("            (\n                ");
            source.push_str(&rust_string(variable));
            source.push_str(",\n                ");
            if encoded.chars().count() <= 72 {
                source.push_str(&rust_string(&encoded));
            } else {
                source.push_str("concat!(\n");
                for chunk in string_chunks(&encoded, 72) {
                    source.push_str("                    ");
                    source.push_str(&rust_string(&chunk));
                    source.push_str(",\n");
                }
                source.push_str("                )");
            }
            source.push_str(",\n            ),\n");
        }
        source.push_str("        ],\n    },\n");
    }
    source.push_str("];\n\n#[test]\nfn regression_formal_");
    source.push_str(slug);
    source.push('_');
    source.push_str(short_digest);
    source.push_str("_trace_shape() -> Result<(), Box<dyn std::error::Error>> {\n");
    source.push_str(
        "    assert_trace_shape(file!(), TRACE_JSON, TRACE_SHA256, VARIABLES, STEPS, LOOP_START)?;\n",
    );
    source.push_str(
        "    Ok(())\n}\n\n#[cfg(not(target_arch = \"wasm32\"))]\n#[test]\nfn regression_formal_",
    );
    source.push_str(slug);
    source.push('_');
    source.push_str(short_digest);
    source.push_str("_replay() -> Result<(), Box<dyn std::error::Error>> {\n    ");
    source.push_str(family.replay_function());
    source.push_str("(TRACE_JSON, WITNESS_AUTHORITY, WITNESS_CAPABILITY)?;\n    Ok(())\n}\n");
    format_rust(&source)
}

fn action_hint(trace: &ItfTrace, index: usize) -> String {
    let state = &trace.states[index];
    if let Some(action) = state
        .get("#meta")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("action"))
        .and_then(Value::as_str)
        .filter(|action| !action.is_empty())
    {
        return action.to_string();
    }
    if index == 0 {
        return "initial".to_string();
    }
    let previous = &trace.states[index - 1];
    let changed: Vec<&str> = trace
        .vars
        .iter()
        .filter(|name| previous.get(*name) != state.get(*name))
        .map(String::as_str)
        .collect();
    if changed.is_empty() {
        "stutter".to_string()
    } else {
        format!("changed: {}", changed.join(", "))
    }
}

fn rust_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        encoded.extend(character.escape_default());
    }
    encoded.push('"');
    encoded
}

fn string_chunks(value: &str, limit: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_len = 0;
    for character in value.chars() {
        if current_len == limit {
            chunks.push(current);
            current = String::new();
            current_len = 0;
        }
        current.push(character);
        current_len += 1;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn format_rust(source: &str) -> Result<String, XtaskError> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| XtaskError::Process(format!("could not start rustfmt: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| XtaskError::Process("rustfmt stdin was unavailable".to_string()))?;
    stdin
        .write_all(source.as_bytes())
        .map_err(|error| XtaskError::Process(format!("could not write to rustfmt: {error}")))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| XtaskError::Process(format!("rustfmt did not finish: {error}")))?;
    if !output.status.success() {
        return Err(XtaskError::Process(format!(
            "rustfmt rejected generated source: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout).map_err(|error| {
        XtaskError::Validation(format!("rustfmt returned non-UTF-8 source: {error}"))
    })
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<(), XtaskError> {
    match fs::read(path) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {
            return Err(XtaskError::Drift(format!(
                "refusing to overwrite {} with different generated content",
                path.display()
            )));
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(XtaskError::Io(display_path(path), error));
        }
        Err(_) => {}
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| XtaskError::Io(display_path(path), error))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(XtaskError::Io(display_path(path), error));
    }
    Ok(())
}
