//! Validated state-machine tables and their committed generated outputs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::{write_if_changed, CodegenError, Result};

pub const STATEMACHINES_INPUT: &str = "spec/statemachines";
pub const CONFORMANCE_ORDERING_DIR: &str = "crates/tooling/chio-conformance/tests/_generated";
pub const STATE_MACHINES_DOC_OUTPUT: &str = "docs/reference/generated/STATE_MACHINES.md";

const GENERATED_MARKER: &str = "DO NOT EDIT - regenerate via 'cargo xtask codegen rust'";
const GENERATED_SOURCE_MARKER: &str = "Source: spec/statemachines/";
const GENERATED_ROOTS: &[&str] = &[
    "crates/trust/chio-federation/src/_generated",
    CONFORMANCE_ORDERING_DIR,
    "docs/reference/generated",
];

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateMachine {
    pub schema: String,
    pub machine: String,
    pub title: String,
    pub scope: String,
    pub owner: String,
    pub doc_refs: Vec<String>,
    pub emit: Vec<Emission>,
    pub states: Vec<String>,
    pub initial: String,
    #[serde(default)]
    pub terminal: Vec<String>,
    pub transitions: Vec<Transition>,
    pub rust: Option<RustEmission>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Emission {
    Conformance,
    Docs,
    Rust,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub from: String,
    pub to: String,
    pub message: String,
    #[serde(default)]
    pub guards: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustEmission {
    pub public_module: String,
    pub handlers: String,
    pub error: String,
    #[serde(default)]
    pub lifetime: bool,
    pub terminal_output_type: String,
    pub terminal_output_method: String,
}

pub fn load_statemachines(input_dir: &Path) -> Result<Vec<StateMachine>> {
    if !input_dir.is_dir() {
        return Err(CodegenError::StateMachine(
            input_dir.to_path_buf(),
            "input directory does not exist".to_string(),
        ));
    }
    let input_metadata = fs::symlink_metadata(input_dir)
        .map_err(|err| CodegenError::Io(input_dir.to_path_buf(), err))?;
    if input_metadata.file_type().is_symlink() {
        return Err(CodegenError::StateMachine(
            input_dir.to_path_buf(),
            "input directory must not be a symlink".to_string(),
        ));
    }

    let mut files = Vec::new();
    for entry in
        fs::read_dir(input_dir).map_err(|err| CodegenError::Io(input_dir.to_path_buf(), err))?
    {
        let entry = entry.map_err(|err| CodegenError::Io(input_dir.to_path_buf(), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| CodegenError::Io(path.clone(), err))?;
        if file_type.is_symlink() {
            return Err(CodegenError::StateMachine(
                path,
                "symlinks are not accepted in the input directory".to_string(),
            ));
        }
        if file_type.is_file() && path.extension() == Some(OsStr::new("toml")) {
            files.push(path);
        }
    }
    files.sort();
    if files.is_empty() {
        return Err(CodegenError::StateMachine(
            input_dir.to_path_buf(),
            "no TOML inputs found".to_string(),
        ));
    }

    let mut machines = Vec::with_capacity(files.len());
    let mut names = BTreeSet::new();
    for path in files {
        let raw =
            fs::read_to_string(&path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
        let machine: StateMachine = toml::from_str(&raw)
            .map_err(|err| CodegenError::StateMachine(path.clone(), err.to_string()))?;
        validate_machine(&machine, &path)?;
        if !names.insert(machine.machine.clone()) {
            return Err(CodegenError::StateMachine(
                path,
                format!("duplicate machine name {}", machine.machine),
            ));
        }
        machines.push(machine);
    }
    Ok(machines)
}

pub fn render_statemachine_outputs(input_dir: &Path) -> Result<BTreeMap<PathBuf, String>> {
    let machines = load_statemachines(input_dir)?;
    let mut outputs = BTreeMap::new();

    for machine in &machines {
        if machine.emit.contains(&Emission::Rust) {
            let path = rust_output_path(machine)?;
            insert_output(&mut outputs, path, render_rust(machine)?, input_dir)?;
        }
        if machine.emit.contains(&Emission::Conformance) {
            let path = Path::new(CONFORMANCE_ORDERING_DIR)
                .join(format!("{}_ordering.rs", machine.machine));
            insert_output(&mut outputs, path, render_conformance(machine)?, input_dir)?;
        }
    }

    if machines
        .iter()
        .any(|machine| machine.emit.contains(&Emission::Docs))
    {
        outputs.insert(
            PathBuf::from(STATE_MACHINES_DOC_OUTPUT),
            render_docs(&machines),
        );
    }
    Ok(outputs)
}

pub fn codegen_statemachines(input_dir: &Path, repo_root: &Path) -> Result<Vec<PathBuf>> {
    let outputs = render_statemachine_outputs(input_dir)?;
    let expected: BTreeSet<PathBuf> = outputs.keys().cloned().collect();
    let managed = find_managed_outputs(repo_root)?;
    for obsolete in managed.difference(&expected) {
        let path = repo_root.join(obsolete);
        fs::remove_file(&path).map_err(|err| CodegenError::Io(path, err))?;
    }

    let mut written = Vec::with_capacity(outputs.len());
    for (relative, body) in outputs {
        let path = repo_root.join(&relative);
        let parent = path.parent().ok_or_else(|| {
            CodegenError::StateMachine(path.clone(), "output has no parent".to_string())
        })?;
        fs::create_dir_all(parent).map_err(|err| CodegenError::Io(parent.to_path_buf(), err))?;
        write_if_changed(&path, body.as_bytes())?;
        written.push(relative);
    }
    Ok(written)
}

pub fn check_statemachine_outputs(input_dir: &Path, repo_root: &Path) -> Result<Vec<PathBuf>> {
    let outputs = render_statemachine_outputs(input_dir)?;
    let expected: BTreeSet<PathBuf> = outputs.keys().cloned().collect();
    let managed = find_managed_outputs(repo_root)?;
    let mut differences = Vec::new();

    for (relative, body) in &outputs {
        let path = repo_root.join(relative);
        match fs::read(&path) {
            Ok(bytes) if bytes == body.as_bytes() => {}
            Ok(bytes) => differences.push(format!(
                "{} is stale (computed {} bytes, on-disk {} bytes)",
                relative.display(),
                body.len(),
                bytes.len()
            )),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                differences.push(format!("{} is missing", relative.display()));
            }
            Err(err) => return Err(CodegenError::Io(path, err)),
        }
    }
    for extra in managed.difference(&expected) {
        differences.push(format!("{} is no longer generated", extra.display()));
    }

    if differences.is_empty() {
        Ok(expected.into_iter().collect())
    } else {
        Err(CodegenError::GeneratedDrift(format!(
            "rerun `cargo xtask codegen rust`:\n  - {}",
            differences.join("\n  - ")
        )))
    }
}

fn insert_output(
    outputs: &mut BTreeMap<PathBuf, String>,
    path: PathBuf,
    body: String,
    input_dir: &Path,
) -> Result<()> {
    if outputs.insert(path.clone(), body).is_some() {
        return Err(CodegenError::StateMachine(
            input_dir.to_path_buf(),
            format!("multiple machines emit {}", path.display()),
        ));
    }
    Ok(())
}

fn validate_machine(machine: &StateMachine, path: &Path) -> Result<()> {
    let fail = |message: String| CodegenError::StateMachine(path.to_path_buf(), message);
    if machine.schema != "chio.statemachine.v1" {
        return Err(fail(format!("unsupported schema {}", machine.schema)));
    }
    if !is_snake_identifier(&machine.machine) {
        return Err(fail("machine must be a snake_case identifier".to_string()));
    }
    if path.file_stem().and_then(OsStr::to_str) != Some(machine.machine.as_str()) {
        return Err(fail("file stem must match machine".to_string()));
    }
    if machine.title.trim().is_empty()
        || machine.scope.trim().is_empty()
        || contains_line_break(&machine.title)
        || contains_line_break(&machine.scope)
    {
        return Err(fail(
            "title and scope must be non-empty single lines".to_string(),
        ));
    }
    validate_relative_path(&machine.owner).map_err(|message| fail(format!("owner: {message}")))?;
    if machine.doc_refs.is_empty()
        || machine.doc_refs.iter().any(|reference| {
            let Some((path, anchor)) = reference.split_once('#') else {
                return true;
            };
            anchor.is_empty()
                || contains_line_break(reference)
                || validate_relative_path(path).is_err()
        })
    {
        return Err(fail(
            "doc_refs must contain relative paths with anchors".to_string(),
        ));
    }
    if machine.emit.is_empty() || !all_unique(&machine.emit) {
        return Err(fail("emit must be non-empty and unique".to_string()));
    }
    if machine.states.is_empty() || !all_unique(&machine.states) {
        return Err(fail("states must be non-empty and unique".to_string()));
    }
    if machine
        .states
        .iter()
        .any(|state| !is_state_identifier(state))
    {
        return Err(fail(
            "states must be PascalCase ASCII identifiers".to_string(),
        ));
    }
    let state_set: BTreeSet<&str> = machine.states.iter().map(String::as_str).collect();
    if !state_set.contains(machine.initial.as_str()) {
        return Err(fail("initial state is not declared".to_string()));
    }
    if !all_unique(&machine.terminal)
        || machine
            .terminal
            .iter()
            .any(|state| !state_set.contains(state.as_str()))
    {
        return Err(fail(
            "terminal states must be unique declared states".to_string(),
        ));
    }

    let terminal: BTreeSet<&str> = machine.terminal.iter().map(String::as_str).collect();
    let mut edges = BTreeSet::new();
    for transition in &machine.transitions {
        if !state_set.contains(transition.from.as_str())
            || !state_set.contains(transition.to.as_str())
        {
            return Err(fail(format!(
                "transition {} -> {} references an unknown state",
                transition.from, transition.to
            )));
        }
        if !is_snake_identifier(&transition.message) {
            return Err(fail(format!(
                "message {} must be a snake_case identifier",
                transition.message
            )));
        }
        if !all_unique(&transition.guards)
            || transition
                .guards
                .iter()
                .any(|guard| !is_snake_identifier(guard))
        {
            return Err(fail(format!(
                "guards for {} from {} must be unique snake_case identifiers",
                transition.message, transition.from
            )));
        }
        if !edges.insert((transition.from.as_str(), transition.message.as_str())) {
            return Err(fail(format!(
                "duplicate transition from {} for {}",
                transition.from, transition.message
            )));
        }
        if terminal.contains(transition.from.as_str()) {
            return Err(fail(format!(
                "terminal state {} has an outgoing transition",
                transition.from
            )));
        }
    }

    for state in &machine.states {
        if !terminal.contains(state.as_str())
            && !machine
                .transitions
                .iter()
                .any(|transition| transition.from == *state)
        {
            return Err(fail(format!(
                "non-terminal state {state} has no outgoing transition"
            )));
        }
    }
    let reachable = reachable_states(machine);
    if let Some(state) = machine
        .states
        .iter()
        .find(|state| !reachable.contains(state.as_str()))
    {
        return Err(fail(format!("state {state} is unreachable")));
    }

    match (machine.emit.contains(&Emission::Rust), &machine.rust) {
        (true, Some(rust)) => validate_rust(machine, rust, path)?,
        (true, None) => return Err(fail("rust emission requires a [rust] table".to_string())),
        (false, Some(_)) => {
            return Err(fail(
                "[rust] is only valid when rust appears in emit".to_string(),
            ));
        }
        (false, None) => {}
    }
    Ok(())
}

fn validate_rust(machine: &StateMachine, rust: &RustEmission, path: &Path) -> Result<()> {
    let fail = |message: String| CodegenError::StateMachine(path.to_path_buf(), message);
    if machine.terminal.len() != 1 {
        return Err(fail(
            "rust emission requires exactly one terminal state".to_string(),
        ));
    }
    if !machine.owner.starts_with("crates/") {
        return Err(fail("rust owner must be under crates/".to_string()));
    }
    if rust.public_module.trim().is_empty()
        || rust.handlers.trim().is_empty()
        || rust.error.trim().is_empty()
        || rust.terminal_output_type.trim().is_empty()
    {
        return Err(fail(
            "rust paths and output type must be non-empty".to_string(),
        ));
    }
    for (name, value) in [
        ("public_module", &rust.public_module),
        ("handlers", &rust.handlers),
        ("error", &rust.error),
    ] {
        syn::parse_str::<syn::Path>(value)
            .map_err(|error| fail(format!("rust {name} is not a valid path: {error}")))?;
    }
    syn::parse_str::<syn::Type>(&rust.terminal_output_type).map_err(|error| {
        fail(format!(
            "rust terminal_output_type is not a valid type: {error}"
        ))
    })?;
    if !is_snake_identifier(&rust.terminal_output_method) {
        return Err(fail(
            "terminal_output_method must be a snake_case identifier".to_string(),
        ));
    }
    Ok(())
}

fn reachable_states(machine: &StateMachine) -> BTreeSet<&str> {
    let mut reachable = BTreeSet::from([machine.initial.as_str()]);
    let mut queue = VecDeque::from([machine.initial.as_str()]);
    while let Some(state) = queue.pop_front() {
        for transition in machine
            .transitions
            .iter()
            .filter(|transition| transition.from == state)
        {
            if reachable.insert(transition.to.as_str()) {
                queue.push_back(transition.to.as_str());
            }
        }
    }
    reachable
}

fn render_rust(machine: &StateMachine) -> Result<String> {
    let rust = machine.rust.as_ref().ok_or_else(|| {
        CodegenError::StateMachine(
            PathBuf::from(&machine.machine),
            "missing rust settings".to_string(),
        )
    })?;
    let terminal = machine.terminal.first().ok_or_else(|| {
        CodegenError::StateMachine(
            PathBuf::from(&machine.machine),
            "missing terminal state".to_string(),
        )
    })?;
    let source = format!("{STATEMACHINES_INPUT}/{}.toml", machine.machine);
    let header = rust_header(&source, &machine.owner);
    let mut out = String::new();
    out.push_str(&format!(
        "//! Ordered states for {}.\n//!\n//! {}\n\n",
        machine.title, machine.scope
    ));

    if let Some(skip) = machine
        .transitions
        .iter()
        .find(|transition| transition.from != machine.initial)
    {
        let lifetime = if rust.lifetime { "<'_>" } else { "" };
        out.push_str(&format!(
            "/// Skipping an intermediate state does not compile.\n///\n/// ```compile_fail\n/// use {}::{};\n/// fn skip(state: {}{}) {{\n///     let _ = state.{}();\n/// }}\n/// ```\n",
            rust.public_module, machine.initial, machine.initial, lifetime, skip.message
        ));
    }
    if let Some(incoming) = machine
        .transitions
        .iter()
        .find(|transition| transition.to == *terminal)
    {
        out.push_str(&format!(
            "/// A terminal state cannot repeat its terminal transition.\n///\n/// ```compile_fail\n/// use {}::{};\n/// fn repeat(state: {}) {{\n///     let _ = state.{}();\n/// }}\n/// ```\n",
            rust.public_module, terminal, terminal, incoming.message
        ));
    }

    for state in &machine.states {
        if state == terminal {
            out.push_str(&format!(
                "pub struct {state} {{\n    output: {},\n}}\n\n",
                rust.terminal_output_type
            ));
        } else {
            let lifetime_decl = if rust.lifetime { "<'a>" } else { "" };
            let lifetime_use = if rust.lifetime { "<'a>" } else { "" };
            out.push_str(&format!(
                "pub struct {state}{lifetime_decl} {{\n    data: {}::{state}Data{lifetime_use},\n}}\n\n",
                rust.handlers
            ));
        }
    }

    let initial_lifetime = if rust.lifetime { "<'a>" } else { "" };
    out.push_str(&format!(
        "impl{initial_lifetime} {}{initial_lifetime} {{\n",
        machine.initial
    ));
    out.push_str(&format!(
        "    pub(crate) fn from_data(data: {}::{}Data{initial_lifetime}) -> Self {{\n        Self {{ data }}\n    }}\n",
        rust.handlers, machine.initial
    ));
    append_transition_methods(&mut out, machine, rust, &machine.initial, terminal);
    out.push_str("}\n\n");

    for state in machine
        .states
        .iter()
        .filter(|state| **state != machine.initial && **state != *terminal)
    {
        let lifetime = if rust.lifetime { "<'a>" } else { "" };
        out.push_str(&format!("impl{lifetime} {state}{lifetime} {{\n"));
        append_transition_methods(&mut out, machine, rust, state, terminal);
        out.push_str("}\n\n");
    }

    out.push_str(&format!(
        "impl {terminal} {{\n    #[must_use]\n    pub fn {}(self) -> {} {{\n        self.output\n    }}\n}}\n",
        rust.terminal_output_method, rust.terminal_output_type
    ));
    format_rust_output(&header, &out)
}

fn append_transition_methods(
    out: &mut String,
    machine: &StateMachine,
    rust: &RustEmission,
    state: &str,
    terminal: &str,
) {
    for transition in machine
        .transitions
        .iter()
        .filter(|transition| transition.from == state)
    {
        let guard_text = if transition.guards.is_empty() {
            "No additional runtime guard is declared.".to_string()
        } else {
            format!("Runtime guards: {}.", transition.guards.join(", "))
        };
        let target = if transition.to == terminal || !rust.lifetime {
            transition.to.clone()
        } else {
            format!("{}<'a>", transition.to)
        };
        let field = if transition.to == terminal {
            "output"
        } else {
            "data"
        };
        out.push_str(&format!(
            "    /// Consume `{}` and enter `{}`. {}\n    pub fn {}(self) -> Result<{}, {}> {{\n        let {field} = {}::{}(self.data)?;\n        Ok({} {{ {field} }})\n    }}\n",
            transition.from,
            transition.to,
            guard_text,
            transition.message,
            target,
            rust.error,
            rust.handlers,
            transition.message,
            transition.to
        ));
    }
}

fn render_conformance(machine: &StateMachine) -> Result<String> {
    let source = format!("{STATEMACHINES_INPUT}/{}.toml", machine.machine);
    let header = rust_header(&source, "chio-conformance");
    let mut out = String::new();
    out.push_str("#![allow(dead_code)]\n\n");
    out.push_str(
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
         pub struct TransitionSpec {\n\
             pub from: &'static str,\n\
             pub message: &'static str,\n\
             pub to: &'static str,\n\
             pub guards: &'static [&'static str],\n\
         }\n\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq)]\n\
         pub struct NonEdge {\n\
             pub state: &'static str,\n\
             pub message: &'static str,\n\
         }\n\n",
    );
    out.push_str(&format!(
        "pub const MACHINE: &str = {:?};\npub const SCOPE: &str = {:?};\n",
        machine.machine, machine.scope
    ));
    append_string_slice(&mut out, "DOC_REFS", &machine.doc_refs);
    append_string_slice(&mut out, "STATES", &machine.states);
    append_string_slice(&mut out, "TERMINAL_STATES", &machine.terminal);
    let messages = messages(machine);
    append_string_slice(&mut out, "MESSAGES", &messages);
    out.push_str("pub const TRANSITIONS: &[TransitionSpec] = &[\n");
    for transition in &machine.transitions {
        out.push_str(&format!(
            "    TransitionSpec {{ from: {:?}, message: {:?}, to: {:?}, guards: &[{}] }},\n",
            transition.from,
            transition.message,
            transition.to,
            transition
                .guards
                .iter()
                .map(|guard| format!("{guard:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out.push_str("];\n\npub const NON_EDGES: &[NonEdge] = &[\n");
    for (state, message) in non_edges(machine) {
        out.push_str(&format!(
            "    NonEdge {{ state: {state:?}, message: {message:?} }},\n"
        ));
    }
    out.push_str("];\n");
    format_rust_output(&header, &out)
}

fn format_rust_output(header: &str, body: &str) -> Result<String> {
    let file = syn::parse_file(body).map_err(CodegenError::SynParse)?;
    let pretty = prettyplease::unparse(&file);
    let mut child = Command::new("rustfmt")
        .args(["--emit", "stdout", "--edition", "2021"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| CodegenError::Io(PathBuf::from("rustfmt"), error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| CodegenError::Formatter("rustfmt stdin was not available".to_string()))?;
    stdin
        .write_all(pretty.as_bytes())
        .map_err(|error| CodegenError::Io(PathBuf::from("rustfmt stdin"), error))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| CodegenError::Io(PathBuf::from("rustfmt"), error))?;
    if !output.status.success() {
        return Err(CodegenError::Formatter(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    let formatted = String::from_utf8(output.stdout)
        .map_err(|error| CodegenError::Formatter(error.to_string()))?;
    Ok(format!("{header}{formatted}"))
}

fn render_docs(machines: &[StateMachine]) -> String {
    let mut out = String::from(
        "<!-- DO NOT EDIT - regenerate via 'cargo xtask codegen rust'. -->\n\
         <!-- Source: spec/statemachines/*.toml -->\n\n\
         # State Machine Reference\n\n\
         These tables are derived reference material. Their cited protocol documents remain authoritative. Each scope statement limits what its transition relation describes.\n",
    );
    for machine in machines
        .iter()
        .filter(|machine| machine.emit.contains(&Emission::Docs))
    {
        out.push_str(&format!(
            "\n## {}\n\n**Machine:** `{}`\n\n**Scope:** {}\n\n**Sources:** {}\n\n",
            machine.title,
            machine.machine,
            machine.scope,
            machine
                .doc_refs
                .iter()
                .map(|reference| format!("`{reference}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push_str("### States\n\n| State | Initial | Terminal |\n|---|---:|---:|\n");
        for state in &machine.states {
            out.push_str(&format!(
                "| `{state}` | {} | {} |\n",
                yes_no(state == &machine.initial),
                yes_no(machine.terminal.contains(state))
            ));
        }
        out.push_str(
            "\n### Transitions\n\n| From | Message | To | Runtime guards |\n|---|---|---|---|\n",
        );
        for transition in &machine.transitions {
            let guards = if transition.guards.is_empty() {
                "None".to_string()
            } else {
                transition
                    .guards
                    .iter()
                    .map(|guard| format!("`{guard}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                transition.from, transition.message, transition.to, guards
            ));
        }
        out.push_str(&format!(
            "\nThe generated conformance relation records {} non-edges across {} states and {} messages.\n",
            non_edges(machine).len(),
            machine.states.len(),
            messages(machine).len()
        ));
    }
    out
}

fn append_string_slice(out: &mut String, name: &str, values: &[String]) {
    out.push_str(&format!(
        "pub const {name}: &[&str] = &[{}];\n",
        values
            .iter()
            .map(|value| format!("{value:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
}

fn messages(machine: &StateMachine) -> Vec<String> {
    machine
        .transitions
        .iter()
        .map(|transition| transition.message.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn non_edges(machine: &StateMachine) -> Vec<(String, String)> {
    let messages = messages(machine);
    let edges: BTreeSet<(&str, &str)> = machine
        .transitions
        .iter()
        .map(|transition| (transition.from.as_str(), transition.message.as_str()))
        .collect();
    let mut missing = Vec::new();
    for state in &machine.states {
        for message in &messages {
            let pair = (state.as_str(), message.as_str());
            if !edges.contains(&pair) {
                missing.push((state.clone(), message.clone()));
            }
        }
    }
    missing
}

/// Static prefix of every state-machine-pass header. Kept as a standalone
/// const so `scripts/check-rust-file-hygiene.py` can extract and verify it
/// against generated files; the per-file source and owner lines follow it.
const STATE_MACHINE_GENERATED_HEADER_PREFIX: &str = "\
// DO NOT EDIT - regenerate via 'cargo xtask codegen rust'.
//
// Source: ";

fn rust_header(source: &str, owner: &str) -> String {
    format!(
        "{STATE_MACHINE_GENERATED_HEADER_PREFIX}{source}\n// Tool:   chio-spec-codegen state machine pass\n// Owner:  {owner}\n//\n// Manual edits will be overwritten.\n\n"
    )
}

fn rust_output_path(machine: &StateMachine) -> Result<PathBuf> {
    validate_relative_path(&machine.owner).map_err(|message| {
        CodegenError::StateMachine(PathBuf::from(&machine.machine), format!("owner: {message}"))
    })?;
    Ok(Path::new(&machine.owner)
        .join("src/_generated")
        .join(format!("{}_typestate.rs", machine.machine)))
}

fn find_managed_outputs(repo_root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut outputs = BTreeSet::new();
    for relative_root in GENERATED_ROOTS {
        let root = repo_root.join(relative_root);
        if root.exists() {
            let metadata =
                fs::symlink_metadata(&root).map_err(|err| CodegenError::Io(root.clone(), err))?;
            if metadata.file_type().is_symlink() {
                return Err(CodegenError::StateMachine(
                    root,
                    "generated output root must not be a symlink".to_string(),
                ));
            }
            walk_managed_outputs(repo_root, &root, &mut outputs)?;
        }
    }
    Ok(outputs)
}

fn walk_managed_outputs(
    repo_root: &Path,
    dir: &Path,
    outputs: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|err| CodegenError::Io(dir.to_path_buf(), err))? {
        let entry = entry.map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| CodegenError::Io(path.clone(), err))?;
        if file_type.is_symlink() {
            return Err(CodegenError::StateMachine(
                path,
                "symlinks are not accepted in generated output directories".to_string(),
            ));
        }
        if file_type.is_dir() {
            walk_managed_outputs(repo_root, &path, outputs)?;
        } else if file_type.is_file() {
            let bytes = fs::read(&path).map_err(|err| CodegenError::Io(path.clone(), err))?;
            let has_generated_marker = bytes
                .windows(GENERATED_MARKER.len())
                .any(|window| window == GENERATED_MARKER.as_bytes());
            let has_source_marker = bytes
                .windows(GENERATED_SOURCE_MARKER.len())
                .any(|window| window == GENERATED_SOURCE_MARKER.as_bytes());
            if has_generated_marker && has_source_marker {
                let relative = path.strip_prefix(repo_root).map_err(|_| {
                    CodegenError::StateMachine(
                        path.clone(),
                        "generated output is outside the repository".to_string(),
                    )
                })?;
                outputs.insert(relative.to_path_buf());
            }
        }
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> core::result::Result<(), String> {
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() {
        return Err("must be a non-empty relative path".to_string());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("must not escape the repository".to_string());
    }
    Ok(())
}

fn contains_line_break(value: &str) -> bool {
    value.contains(['\r', '\n'])
}

fn is_snake_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        && !value.ends_with('_')
        && !value.contains("__")
}

fn is_state_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| first.is_ascii_uppercase())
        && chars.all(|ch| ch.is_ascii_alphanumeric())
}

fn all_unique<T: Ord + Clone>(items: &[T]) -> bool {
    items.iter().cloned().collect::<BTreeSet<_>>().len() == items.len()
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID: &str = r#"
schema = "chio.statemachine.v1"
machine = "sample"
title = "Sample"
scope = "A bounded local lifecycle."
owner = "crates/trust/chio-federation"
doc_refs = ["spec/PROTOCOL.md#sample"]
emit = ["conformance", "docs"]
states = ["First", "Last"]
initial = "First"
terminal = ["Last"]

[[transitions]]
from = "First"
to = "Last"
message = "finish"
guards = ["input_valid"]
"#;

    fn temp_dir(label: &str) -> Result<PathBuf> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| CodegenError::Io(PathBuf::from(label), std::io::Error::other(err)))?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("chio-statemachine-{label}-{nonce}")))
    }

    fn load_text(text: &str) -> Result<Vec<StateMachine>> {
        let dir = temp_dir("load")?;
        fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
        let path = dir.join("sample.toml");
        fs::write(&path, text).map_err(|err| CodegenError::Io(path, err))?;
        let result = load_statemachines(&dir);
        let _ = fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn valid_table_loads() -> Result<()> {
        let machines = load_text(VALID)?;
        assert_eq!(machines.len(), 1);
        assert_eq!(machines[0].machine, "sample");
        Ok(())
    }

    #[test]
    fn unknown_state_is_rejected() {
        let invalid = VALID.replace("to = \"Last\"", "to = \"Missing\"");
        assert!(matches!(
            load_text(&invalid),
            Err(CodegenError::StateMachine(_, message))
                if message.contains("unknown state")
        ));
    }

    #[test]
    fn unreachable_state_is_rejected() {
        let invalid = VALID.replace(
            "states = [\"First\", \"Last\"]",
            "states = [\"First\", \"Other\", \"Last\"]",
        );
        assert!(matches!(
            load_text(&invalid),
            Err(CodegenError::StateMachine(_, message))
                if message.contains("Other")
        ));
    }

    #[test]
    fn dead_non_terminal_state_is_rejected() {
        let invalid = VALID.replace("terminal = [\"Last\"]", "terminal = []");
        assert!(matches!(
            load_text(&invalid),
            Err(CodegenError::StateMachine(_, message))
                if message.contains("Last") && message.contains("no outgoing")
        ));
    }

    #[test]
    fn duplicate_edge_is_rejected() {
        let edge = "\n[[transitions]]\nfrom = \"First\"\nto = \"Last\"\nmessage = \"finish\"\n";
        let invalid = format!("{VALID}{edge}");
        assert!(matches!(
            load_text(&invalid),
            Err(CodegenError::StateMachine(_, message))
                if message.contains("duplicate transition")
        ));
    }

    #[test]
    fn duplicate_guard_is_rejected() {
        let invalid = VALID.replace(
            "guards = [\"input_valid\"]",
            "guards = [\"input_valid\", \"input_valid\"]",
        );
        assert!(matches!(
            load_text(&invalid),
            Err(CodegenError::StateMachine(_, message))
                if message.contains("guards")
        ));
    }

    #[test]
    fn stale_and_unexpected_outputs_are_rejected() -> Result<()> {
        let repo = temp_dir("drift")?;
        let input = repo.join(STATEMACHINES_INPUT);
        fs::create_dir_all(&input).map_err(|err| CodegenError::Io(input.clone(), err))?;
        let table = input.join("sample.toml");
        fs::write(&table, VALID).map_err(|err| CodegenError::Io(table, err))?;
        codegen_statemachines(&input, &repo)?;
        check_statemachine_outputs(&input, &repo)?;

        let docs = repo.join(STATE_MACHINES_DOC_OUTPUT);
        fs::write(&docs, "stale").map_err(|err| CodegenError::Io(docs.clone(), err))?;
        assert!(matches!(
            check_statemachine_outputs(&input, &repo),
            Err(CodegenError::GeneratedDrift(message)) if message.contains("is stale")
        ));
        codegen_statemachines(&input, &repo)?;

        let extra = repo.join(CONFORMANCE_ORDERING_DIR).join("old_ordering.rs");
        fs::write(
            &extra,
            rust_header("spec/statemachines/removed.toml", "test"),
        )
        .map_err(|err| CodegenError::Io(extra, err))?;
        assert!(matches!(
            check_statemachine_outputs(&input, &repo),
            Err(CodegenError::GeneratedDrift(message)) if message.contains("no longer generated")
        ));
        let _ = fs::remove_dir_all(repo);
        Ok(())
    }
}
