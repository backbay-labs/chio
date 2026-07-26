use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::{rustfmt_generated, write_if_changed, CodegenError, Result};

pub const ERROR_REGISTRY_INPUT: &str = "spec/errors/registry.yaml";
pub const ERRORS_GENERATED_DIR: &str = "crates/core/chio-errors/src/_generated";
pub const ERROR_CODES_OUTPUT: &str = "error_codes.rs";

const ERRORS_MOD_FILE: &str = "mod.rs";
const REGISTRY_SCHEMA: &str = "chio.error-urn-registry.v1";
const ERROR_CODES_GENERATED_HEADER: &str = "\
// DO NOT EDIT - regenerate via 'cargo run -p chio-spec-codegen -- --errors-only'.
//
// Source: spec/errors/registry.yaml
// Tool:   chio-spec-codegen
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration.
";

#[derive(Debug)]
struct ErrorRegistry {
    schema: String,
    version: String,
    updated_at: String,
    domains: Vec<RegistryDomain>,
    codes: Vec<RegistryCode>,
}

#[derive(Debug)]
struct RegistryDomain {
    id: String,
    class: String,
    description: String,
    reserved_for: Option<String>,
}

#[derive(Debug)]
struct RegistryCode {
    urn: String,
    domain: String,
    severity: String,
    summary: String,
    help: String,
    string_code: String,
    jsonrpc_code: Option<i32>,
    since: String,
    stability: String,
    consumed_by: Vec<String>,
}

#[derive(Debug, Default)]
struct DomainBuilder {
    line: usize,
    id: Option<String>,
    class: Option<String>,
    description: Option<String>,
    reserved_for: Option<String>,
}

#[derive(Debug, Default)]
struct CodeBuilder {
    line: usize,
    urn: Option<String>,
    domain: Option<String>,
    severity: Option<String>,
    summary: Option<String>,
    help: Option<String>,
    string_code: Option<String>,
    jsonrpc_code: Option<i32>,
    since: Option<String>,
    stability: Option<String>,
    consumed_by: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Top,
    Domains,
    Codes,
}

pub fn codegen_error_codes(registry_path: &Path, out_dir: &Path) -> Result<()> {
    let error_codes = render_error_codes(registry_path)?;
    fs::create_dir_all(out_dir).map_err(|err| CodegenError::Io(out_dir.to_path_buf(), err))?;

    let error_codes_path = out_dir.join(ERROR_CODES_OUTPUT);
    write_if_changed(&error_codes_path, error_codes.as_bytes())?;

    let mod_path = out_dir.join(ERRORS_MOD_FILE);
    let mod_body = render_errors_mod();
    write_if_changed(&mod_path, mod_body.as_bytes())?;

    Ok(())
}

pub fn render_error_codes(registry_path: &Path) -> Result<String> {
    let registry = load_error_registry(registry_path)?;
    render_error_registry(registry_path, &registry)
}

fn load_error_registry(path: &Path) -> Result<ErrorRegistry> {
    let raw = fs::read_to_string(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    parse_error_registry(path, &raw)
}

fn parse_error_registry(path: &Path, raw: &str) -> Result<ErrorRegistry> {
    let mut schema: Option<String> = None;
    let mut version: Option<String> = None;
    let mut updated_at: Option<String> = None;
    let mut domains: Vec<RegistryDomain> = Vec::new();
    let mut codes: Vec<RegistryCode> = Vec::new();
    let mut current_domain: Option<DomainBuilder> = None;
    let mut current_code: Option<CodeBuilder> = None;
    let mut section = Section::Top;
    let mut reading_consumed_by = false;

    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = leading_spaces(line);
        if indent == 0 {
            finish_pending_domain(path, &mut current_domain, &mut domains)?;
            finish_pending_code(path, &mut current_code, &mut codes)?;
            reading_consumed_by = false;

            match trimmed {
                "domains:" => {
                    section = Section::Domains;
                }
                "codes:" => {
                    section = Section::Codes;
                }
                _ => {
                    section = Section::Top;
                    let (key, value) = parse_key_value(path, line_number, trimmed)?;
                    let parsed = parse_scalar(path, line_number, value)?;
                    match key {
                        "schema" => {
                            set_string_field(path, line_number, "schema", &mut schema, parsed)?
                        }
                        "version" => {
                            set_string_field(path, line_number, "version", &mut version, parsed)?;
                        }
                        "updated_at" => set_string_field(
                            path,
                            line_number,
                            "updated_at",
                            &mut updated_at,
                            parsed,
                        )?,
                        other => {
                            return Err(registry_error(
                                path,
                                line_number,
                                format!("unknown top-level key `{other}`"),
                            ));
                        }
                    }
                }
            }
            continue;
        }

        match section {
            Section::Top => {
                return Err(registry_error(
                    path,
                    line_number,
                    "indented content appeared before a sequence section",
                ));
            }
            Section::Domains => {
                parse_domain_line(
                    path,
                    line_number,
                    indent,
                    trimmed,
                    &mut current_domain,
                    &mut domains,
                )?;
            }
            Section::Codes => {
                parse_code_line(
                    path,
                    line_number,
                    indent,
                    trimmed,
                    &mut current_code,
                    &mut codes,
                    &mut reading_consumed_by,
                )?;
            }
        }
    }

    finish_pending_domain(path, &mut current_domain, &mut domains)?;
    finish_pending_code(path, &mut current_code, &mut codes)?;

    let registry = ErrorRegistry {
        schema: required_string(path, 1, "schema", schema)?,
        version: required_string(path, 1, "version", version)?,
        updated_at: required_string(path, 1, "updated_at", updated_at)?,
        domains,
        codes,
    };
    validate_registry(path, &registry)?;
    Ok(registry)
}

fn parse_domain_line(
    path: &Path,
    line_number: usize,
    indent: usize,
    trimmed: &str,
    current_domain: &mut Option<DomainBuilder>,
    domains: &mut Vec<RegistryDomain>,
) -> Result<()> {
    if indent == 2 && trimmed.starts_with("- ") {
        finish_pending_domain(path, current_domain, domains)?;
        let mut builder = DomainBuilder {
            line: line_number,
            ..DomainBuilder::default()
        };
        let inline = trimmed.trim_start_matches("- ").trim();
        if !inline.is_empty() {
            set_domain_field(path, line_number, inline, &mut builder)?;
        }
        *current_domain = Some(builder);
        return Ok(());
    }

    if indent != 4 {
        return Err(registry_error(
            path,
            line_number,
            "domain entries must use two-space YAML indentation",
        ));
    }

    let Some(builder) = current_domain.as_mut() else {
        return Err(registry_error(
            path,
            line_number,
            "domain field appeared before a domain item",
        ));
    };
    set_domain_field(path, line_number, trimmed, builder)
}

fn parse_code_line(
    path: &Path,
    line_number: usize,
    indent: usize,
    trimmed: &str,
    current_code: &mut Option<CodeBuilder>,
    codes: &mut Vec<RegistryCode>,
    reading_consumed_by: &mut bool,
) -> Result<()> {
    if indent == 2 && trimmed.starts_with("- ") {
        finish_pending_code(path, current_code, codes)?;
        *reading_consumed_by = false;
        let mut builder = CodeBuilder {
            line: line_number,
            ..CodeBuilder::default()
        };
        let inline = trimmed.trim_start_matches("- ").trim();
        if !inline.is_empty() {
            set_code_field(path, line_number, inline, &mut builder, reading_consumed_by)?;
        }
        *current_code = Some(builder);
        return Ok(());
    }

    if indent == 6 && trimmed.starts_with("- ") {
        if !*reading_consumed_by {
            return Err(registry_error(
                path,
                line_number,
                "sequence item is only supported under consumed_by",
            ));
        }
        let Some(builder) = current_code.as_mut() else {
            return Err(registry_error(
                path,
                line_number,
                "consumed_by value appeared before a code item",
            ));
        };
        let value = parse_scalar(path, line_number, trimmed.trim_start_matches("- ").trim())?;
        builder.consumed_by.push(value);
        return Ok(());
    }

    if indent != 4 {
        return Err(registry_error(
            path,
            line_number,
            "code entries must use two-space YAML indentation",
        ));
    }

    let Some(builder) = current_code.as_mut() else {
        return Err(registry_error(
            path,
            line_number,
            "code field appeared before a code item",
        ));
    };
    set_code_field(path, line_number, trimmed, builder, reading_consumed_by)
}

fn set_domain_field(
    path: &Path,
    line_number: usize,
    line: &str,
    builder: &mut DomainBuilder,
) -> Result<()> {
    let (key, value) = parse_key_value(path, line_number, line)?;
    let parsed = parse_scalar(path, line_number, value)?;
    match key {
        "id" => set_string_field(path, line_number, "id", &mut builder.id, parsed),
        "class" => set_string_field(path, line_number, "class", &mut builder.class, parsed),
        "description" => set_string_field(
            path,
            line_number,
            "description",
            &mut builder.description,
            parsed,
        ),
        "reserved_for" => set_string_field(
            path,
            line_number,
            "reserved_for",
            &mut builder.reserved_for,
            parsed,
        ),
        other => Err(registry_error(
            path,
            line_number,
            format!("unknown domain key `{other}`"),
        )),
    }
}

fn set_code_field(
    path: &Path,
    line_number: usize,
    line: &str,
    builder: &mut CodeBuilder,
    reading_consumed_by: &mut bool,
) -> Result<()> {
    let (key, value) = parse_key_value(path, line_number, line)?;
    match key {
        "consumed_by" => {
            if !value.trim().is_empty() {
                return Err(registry_error(
                    path,
                    line_number,
                    "consumed_by must be a YAML sequence",
                ));
            }
            *reading_consumed_by = true;
            Ok(())
        }
        "jsonrpc_code" => {
            *reading_consumed_by = false;
            if builder.jsonrpc_code.is_some() {
                return Err(registry_error(
                    path,
                    line_number,
                    "duplicate code key `jsonrpc_code`",
                ));
            }
            let code = value.parse::<i32>().map_err(|err| {
                registry_error(
                    path,
                    line_number,
                    format!("jsonrpc_code must be an integer: {err}"),
                )
            })?;
            builder.jsonrpc_code = Some(code);
            Ok(())
        }
        "urn" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "urn",
                &mut builder.urn,
                parse_scalar(path, line_number, value)?,
            )
        }
        "domain" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "domain",
                &mut builder.domain,
                parse_scalar(path, line_number, value)?,
            )
        }
        "severity" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "severity",
                &mut builder.severity,
                parse_scalar(path, line_number, value)?,
            )
        }
        "summary" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "summary",
                &mut builder.summary,
                parse_scalar(path, line_number, value)?,
            )
        }
        "help" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "help",
                &mut builder.help,
                parse_scalar(path, line_number, value)?,
            )
        }
        "string_code" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "string_code",
                &mut builder.string_code,
                parse_scalar(path, line_number, value)?,
            )
        }
        "since" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "since",
                &mut builder.since,
                parse_scalar(path, line_number, value)?,
            )
        }
        "stability" => {
            *reading_consumed_by = false;
            set_string_field(
                path,
                line_number,
                "stability",
                &mut builder.stability,
                parse_scalar(path, line_number, value)?,
            )
        }
        other => Err(registry_error(
            path,
            line_number,
            format!("unknown code key `{other}`"),
        )),
    }
}

fn finish_pending_domain(
    path: &Path,
    current_domain: &mut Option<DomainBuilder>,
    domains: &mut Vec<RegistryDomain>,
) -> Result<()> {
    let Some(builder) = current_domain.take() else {
        return Ok(());
    };
    domains.push(finish_domain(path, builder)?);
    Ok(())
}

fn finish_pending_code(
    path: &Path,
    current_code: &mut Option<CodeBuilder>,
    codes: &mut Vec<RegistryCode>,
) -> Result<()> {
    let Some(builder) = current_code.take() else {
        return Ok(());
    };
    codes.push(finish_code(path, builder)?);
    Ok(())
}

fn finish_domain(path: &Path, builder: DomainBuilder) -> Result<RegistryDomain> {
    let line = builder.line;
    Ok(RegistryDomain {
        id: required_string(path, line, "id", builder.id)?,
        class: required_string(path, line, "class", builder.class)?,
        description: required_string(path, line, "description", builder.description)?,
        reserved_for: builder.reserved_for,
    })
}

fn finish_code(path: &Path, builder: CodeBuilder) -> Result<RegistryCode> {
    let line = builder.line;
    Ok(RegistryCode {
        urn: required_string(path, line, "urn", builder.urn)?,
        domain: required_string(path, line, "domain", builder.domain)?,
        severity: required_string(path, line, "severity", builder.severity)?,
        summary: required_string(path, line, "summary", builder.summary)?,
        help: required_string(path, line, "help", builder.help)?,
        string_code: required_string(path, line, "string_code", builder.string_code)?,
        jsonrpc_code: builder.jsonrpc_code,
        since: required_string(path, line, "since", builder.since)?,
        stability: required_string(path, line, "stability", builder.stability)?,
        consumed_by: builder.consumed_by,
    })
}

fn validate_registry(path: &Path, registry: &ErrorRegistry) -> Result<()> {
    if registry.schema != REGISTRY_SCHEMA {
        return Err(registry_error(
            path,
            1,
            format!("schema must be `{REGISTRY_SCHEMA}`"),
        ));
    }
    if registry.version.trim().is_empty() {
        return Err(registry_error(path, 1, "version must not be empty"));
    }
    if registry.updated_at.trim().is_empty() {
        return Err(registry_error(path, 1, "updated_at must not be empty"));
    }
    if registry.domains.is_empty() {
        return Err(registry_error(path, 1, "domains must not be empty"));
    }
    if registry.codes.is_empty() {
        return Err(registry_error(path, 1, "codes must not be empty"));
    }

    let mut domain_ids: BTreeSet<String> = BTreeSet::new();
    for domain in &registry.domains {
        if !domain_ids.insert(domain.id.clone()) {
            return Err(registry_error(
                path,
                1,
                format!("duplicate domain `{}`", domain.id),
            ));
        }
        if domain_variant(&domain.id).is_none() {
            return Err(registry_error(
                path,
                1,
                format!("unknown domain `{}`", domain.id),
            ));
        }
        match domain.class.as_str() {
            "core" => {}
            "reserved" => {
                let reserved_for = domain.reserved_for.as_deref().unwrap_or_default();
                if reserved_for.trim().is_empty() {
                    return Err(registry_error(
                        path,
                        1,
                        format!("reserved domain `{}` must declare reserved_for", domain.id),
                    ));
                }
            }
            other => {
                return Err(registry_error(
                    path,
                    1,
                    format!("unknown domain class `{other}`"),
                ));
            }
        }
        if domain.description.trim().is_empty() {
            return Err(registry_error(
                path,
                1,
                format!("domain `{}` description must not be empty", domain.id),
            ));
        }
    }

    let mut urns: BTreeSet<String> = BTreeSet::new();
    let mut constant_names: BTreeSet<String> = BTreeSet::new();
    for code in &registry.codes {
        if !urns.insert(code.urn.clone()) {
            return Err(registry_error(
                path,
                1,
                format!("duplicate error URN `{}`", code.urn),
            ));
        }
        let constant_name = constant_name_for_code(path, code)?;
        if !constant_names.insert(constant_name.clone()) {
            return Err(registry_error(
                path,
                1,
                format!("duplicate generated constant `{constant_name}`"),
            ));
        }
        if !domain_ids.contains(&code.domain) {
            return Err(registry_error(
                path,
                1,
                format!(
                    "code `{}` uses undeclared domain `{}`",
                    code.urn, code.domain
                ),
            ));
        }
        if severity_variant(&code.severity).is_none() {
            return Err(registry_error(
                path,
                1,
                format!(
                    "code `{}` uses unknown severity `{}`",
                    code.urn, code.severity
                ),
            ));
        }
        match code.stability.as_str() {
            "stable" | "unstable" | "deprecated" => {}
            other => {
                return Err(registry_error(
                    path,
                    1,
                    format!("code `{}` uses unknown stability `{other}`", code.urn),
                ));
            }
        }
        let expected_prefix = format!("urn:chio:error:{}:", code.domain);
        if !code.urn.starts_with(&expected_prefix) {
            return Err(registry_error(
                path,
                1,
                format!("code `{}` does not match its domain", code.urn),
            ));
        }
        if code.summary.trim().is_empty()
            || code.help.trim().is_empty()
            || code.string_code.trim().is_empty()
            || code.since.trim().is_empty()
        {
            return Err(registry_error(
                path,
                1,
                format!("code `{}` has an empty required field", code.urn),
            ));
        }
        if code.consumed_by.is_empty() {
            return Err(registry_error(
                path,
                1,
                format!("code `{}` must declare consumed_by", code.urn),
            ));
        }
        for consumer in &code.consumed_by {
            if consumer.trim().is_empty() {
                return Err(registry_error(
                    path,
                    1,
                    format!("code `{}` has an empty consumed_by value", code.urn),
                ));
            }
        }
    }

    Ok(())
}

fn render_error_registry(path: &Path, registry: &ErrorRegistry) -> Result<String> {
    let mut body = String::new();
    body.push_str("use crate::{Domain, Severity};\n\n");
    body.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    body.push_str("pub struct ErrorCodeSpec {\n");
    body.push_str("    pub urn: &'static str,\n");
    body.push_str("    pub domain: Domain,\n");
    body.push_str("    pub severity: Severity,\n");
    body.push_str("    pub summary: &'static str,\n");
    body.push_str("    pub help: &'static str,\n");
    body.push_str("    pub string_code: &'static str,\n");
    body.push_str("    pub jsonrpc_code: Option<i32>,\n");
    body.push_str("    pub since: &'static str,\n");
    body.push_str("    pub stability: &'static str,\n");
    body.push_str("    pub consumed_by: &'static [&'static str],\n");
    body.push_str("}\n\n");
    push_const_str(&mut body, "REGISTRY_SCHEMA", &registry.schema);
    push_const_str(&mut body, "REGISTRY_VERSION", &registry.version);
    push_const_str(&mut body, "REGISTRY_UPDATED_AT", &registry.updated_at);
    body.push('\n');

    let mut constant_names: Vec<String> = Vec::with_capacity(registry.codes.len());
    for code in &registry.codes {
        let name = constant_name_for_code(path, code)?;
        let Some(domain_variant) = domain_variant(&code.domain) else {
            return Err(registry_error(
                path,
                1,
                format!("unknown domain `{}`", code.domain),
            ));
        };
        let Some(severity_variant) = severity_variant(&code.severity) else {
            return Err(registry_error(
                path,
                1,
                format!("unknown severity `{}`", code.severity),
            ));
        };

        constant_names.push(name.clone());
        body.push_str("pub const ");
        body.push_str(&name);
        body.push_str(": ErrorCodeSpec = ErrorCodeSpec {\n");
        push_struct_str_field(&mut body, "urn", &code.urn);
        body.push_str("    domain: Domain::");
        body.push_str(domain_variant);
        body.push_str(",\n");
        body.push_str("    severity: Severity::");
        body.push_str(severity_variant);
        body.push_str(",\n");
        push_struct_str_field(&mut body, "summary", &code.summary);
        push_struct_str_field(&mut body, "help", &code.help);
        push_struct_str_field(&mut body, "string_code", &code.string_code);
        match code.jsonrpc_code {
            Some(jsonrpc_code) => {
                body.push_str("    jsonrpc_code: Some(");
                body.push_str(&jsonrpc_code.to_string());
                body.push_str("),\n");
            }
            None => {
                body.push_str("    jsonrpc_code: None,\n");
            }
        }
        push_struct_str_field(&mut body, "since", &code.since);
        push_struct_str_field(&mut body, "stability", &code.stability);
        body.push_str("    consumed_by: &[");
        for (index, consumer) in code.consumed_by.iter().enumerate() {
            if index > 0 {
                body.push_str(", ");
            }
            body.push_str(&rust_string_literal(consumer));
        }
        body.push_str("],\n");
        body.push_str("};\n\n");
    }

    body.push_str("pub static ERROR_CODES: &[ErrorCodeSpec] = &[\n");
    for name in &constant_names {
        body.push_str("    ");
        body.push_str(name);
        body.push_str(",\n");
    }
    body.push_str("];\n\n");
    body.push_str("#[must_use]\n");
    body.push_str("pub fn lookup_error_code(urn: &str) -> Option<&'static ErrorCodeSpec> {\n");
    body.push_str("    ERROR_CODES.iter().find(|entry| entry.urn == urn)\n");
    body.push_str("}\n\n");
    body.push_str("#[must_use]\n");
    body.push_str("pub fn lookup_string_code(code: &str) -> Option<&'static ErrorCodeSpec> {\n");
    body.push_str("    let mut matches = lookup_string_code_matches(code);\n");
    body.push_str("    let first = matches.next()?;\n");
    body.push_str("    if matches.next().is_some() {\n");
    body.push_str("        None\n");
    body.push_str("    } else {\n");
    body.push_str("        Some(first)\n");
    body.push_str("    }\n");
    body.push_str("}\n\n");
    body.push_str(
        "pub fn lookup_string_code_matches(\n    code: &str,\n) -> impl Iterator<Item = &'static ErrorCodeSpec> + '_ {\n",
    );
    body.push_str("    ERROR_CODES\n");
    body.push_str("        .iter()\n");
    body.push_str("        .filter(move |entry| entry.string_code == code)\n");
    body.push_str("}\n\n");
    body.push_str("#[must_use]\n");
    body.push_str("pub fn lookup_jsonrpc_code(code: i32) -> Option<&'static ErrorCodeSpec> {\n");
    body.push_str("    ERROR_CODES.iter().find(|entry| entry.jsonrpc_code == Some(code))\n");
    body.push_str("}\n");

    let _ = syn::parse_file(&body).map_err(CodegenError::SynParse)?;
    let mut formatted = String::with_capacity(ERROR_CODES_GENERATED_HEADER.len() + body.len() + 1);
    formatted.push_str(ERROR_CODES_GENERATED_HEADER);
    formatted.push('\n');
    formatted.push_str(&body);
    rustfmt_generated(path, &formatted)
}

fn render_errors_mod() -> String {
    format!("{ERROR_CODES_GENERATED_HEADER}\npub mod error_codes;\n")
}

fn push_const_str(body: &mut String, name: &str, value: &str) {
    body.push_str("pub const ");
    body.push_str(name);
    body.push_str(": &str = ");
    body.push_str(&rust_string_literal(value));
    body.push_str(";\n");
}

fn push_struct_str_field(body: &mut String, field: &str, value: &str) {
    body.push_str("    ");
    body.push_str(field);
    body.push_str(": ");
    body.push_str(&rust_string_literal(value));
    body.push_str(",\n");
}

fn constant_name_for_code(path: &Path, code: &RegistryCode) -> Result<String> {
    let prefix = "urn:chio:error:";
    let Some(rest) = code.urn.strip_prefix(prefix) else {
        return Err(registry_error(
            path,
            1,
            format!("code `{}` must start with `{prefix}`", code.urn),
        ));
    };
    let Some((domain, slug)) = rest.split_once(':') else {
        return Err(registry_error(
            path,
            1,
            format!("code `{}` must contain domain and slug", code.urn),
        ));
    };
    let mut name = String::with_capacity(domain.len() + slug.len() + 1);
    push_identifier_part(&mut name, domain);
    name.push('_');
    push_identifier_part(&mut name, slug);
    if name.starts_with('_') || name.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        name.insert_str(0, "ERROR");
    }
    Ok(name)
}

fn push_identifier_part(out: &mut String, value: &str) {
    let mut previous_was_separator = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            out.push('_');
            previous_was_separator = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
}

fn domain_variant(value: &str) -> Option<&'static str> {
    match value {
        "capability" => Some("Capability"),
        "policy" => Some("Policy"),
        "guard" => Some("Guard"),
        "attest" => Some("Attest"),
        "replay" => Some("Replay"),
        "provider" => Some("Provider"),
        "manifest" => Some("Manifest"),
        "kernel" => Some("Kernel"),
        "transport" => Some("Transport"),
        "cli" => Some("Cli"),
        "delegation" => Some("Delegation"),
        "adversarial" => Some("Adversarial"),
        "threat" => Some("Threat"),
        "arena" => Some("Arena"),
        "economy" => Some("Economy"),
        "lineage" => Some("Lineage"),
        "custody" => Some("Custody"),
        "weights" => Some("Weights"),
        "mobile" => Some("Mobile"),
        "transaction" => Some("Transaction"),
        _ => None,
    }
}

fn severity_variant(value: &str) -> Option<&'static str> {
    match value {
        "info" => Some("Info"),
        "warning" => Some("Warning"),
        "error" => Some("Error"),
        "fatal" => Some("Fatal"),
        _ => None,
    }
}

fn parse_key_value<'a>(
    path: &Path,
    line_number: usize,
    line: &'a str,
) -> Result<(&'a str, &'a str)> {
    let Some((key, value)) = line.split_once(':') else {
        return Err(registry_error(
            path,
            line_number,
            format!("expected key-value pair, got `{line}`"),
        ));
    };
    let key = key.trim();
    if key.is_empty() {
        return Err(registry_error(path, line_number, "key must not be empty"));
    }
    Ok((key, value.trim()))
}

fn parse_scalar(path: &Path, line_number: usize, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(registry_error(
            path,
            line_number,
            "scalar value must not be empty",
        ));
    }
    if !value.starts_with('"') {
        return Ok(value.to_string());
    }
    if !value.ends_with('"') || value.len() == 1 {
        return Err(registry_error(
            path,
            line_number,
            "quoted scalar is missing its closing quote",
        ));
    }

    let inner = &value[1..value.len() - 1];
    let mut parsed = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            parsed.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            return Err(registry_error(
                path,
                line_number,
                "quoted scalar ends with an escape marker",
            ));
        };
        match escaped {
            '"' => parsed.push('"'),
            '\\' => parsed.push('\\'),
            'n' => parsed.push('\n'),
            'r' => parsed.push('\r'),
            't' => parsed.push('\t'),
            other => {
                return Err(registry_error(
                    path,
                    line_number,
                    format!("unsupported escape sequence `\\{other}`"),
                ));
            }
        }
    }
    Ok(parsed)
}

fn set_string_field(
    path: &Path,
    line_number: usize,
    field: &str,
    target: &mut Option<String>,
    value: String,
) -> Result<()> {
    if target.is_some() {
        return Err(registry_error(
            path,
            line_number,
            format!("duplicate key `{field}`"),
        ));
    }
    *target = Some(value);
    Ok(())
}

fn required_string(
    path: &Path,
    line_number: usize,
    field: &str,
    value: Option<String>,
) -> Result<String> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(registry_error(
            path,
            line_number,
            format!("missing required key `{field}`"),
        )),
    }
}

fn rust_string_literal(value: &str) -> String {
    let mut literal = String::with_capacity(value.len() + 2);
    literal.push('"');
    for ch in value.chars() {
        match ch {
            '"' => literal.push_str("\\\""),
            '\\' => literal.push_str("\\\\"),
            '\n' => literal.push_str("\\n"),
            '\r' => literal.push_str("\\r"),
            '\t' => literal.push_str("\\t"),
            ch if ch.is_control() => {
                literal.push_str("\\u{");
                literal.push_str(&format!("{:x}", u32::from(ch)));
                literal.push('}');
            }
            ch => literal.push(ch),
        }
    }
    literal.push('"');
    literal
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn registry_error(path: &Path, line_number: usize, message: impl Into<String>) -> CodegenError {
    CodegenError::Registry(
        path.to_path_buf(),
        format!("line {line_number}: {}", message.into()),
    )
}
