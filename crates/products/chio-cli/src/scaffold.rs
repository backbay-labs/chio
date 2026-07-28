use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::CliError;

const CARGO_TEMPLATE: &str = include_str!("../templates/init/Cargo.toml.tmpl");
const README_TEMPLATE: &str = include_str!("../templates/init/README.md.tmpl");
const POLICY_TEMPLATE: &str = include_str!("../templates/init/policy.yaml.tmpl");
const GITIGNORE_TEMPLATE: &str = include_str!("../templates/init/gitignore.tmpl");
const HELLO_SERVER_TEMPLATE: &str = include_str!("../templates/init/src/bin/hello_server.rs.tmpl");
const DEMO_TEMPLATE: &str = include_str!("../templates/init/src/bin/demo.rs.tmpl");

pub(crate) fn cmd_init(path: &Path) -> Result<(), CliError> {
    let path = normalize_target_path(path)?;
    ensure_target_dir(&path)?;

    let project_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "could not derive a project name from `{}`",
                path.display()
            ))
        })?;
    let package_name = sanitize_package_name(project_name);

    let mut replacements = BTreeMap::new();
    replacements.insert("PROJECT_NAME", project_name.to_string());
    replacements.insert("PACKAGE_NAME", package_name.clone());

    write_template(path.join("Cargo.toml"), CARGO_TEMPLATE, &replacements)?;
    write_template(path.join("README.md"), README_TEMPLATE, &replacements)?;
    write_template(path.join("policy.yaml"), POLICY_TEMPLATE, &replacements)?;
    write_template(path.join(".gitignore"), GITIGNORE_TEMPLATE, &replacements)?;
    write_template(
        path.join("src/bin/hello_server.rs"),
        HELLO_SERVER_TEMPLATE,
        &replacements,
    )?;
    write_template(path.join("src/bin/demo.rs"), DEMO_TEMPLATE, &replacements)?;

    let absolute = fs::canonicalize(&path).unwrap_or_else(|_| path.to_path_buf());
    let chio_bin_hint = std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "/path/to/chio".to_string());

    println!("created Chio scaffold at {}", absolute.display());
    println!();
    println!("Next steps:");
    println!("  cd {}", absolute.display());
    println!("  cargo build");
    println!("  CHIO_BIN={} cargo run --quiet --bin demo", chio_bin_hint);

    Ok(())
}

fn normalize_target_path(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_absolute() {
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(CliError::cli_other_error(
                "scaffold target path must not contain parent components after a path segment",
            ));
        }
        return Ok(path.components().collect());
    }

    let mut leading_parents = 0_usize;
    let mut relative_tail = PathBuf::new();
    let mut reached_target = false;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if reached_target {
                    return Err(CliError::cli_other_error(
                        "scaffold target path must not contain parent components after a path segment",
                    ));
                }
                leading_parents += 1;
            }
            Component::Normal(name) => {
                reached_target = true;
                relative_tail.push(name);
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(CliError::cli_other_error(
                    "relative scaffold target path must not contain a platform prefix or root",
                ));
            }
        }
    }

    if leading_parents == 0 {
        return Ok(path.components().collect());
    }

    let mut normalized = std::env::current_dir()?;
    for _ in 0..leading_parents {
        normalized.pop();
    }
    normalized.push(relative_tail);
    Ok(normalized)
}

fn ensure_target_dir(path: &Path) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(CliError::cli_other_error(format!(
                    "refusing to scaffold into symbolic link `{}`",
                    path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(CliError::cli_other_error(format!(
                    "refusing to scaffold into non-directory `{}`",
                    path.display()
                )));
            }
            chio_control_plane::ensure_private_directory(path)?;
            if path.read_dir()?.next().is_some() {
                return Err(CliError::cli_other_error(format!(
                    "refusing to scaffold into non-empty directory `{}`",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            chio_control_plane::ensure_private_directory(path)?;
        }
        Err(error) => {
            return Err(error.into());
        }
    }

    Ok(())
}

fn sanitize_package_name(input: &str) -> String {
    let mut package = input
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();

    while package.contains("--") {
        package = package.replace("--", "-");
    }
    package = package.trim_matches('-').to_string();

    if package.is_empty() {
        "chio-app".to_string()
    } else {
        package
    }
}

fn write_template(
    path: PathBuf,
    template: &str,
    replacements: &BTreeMap<&str, String>,
) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, render_template(template, replacements))?;
    Ok(())
}

fn render_template(template: &str, replacements: &BTreeMap<&str, String>) -> String {
    let mut rendered = template.to_string();
    for (key, value) in replacements {
        rendered = rendered.replace(&format!("{{{{{key}}}}}"), value);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{normalize_target_path, sanitize_package_name};
    use crate::CliError;

    #[test]
    fn normalize_target_path_preserves_ordinary_relative_path() -> Result<(), CliError> {
        let path = Path::new("nested/project");

        assert_eq!(normalize_target_path(path)?, path);
        Ok(())
    }

    #[test]
    fn sanitize_package_name_normalizes_cli_input() {
        assert_eq!(sanitize_package_name("My Project"), "my-project");
        assert_eq!(sanitize_package_name("chio_demo"), "chio-demo");
        assert_eq!(sanitize_package_name("___"), "chio-app");
    }
}
