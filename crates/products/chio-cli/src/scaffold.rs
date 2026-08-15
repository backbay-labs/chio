use std::collections::BTreeMap;
use std::path::{Component, Path};

use crate::CliError;

const CARGO_TEMPLATE: &str = include_str!("../templates/init/Cargo.toml.tmpl");
const README_TEMPLATE: &str = include_str!("../templates/init/README.md.tmpl");
const POLICY_TEMPLATE: &str = include_str!("../templates/init/policy.yaml.tmpl");
const GITIGNORE_TEMPLATE: &str = include_str!("../templates/init/gitignore.tmpl");
const HELLO_SERVER_TEMPLATE: &str = include_str!("../templates/init/src/bin/hello_server.rs.tmpl");
const DEMO_TEMPLATE: &str = include_str!("../templates/init/src/bin/demo.rs.tmpl");

pub(crate) fn cmd_init(path: &Path) -> Result<(), CliError> {
    let directory = ensure_target_dir(path)?;
    let path = directory.path();

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

    write_template(&directory, Path::new("Cargo.toml"), CARGO_TEMPLATE, &replacements)?;
    write_template(&directory, Path::new("README.md"), README_TEMPLATE, &replacements)?;
    write_template(&directory, Path::new("policy.yaml"), POLICY_TEMPLATE, &replacements)?;
    write_template(&directory, Path::new(".gitignore"), GITIGNORE_TEMPLATE, &replacements)?;
    directory.create_dir_all(Path::new("src/bin"))?;
    write_template(
        &directory,
        Path::new("src/bin/hello_server.rs"),
        HELLO_SERVER_TEMPLATE,
        &replacements,
    )?;
    write_template(
        &directory,
        Path::new("src/bin/demo.rs"),
        DEMO_TEMPLATE,
        &replacements,
    )?;

    let chio_bin_hint = std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "/path/to/chio".to_string());

    directory.validate_path_identity()?;
    println!("created Chio scaffold at {}", path.display());
    println!();
    println!("Next steps:");
    println!("  cd {}", path.display());
    println!("  cargo build");
    println!("  CHIO_BIN={} cargo run --quiet --bin demo", chio_bin_hint);

    Ok(())
}

fn ensure_target_dir(path: &Path) -> Result<chio_control_plane::PreparedPrivateDirectory, CliError> {
    let mut reached_named_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => reached_named_component = true,
            Component::ParentDir if reached_named_component => {
                return Err(CliError::cli_other_error(format!(
                    "refusing to scaffold into a path with parent components after a named component `{}`",
                    path.display()
                )));
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {}
        }
    }

    let directory = chio_control_plane::prepare_private_directory(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotADirectory {
            CliError::cli_other_error(format!(
                "refusing to scaffold into symbolic link or non-directory `{}`",
                path.display()
            ))
        } else {
            CliError::Io(error)
        }
    })?;
    if !directory.is_empty()? {
        return Err(CliError::cli_other_error(format!(
            "refusing to scaffold into non-empty directory `{}`",
            directory.path().display()
        )));
    }
    Ok(directory)
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
    directory: &chio_control_plane::PreparedPrivateDirectory,
    path: &Path,
    template: &str,
    replacements: &BTreeMap<&str, String>,
) -> Result<(), CliError> {
    let rendered = render_template(template, replacements);
    directory.write_new(path, rendered.as_bytes())?;
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
    use super::sanitize_package_name;

    #[test]
    fn sanitize_package_name_normalizes_cli_input() {
        assert_eq!(sanitize_package_name("My Project"), "my-project");
        assert_eq!(sanitize_package_name("chio_demo"), "chio-demo");
        assert_eq!(sanitize_package_name("___"), "chio-app");
    }
}
