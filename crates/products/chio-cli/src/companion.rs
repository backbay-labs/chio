//! Dispatch only to the paired operator beside this installed CLI.
//! PATH and working-directory executables cannot shadow the companion.
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::Command,
};

fn companion(executable: &Path) -> io::Result<PathBuf> {
    let parent = executable
        .parent()
        .ok_or_else(|| io::Error::other("Cannot locate the installed Chio directory"))?;
    let name = if cfg!(windows) {
        "megastart.exe"
    } else {
        "megastart"
    };
    let path = parent.join(name);
    let metadata = std::fs::metadata(&path).map_err(|_| io::Error::new(io::ErrorKind::NotFound,
        "This Chio installation has no paired workshop operator. Install a compatible Chio workshop release from https://chio.computer/docs/installation."))?;
    if !metadata.is_file() || path.canonicalize()? == executable.canonicalize()? {
        return Err(io::Error::other(
            "The paired workshop operator is invalid; reinstall the matching release",
        ));
    }
    Ok(path)
}

pub(crate) fn megastart(arguments: &[OsString]) -> io::Result<()> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let mut command = Command::new(companion(&executable)?);
    command.args(arguments);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Preserve terminal signals and the operator's exit status without
        // leaving a launcher process behind the foreground local host.
        Err(command.exec())
    }
    #[cfg(not(unix))]
    {
        let status = command.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn workshop_arguments_are_forwarded_without_parsing_the_setup() {
        let parsed = crate::cli_entrypoint_support::parse_cli([
            "chio",
            "megastart",
            "workshop",
            "--setup",
            "sf1.native.hermes.codex.pi",
            "--no-open",
        ])
        .unwrap();
        match parsed.command {
            crate::Commands::Megastart { arguments } => assert_eq!(
                arguments,
                [
                    "workshop",
                    "--setup",
                    "sf1.native.hermes.codex.pi",
                    "--no-open"
                ]
                .map(OsString::from)
            ),
            _ => panic!("Expected the workshop companion"),
        }
        let help =
            crate::cli_entrypoint_support::parse_cli(["chio", "megastart", "--help"]).unwrap();
        assert!(
            matches!(help.command, crate::Commands::Megastart { arguments } if arguments == [OsString::from("--help")])
        );
    }
    #[test]
    fn a_missing_sibling_never_searches_path() {
        let root =
            std::env::temp_dir().join(format!("chio-companion-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let executable = root.join("chio");
        std::fs::write(&executable, b"cli").unwrap();
        assert_eq!(
            companion(&executable).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        std::fs::write(
            root.join(if cfg!(windows) {
                "megastart.exe"
            } else {
                "megastart"
            }),
            b"operator",
        )
        .unwrap();
        assert_eq!(
            companion(&executable).unwrap().parent(),
            Some(root.as_path())
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
