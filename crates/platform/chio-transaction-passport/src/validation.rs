use std::fmt;
use std::path::{Component, Path};

pub(super) fn validate_sha256_hex(value: &str) -> Result<(), ()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(())
    }
}

pub(super) fn validate_bundle_relative_path(value: &str) -> Result<(), ()> {
    if value.is_empty() {
        return Err(());
    }
    if value.contains('\\') || has_windows_drive_prefix(value) {
        return Err(());
    }

    let path = Path::new(value);
    if path.is_absolute() {
        return Err(());
    }

    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => {
                saw_component = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(());
            }
        }
    }

    if saw_component {
        Ok(())
    } else {
        Err(())
    }
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub(super) fn require_non_empty<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<(), EmptyField<'a>> {
    if value.is_empty() {
        Err(EmptyField { field, value })
    } else {
        Ok(())
    }
}

pub(super) struct EmptyField<'a> {
    field: &'static str,
    value: &'a str,
}

impl fmt::Display for EmptyField<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} must not be empty: {}",
            self.field, self.value
        )
    }
}
