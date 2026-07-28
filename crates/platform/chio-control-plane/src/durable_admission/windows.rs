use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_DIRECTORY_FILE, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    STATUS_REPARSE_POINT_ENCOUNTERED, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(super) fn prepare_private_directory(path: &Path) -> Result<(), std::io::Error> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(invalid_path(
            "private directory path must not contain parent components",
        ));
    }
    let absolute = std::path::absolute(path)?;
    let (root, names) = split_absolute_path(&absolute)?;

    let mut options = OpenOptions::new();
    options
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let mut directory = options.open(root)?;
    validate_directory_handle(&directory)?;
    let mut pinned_ancestors = Vec::new();
    for component in names {
        let child = open_or_create_child(&directory, &component)?;
        pinned_ancestors.push(directory);
        directory = child;
    }
    Ok(())
}

fn split_absolute_path(path: &Path) -> Result<(PathBuf, Vec<OsString>), std::io::Error> {
    let mut root = PathBuf::new();
    let mut names = Vec::<OsString>::new();
    let mut saw_prefix = false;
    let mut saw_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if !saw_prefix && !saw_root && names.is_empty() => {
                match prefix.kind() {
                    Prefix::Disk(_)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::UNC(_, _)
                    | Prefix::VerbatimUNC(_, _) => {}
                    _ => {
                        return Err(invalid_path(
                            "private directory path uses an unsupported Windows prefix",
                        ));
                    }
                }
                root.push(prefix.as_os_str());
                saw_prefix = true;
            }
            Component::RootDir if saw_prefix && !saw_root && names.is_empty() => {
                root.push(component.as_os_str());
                saw_root = true;
            }
            Component::CurDir => {
                return Err(invalid_path(
                    "private directory path must not contain current-directory components",
                ));
            }
            Component::Normal(name) if saw_root => {
                validate_component(name)?;
                names.push(name.to_os_string());
            }
            Component::ParentDir => {
                return Err(invalid_path(
                    "private directory path must not contain parent components",
                ));
            }
            _ => {
                return Err(invalid_path(
                    "private directory path is not an absolute Windows filesystem path",
                ));
            }
        }
    }
    if !saw_prefix || !saw_root || names.is_empty() {
        return Err(invalid_path(
            "private directory path must name a directory below a Windows filesystem root",
        ));
    }
    Ok((root, names))
}

fn open_or_create_child(parent: &File, component: &OsStr) -> Result<File, std::io::Error> {
    use std::os::windows::ffi::OsStrExt;

    validate_component(component)?;
    let mut encoded = component.encode_wide().collect::<Vec<_>>();
    let length = u16::try_from(encoded.len() * 2)
        .map_err(|_| invalid_path("Windows directory component length overflow"))?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())
            .map_err(|_| invalid_path("Windows object-attribute size overflow"))?,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: std::ptr::from_ref(&name),
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: the counted component name and object attributes remain live for
    // the call. RootDirectory is the owned parent directory handle.
    let status = unsafe {
        NtCreateFile(
            std::ptr::from_mut(&mut handle),
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            std::ptr::from_ref(&attributes),
            std::ptr::from_mut(&mut io_status),
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        if status == STATUS_REPARSE_POINT_ENCOUNTERED {
            return Err(reparse_point_error());
        }
        // SAFETY: RtlNtStatusToDosError accepts every NTSTATUS value.
        let windows_error = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(
            i32::try_from(windows_error).unwrap_or(i32::MAX),
        ));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(
            "Windows returned a null private-directory handle",
        ));
    }
    // SAFETY: NtCreateFile returned a unique owned handle on success.
    let child = unsafe { File::from_raw_handle(handle) };
    validate_directory_handle(&child)?;
    Ok(child)
}

fn validate_component(component: &OsStr) -> Result<(), std::io::Error> {
    use std::os::windows::ffi::OsStrExt;

    let encoded = component.encode_wide().collect::<Vec<_>>();
    if encoded.is_empty() || encoded.contains(&0) {
        return Err(invalid_path(
            "private directory path contains an invalid empty or NUL component",
        ));
    }
    if encoded.as_slice() == [u16::from(b'.')]
        || encoded.as_slice() == [u16::from(b'.'), u16::from(b'.')]
    {
        return Err(invalid_path(
            "private directory path must not contain dot components",
        ));
    }
    if encoded.len() > usize::from(u16::MAX) / 2 {
        return Err(invalid_path(
            "private directory path component exceeds the Windows Unicode limit",
        ));
    }
    Ok(())
}

fn validate_directory_handle(directory: &File) -> Result<(), std::io::Error> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let buffer_size = u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
        .map_err(|_| invalid_path("Windows file-attribute buffer size overflow"))?;
    // SAFETY: `directory` owns a live handle, and `attributes` points to a
    // correctly sized writable FILE_ATTRIBUTE_TAG_INFO buffer.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut attributes).cast(),
            buffer_size,
        )
    };
    if queried == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(reparse_point_error());
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(invalid_path(
            "private directory ancestry must contain only directories",
        ));
    }
    Ok(())
}

fn invalid_path(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

fn reparse_point_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "private directory ancestry must not contain Windows reparse points",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use super::*;

    fn create_junction(link: &Path, target: &Path) -> Result<(), std::io::Error> {
        let output = Command::new("cmd")
            .arg("/D")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "failed to create test junction: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    #[test]
    fn private_directory_creates_missing_components_without_reparse_points(
    ) -> Result<(), std::io::Error> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("nested").join("project");

        prepare_private_directory(&target)?;

        assert!(target.is_dir());
        Ok(())
    }

    #[test]
    fn private_directory_rejects_intermediate_junction_before_creating_leaf(
    ) -> Result<(), std::io::Error> {
        let directory = tempfile::tempdir()?;
        let outside = directory.path().join("attacker-selected");
        let junction = directory.path().join("alias");
        fs::create_dir(&outside)?;
        create_junction(&junction, &outside)?;

        let result = prepare_private_directory(&junction.join("project"));

        assert!(result.is_err());
        assert!(!outside.join("project").exists());
        fs::remove_dir(&junction)?;
        Ok(())
    }

    #[test]
    fn private_directory_rejects_final_junction() -> Result<(), std::io::Error> {
        let directory = tempfile::tempdir()?;
        let outside = directory.path().join("attacker-selected");
        let junction = directory.path().join("authority.locks");
        fs::create_dir(&outside)?;
        create_junction(&junction, &outside)?;

        let result = prepare_private_directory(&junction);

        assert!(result.is_err());
        fs::remove_dir(&junction)?;
        Ok(())
    }

    #[test]
    fn supported_windows_roots_are_kept_outside_the_component_walk() -> Result<(), std::io::Error> {
        for (path, expected_root) in [
            (r"C:\project", r"C:\"),
            (r"\\?\C:\project", r"\\?\C:\"),
            (r"\\server\share\project", r"\\server\share\"),
            (r"\\?\UNC\server\share\project", r"\\?\UNC\server\share\"),
        ] {
            let (root, names) = split_absolute_path(Path::new(path))?;
            assert_eq!(root, Path::new(expected_root));
            assert_eq!(names, [OsString::from("project")]);
        }
        Ok(())
    }

    #[test]
    fn windows_device_namespaces_fail_closed() {
        for path in [
            r"\\.\C:\project",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\project",
        ] {
            assert!(split_absolute_path(Path::new(path)).is_err());
        }
    }

    #[test]
    fn windows_filesystem_root_is_not_a_private_directory() {
        assert!(split_absolute_path(Path::new(r"C:\")).is_err());
    }

    #[test]
    fn verbatim_current_directory_component_fails_closed() {
        assert!(split_absolute_path(Path::new(r"\\?\C:\safe\.\project")).is_err());
    }
}
