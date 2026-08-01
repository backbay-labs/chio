use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileNamesInformation, NtCreateFile, NtQueryDirectoryFile, FILE_CREATE, FILE_DIRECTORY_FILE,
    FILE_NAMES_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    STATUS_NO_MORE_FILES, STATUS_REPARSE_POINT_ENCOUNTERED, STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FILE_WRITE_DATA, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const DIRECTORY_TRAVERSE_ACCESS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const DIRECTORY_MUTATION_ACCESS: u32 =
    DIRECTORY_TRAVERSE_ACCESS | FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;

pub(super) struct PreparedPrivateDirectory {
    directory: File,
    _pinned_ancestors: Vec<File>,
}

impl PreparedPrivateDirectory {
    pub(super) fn validate_path_identity(&self, path: &Path) -> Result<(), std::io::Error> {
        let pinned = self.directory.metadata()?;
        let current = fs::symlink_metadata(path)?;
        let pinned_identity = pinned.volume_serial_number().zip(pinned.file_index());
        let current_identity = current.volume_serial_number().zip(current.file_index());
        if current.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !current.is_dir()
            || pinned_identity.is_none()
            || pinned_identity != current_identity
        {
            return Err(invalid_data(format!(
                "prepared private directory path `{}` no longer identifies the pinned directory",
                path.display()
            )));
        }
        Ok(())
    }

    pub(super) fn is_empty(&self) -> Result<bool, std::io::Error> {
        let name_offset = std::mem::offset_of!(FILE_NAMES_INFORMATION, FileName);
        let minimum_buffer_bytes = usize::from(u16::MAX)
            .checked_add(name_offset)
            .and_then(|size| size.checked_add(std::mem::size_of::<usize>()))
            .ok_or_else(|| invalid_path("Windows directory query buffer size overflow"))?;
        let word_count = minimum_buffer_bytes.div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; word_count];
        let buffer_bytes = buffer
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or_else(|| invalid_path("Windows directory query buffer size overflow"))?;
        let buffer_length = u32::try_from(buffer_bytes)
            .map_err(|_| invalid_path("Windows directory query buffer size overflow"))?;
        let mut restart_scan = true;

        loop {
            let mut io_status = IO_STATUS_BLOCK::default();
            // SAFETY: the target directory handle is live and was opened for
            // synchronous directory listing. `buffer` is aligned, initialized,
            // and writable for `buffer_length` bytes for the duration of the
            // call.
            let status = unsafe {
                NtQueryDirectoryFile(
                    self.directory.as_raw_handle() as HANDLE,
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null(),
                    std::ptr::from_mut(&mut io_status),
                    buffer.as_mut_ptr().cast(),
                    buffer_length,
                    FileNamesInformation,
                    true,
                    std::ptr::null(),
                    restart_scan,
                )
            };
            if status == STATUS_NO_MORE_FILES {
                return Ok(true);
            }
            if status != STATUS_SUCCESS {
                return Err(ntstatus_error(status));
            }

            let information_length = io_status.Information;
            if information_length < name_offset {
                return Err(invalid_data("Windows returned a truncated directory entry"));
            }
            // SAFETY: `buffer` has `usize` alignment and the successful query
            // initialized at least the fixed entry prefix checked above.
            let entry = unsafe { std::ptr::read(buffer.as_ptr().cast::<FILE_NAMES_INFORMATION>()) };
            let file_name_length = usize::try_from(entry.FileNameLength)
                .map_err(|_| invalid_data("Windows directory entry name length overflow"))?;
            if file_name_length % std::mem::size_of::<u16>() != 0 {
                return Err(invalid_data(
                    "Windows returned an odd directory entry name length",
                ));
            }
            let name_end = name_offset
                .checked_add(file_name_length)
                .ok_or_else(|| invalid_data("Windows directory entry name length overflow"))?;
            if name_end > information_length || name_end > buffer_bytes {
                return Err(invalid_data(
                    "Windows returned a truncated directory entry name",
                ));
            }
            let file_name_units = file_name_length / std::mem::size_of::<u16>();
            // SAFETY: `buffer` is aligned to `usize`, `name_offset` is aligned
            // for u16, and the checked range lies inside initialized query
            // output.
            let file_name = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().cast::<u8>().add(name_offset).cast::<u16>(),
                    file_name_units,
                )
            };
            let dot = u16::from(b'.');
            if file_name != [dot] && file_name != [dot, dot] {
                return Ok(false);
            }
            restart_scan = false;
        }
    }

    pub(super) fn create_dir_all(&self, relative: &Path) -> Result<(), std::io::Error> {
        let components = split_relative_path(relative)?;
        let mut directory = self.directory.try_clone()?;
        for component in components {
            directory = open_directory_child(
                &directory,
                &component,
                DIRECTORY_MUTATION_ACCESS,
                FILE_OPEN_IF,
            )?;
        }
        Ok(())
    }

    pub(super) fn write_new(&self, relative: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
        let components = split_relative_path(relative)?;
        let (file_name, parents) = components
            .split_last()
            .ok_or_else(|| invalid_path("private file path must name a relative file"))?;
        let mut directory = self.directory.try_clone()?;
        for component in parents {
            directory =
                open_directory_child(&directory, component, DIRECTORY_MUTATION_ACCESS, FILE_OPEN)?;
        }

        let mut file = open_child(
            &directory,
            file_name,
            FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )?;
        validate_regular_file_handle(&file)?;
        file.write_all(contents)?;
        file.sync_all()
    }
}

pub(super) fn prepare_private_directory(
    path: &Path,
) -> Result<PreparedPrivateDirectory, std::io::Error> {
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
        .access_mode(DIRECTORY_TRAVERSE_ACCESS)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let mut directory = options.open(root)?;
    validate_directory_handle(&directory)?;
    let mut pinned_ancestors = Vec::new();
    let final_index = names
        .len()
        .checked_sub(1)
        .ok_or_else(|| invalid_path("private directory path must name a directory"))?;
    for (index, component) in names.into_iter().enumerate() {
        let desired_access = if index == final_index {
            DIRECTORY_MUTATION_ACCESS
        } else {
            DIRECTORY_TRAVERSE_ACCESS
        };
        let child = open_directory_child(&directory, &component, desired_access, FILE_OPEN_IF)?;
        pinned_ancestors.push(directory);
        directory = child;
    }
    Ok(PreparedPrivateDirectory {
        directory,
        _pinned_ancestors: pinned_ancestors,
    })
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

fn split_relative_path(path: &Path) -> Result<Vec<OsString>, std::io::Error> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                validate_component(name)?;
                names.push(name.to_os_string());
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(invalid_path(
                    "private file path must contain only normal relative components",
                ));
            }
        }
    }
    if names.is_empty() {
        return Err(invalid_path(
            "private file path must name a relative filesystem entry",
        ));
    }
    Ok(names)
}

fn open_directory_child(
    parent: &File,
    component: &OsStr,
    desired_access: u32,
    create_disposition: u32,
) -> Result<File, std::io::Error> {
    let child = open_child(
        parent,
        component,
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        create_disposition,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )?;
    validate_directory_handle(&child)?;
    Ok(child)
}

fn open_child(
    parent: &File,
    component: &OsStr,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Result<File, std::io::Error> {
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
            desired_access,
            std::ptr::from_ref(&attributes),
            std::ptr::from_mut(&mut io_status),
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            create_disposition,
            create_options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        if status == STATUS_REPARSE_POINT_ENCOUNTERED {
            return Err(reparse_point_error());
        }
        return Err(ntstatus_error(status));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(
            "Windows returned a null private filesystem handle",
        ));
    }
    // SAFETY: NtCreateFile returned a unique owned handle on success.
    Ok(unsafe { File::from_raw_handle(handle) })
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
    if encoded.contains(&u16::from(b':')) {
        return Err(invalid_path(
            "private directory path must not contain alternate data stream components",
        ));
    }
    if encoded
        .last()
        .is_some_and(|unit| *unit == u16::from(b'.') || *unit == u16::from(b' '))
    {
        return Err(invalid_path(
            "private directory path components must not end in a dot or space",
        ));
    }
    if encoded.len() > usize::from(u16::MAX) / 2 {
        return Err(invalid_path(
            "private directory path component exceeds the Windows Unicode limit",
        ));
    }
    Ok(())
}

fn validate_regular_file_handle(file: &File) -> Result<(), std::io::Error> {
    let attributes = query_file_attributes(file)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(reparse_point_error());
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(invalid_path("private file path must not name a directory"));
    }
    Ok(())
}

fn validate_directory_handle(directory: &File) -> Result<(), std::io::Error> {
    let attributes = query_file_attributes(directory)?;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(reparse_point_error());
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(invalid_path(
            "private directory ancestry must contain only directories",
        ));
    }
    Ok(())
}

fn query_file_attributes(file: &File) -> Result<u32, std::io::Error> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let buffer_size = u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
        .map_err(|_| invalid_path("Windows file-attribute buffer size overflow"))?;
    // SAFETY: `file` owns a live handle, and `attributes` points to a
    // correctly sized writable FILE_ATTRIBUTE_TAG_INFO buffer.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut attributes).cast(),
            buffer_size,
        )
    };
    if queried == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(attributes.FileAttributes)
}

fn invalid_path(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn ntstatus_error(status: i32) -> std::io::Error {
    // SAFETY: RtlNtStatusToDosError accepts every NTSTATUS value.
    let windows_error = unsafe { RtlNtStatusToDosError(status) };
    std::io::Error::from_raw_os_error(i32::try_from(windows_error).unwrap_or(i32::MAX))
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

        let prepared = prepare_private_directory(&target)?;

        assert!(target.is_dir());
        assert!(prepared.is_empty()?);
        Ok(())
    }

    #[test]
    fn prepared_directory_supports_root_relative_scaffold_operations() -> Result<(), std::io::Error>
    {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("project");
        let prepared = prepare_private_directory(&target)?;

        assert!(prepared.is_empty()?);
        assert!(prepared.is_empty()?);
        prepared.create_dir_all(Path::new("src/bin"))?;
        prepared.write_new(Path::new("Cargo.toml"), b"[package]\n")?;
        prepared.write_new(Path::new("src/bin/demo.rs"), b"fn main() {}\n")?;

        assert!(!prepared.is_empty()?);
        assert!(!prepared.is_empty()?);
        assert_eq!(fs::read(target.join("Cargo.toml"))?, b"[package]\n");
        assert_eq!(fs::read(target.join("src/bin/demo.rs"))?, b"fn main() {}\n");
        Ok(())
    }

    #[test]
    fn prepared_directory_write_new_never_overwrites_existing_file() -> Result<(), std::io::Error> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("project");
        let prepared = prepare_private_directory(&target)?;
        prepared.write_new(Path::new("policy.yaml"), b"first\n")?;

        let result = prepared.write_new(Path::new("policy.yaml"), b"second\n");

        assert!(result.is_err());
        assert_eq!(fs::read(target.join("policy.yaml"))?, b"first\n");
        Ok(())
    }

    #[test]
    fn prepared_directory_relative_operations_reject_escape_paths() -> Result<(), std::io::Error> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("project");
        let prepared = prepare_private_directory(&target)?;

        assert!(prepared
            .create_dir_all(Path::new("../attacker-selected"))
            .is_err());
        assert!(prepared
            .write_new(Path::new(r"C:\attacker-selected"), b"outside")
            .is_err());
        assert!(prepared
            .write_new(Path::new("policy.yaml:stream"), b"outside")
            .is_err());
        assert!(!directory.path().join("attacker-selected").exists());
        assert!(prepared.is_empty()?);
        Ok(())
    }

    #[test]
    fn prepared_directory_rejects_inserted_junction_during_relative_walk(
    ) -> Result<(), std::io::Error> {
        let directory = tempfile::tempdir()?;
        let target = directory.path().join("project");
        let outside = directory.path().join("attacker-selected");
        let junction = target.join("src");
        let prepared = prepare_private_directory(&target)?;
        fs::create_dir(&outside)?;
        create_junction(&junction, &outside)?;

        let create_result = prepared.create_dir_all(Path::new("src/bin"));
        let write_result = prepared.write_new(Path::new("src/demo.rs"), b"outside");

        assert!(create_result.is_err());
        assert!(write_result.is_err());
        assert!(!outside.join("bin").exists());
        assert!(!outside.join("demo.rs").exists());
        fs::remove_dir(&junction)?;
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
