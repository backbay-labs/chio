//! Narrow audited boundary for binding a `rusqlite` connection to the exact
//! main-database file borrowed by SQLite.
//!
//! The workspace uses rusqlite's pinned `bundled` SQLite build. Qualified
//! stores require a bundled Unix VFS, whose `unixFile` prefix is stable and
//! contains the database descriptor after SQLite's public `sqlite3_file` base.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_int, c_void, CStr};

use rusqlite::ffi;

/// Filesystem identity of the exact main-database descriptor held by SQLite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub link_count: u64,
}

#[cfg(unix)]
#[repr(C)]
#[derive(Clone, Copy)]
struct BundledUnixFilePrefix {
    methods: *const ffi::sqlite3_io_methods,
    vfs: *mut ffi::sqlite3_vfs,
    inode_info: *mut c_void,
    descriptor: c_int,
}

/// Read the device, inode, and link count from the actual descriptor backing
/// `connection`'s main database.
///
/// This deliberately fails closed for non-Unix or non-bundled-Unix VFSes.
#[cfg(unix)]
pub fn main_database_file_identity(
    connection: &rusqlite::Connection,
) -> Result<SqliteFileIdentity, String> {
    let mut file = std::ptr::null_mut::<ffi::sqlite3_file>();
    let mut vfs = std::ptr::null_mut::<ffi::sqlite3_vfs>();
    // SAFETY: `connection` keeps its sqlite3 handle alive for this call. Both
    // opcodes are public SQLite APIs and receive correctly typed out-pointers.
    let (file_result, vfs_result) = unsafe {
        let handle = connection.handle();
        (
            ffi::sqlite3_file_control(
                handle,
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                std::ptr::addr_of_mut!(file).cast(),
            ),
            ffi::sqlite3_file_control(
                handle,
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_VFS_POINTER,
                std::ptr::addr_of_mut!(vfs).cast(),
            ),
        )
    };
    if file_result != ffi::SQLITE_OK || file.is_null() {
        return Err(format!(
            "SQLite main file pointer is unavailable (result {file_result})"
        ));
    }
    if vfs_result != ffi::SQLITE_OK || vfs.is_null() {
        return Err(format!(
            "SQLite main VFS pointer is unavailable (result {vfs_result})"
        ));
    }

    // SAFETY: SQLite returned `vfs` from the live connection. Its public
    // sqlite3_vfs fields remain valid while the connection is borrowed.
    let (vfs_name, vfs_file_size) = unsafe {
        let vfs = &*vfs;
        let name = if vfs.zName.is_null() {
            return Err("SQLite main VFS has no name".to_owned());
        } else {
            CStr::from_ptr(vfs.zName)
                .to_str()
                .map_err(|_| "SQLite main VFS name is not UTF-8".to_owned())?
                .to_owned()
        };
        (name, vfs.szOsFile)
    };
    if !vfs_name.starts_with("unix") {
        return Err(format!(
            "qualified SQLite file identity requires a bundled Unix VFS, got {vfs_name}"
        ));
    }
    if vfs_file_size < std::mem::size_of::<BundledUnixFilePrefix>() as c_int {
        return Err("SQLite Unix VFS file object is smaller than its audited prefix".to_owned());
    }

    // SAFETY: the public FILE_POINTER opcode returned an allocation whose VFS
    // reports enough bytes for the pinned bundled Unix prefix checked above.
    // `read_unaligned` avoids imposing a stronger alignment than SQLite gave.
    let prefix = unsafe { std::ptr::read_unaligned(file.cast::<BundledUnixFilePrefix>()) };
    if prefix.vfs != vfs {
        return Err("SQLite main file is not owned by the reported Unix VFS".to_owned());
    }
    if prefix.methods.is_null() || prefix.descriptor < 0 {
        return Err("SQLite main database descriptor is unavailable".to_owned());
    }

    let descriptor_path = if cfg!(target_os = "linux") {
        format!("/proc/self/fd/{}", prefix.descriptor)
    } else {
        format!("/dev/fd/{}", prefix.descriptor)
    };
    let metadata = std::fs::metadata(&descriptor_path)
        .map_err(|error| format!("SQLite main database descriptor metadata failed: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    Ok(SqliteFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        link_count: metadata.nlink(),
    })
}

#[cfg(not(unix))]
pub fn main_database_file_identity(
    _connection: &rusqlite::Connection,
) -> Result<SqliteFileIdentity, String> {
    Err("qualified SQLite file identity requires Unix".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn reports_the_borrowed_main_database_file() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir()?;
        let database = directory.path().join("identity.sqlite3");
        let connection = rusqlite::Connection::open(&database)?;
        connection.execute_batch("CREATE TABLE identity_probe (value INTEGER NOT NULL);")?;

        let expected = std::fs::metadata(&database)?;
        let actual = main_database_file_identity(&connection)?;
        assert_eq!(actual.device, expected.dev());
        assert_eq!(actual.inode, expected.ino());
        assert_eq!(actual.link_count, expected.nlink());
        Ok(())
    }
}
