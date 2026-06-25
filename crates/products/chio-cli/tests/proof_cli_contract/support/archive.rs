use chio_test_support::prelude::*;
use std::{collections::BTreeSet, io::Write, path::Path};

#[cfg(unix)]
fn append_symlink_member<W: Write>(builder: &mut tar::Builder<W>, outside_passport: &Path) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_mode(0o777);
    header.set_size(0);
    header.set_cksum();
    builder
        .append_link(&mut header, "transaction-passport.json", outside_passport)
        .test_expect("append symlink member");
}

#[cfg(unix)]
pub(crate) fn write_tgz_with_symlink_member(path: &Path, outside_passport: &Path) {
    let file = std::fs::File::create(path).test_expect("create archive");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_symlink_member(&mut builder, outside_passport);
    builder.finish().test_expect("finish archive");
    let encoder = builder.into_inner().test_expect("finish encoder");
    encoder.finish().test_expect("finish gzip");
}

#[cfg(unix)]
pub(crate) fn write_tar_zst_with_symlink_member(path: &Path, outside_passport: &Path) {
    let file = std::fs::File::create(path).test_expect("create archive");
    let encoder = zstd::stream::write::Encoder::new(file, 0).test_expect("create zstd encoder");
    let mut builder = tar::Builder::new(encoder);
    append_symlink_member(&mut builder, outside_passport);
    builder.finish().test_expect("finish archive");
    let encoder = builder.into_inner().test_expect("finish encoder");
    encoder.finish().test_expect("finish zstd");
}

pub(crate) fn tgz_member_names(path: &Path) -> BTreeSet<String> {
    let file = std::fs::File::open(path).test_expect("open tgz archive");
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    archive
        .entries()
        .test_expect("read archive entries")
        .map(|entry| {
            entry
                .test_expect("read archive entry")
                .path()
                .test_expect("read archive path")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}
