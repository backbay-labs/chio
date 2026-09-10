// Source-review specimens only. NOT COMPILED OR EXECUTED by this review.
// Run with der alloc enabled. The SetOfRef assertions expose the unresolved issue.
use der::{asn1::SetOfRef, Decode, Error, Length, Reader, SliceReader};

#[test]
fn nested_values_must_be_fully_consumed() {
    let mut r = SliceReader::new(&[1, 2]).unwrap();
    let result: Result<(), Error> = r.read_nested(Length::from(2u8), |inner| {
        inner.read_slice(Length::ONE)?;
        Ok(())
    });
    assert!(result.is_err());
}

#[test]
fn typed_set_must_reject_null_as_integer() {
    assert!(SetOfRef::<u8>::from_der(&[0x31, 0x02, 0x05, 0x00]).is_err());
}
