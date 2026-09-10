use der::{Decode, Encode, asn1::SetOfRef};
fn main() {
    for (name, bytes) in [("valid_integer", &[0x31, 0x03, 0x02, 0x01, 0x01][..]), ("wrong_type_null", &[0x31, 0x02, 0x05, 0x00][..])] {
        match SetOfRef::<u8>::from_der(bytes) {
            Ok(set) => println!("{name}: accepted len={} count={} first={:?} reencoded={:?}", set.len(), set.iter().count(), set.iter().next(), set.to_der()),
            Err(err) => println!("{name}: rejected {err}"),
        }
    }
}
