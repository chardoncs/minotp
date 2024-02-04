use minotp::{GenerateOtpDefault, Hotp};
use sha1::Sha1;

#[test]
fn test_hotp_sha1_1() {
    let hotp = Hotp::<Sha1>::from_bytes(b"3132333435363738393031323334353637383930", 1).unwrap();

    assert_eq!(hotp.gen_8(), 56652700);
}
