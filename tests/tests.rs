use minotp::{GenerateOtp, GenerateOtpDefault, Hotp};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;

#[test]
fn hotp_sha1_digit4_default() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen_4(), 7126);
}

#[test]
fn hotp_sha1_digit4_default_str() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen_4_str(), "7126");
}

#[test]
fn hotp_sha1_digit6_default() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen_6(), 147126);
}

#[test]
fn hotp_sha1_digit6_default_str() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen_6_str(), "147126");
}

#[test]
fn hotp_sha1_digit8_default() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen_8(), 97147126);
}

#[test]
fn hotp_sha1_digit8_default_str() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen_8_str(), "97147126");
}

#[test]
fn hotp_sha1_digit8_generic() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen(8), 97147126);
}

#[test]
fn hotp_sha1_digit10_generic() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen(10), 997147126);
}

#[test]
fn hotp_sha1_digit10_default_str_leading_zeroes() {
    let hotp = Hotp::<Sha1>::from_bytes(b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE).unwrap();

    assert_eq!(hotp.gen_str(10), "0997147126");
}

#[test]
fn hotp_sha256_digit6_default() {
    let hotp = Hotp::<Sha256>::from_bytes(b"111111111111111111111111111", 0xAAAA).unwrap();

    assert_eq!(hotp.gen_6(), 646199);
}

#[test]
fn hotp_sha512_digit8_default() {
    let hotp = Hotp::<Sha512>::from_bytes(b"111111111111111111111111111", 0xAAAA).unwrap();

    assert_eq!(hotp.gen_8(), 55717069);
}

#[test]
fn hotp_sha3_256_digit8_default() {
    let hotp = Hotp::<Sha3_256>::from_bytes(b"111111111111111111111111111", 0xAAAA).unwrap();

    assert_eq!(hotp.gen_8(), 49753380)
}
