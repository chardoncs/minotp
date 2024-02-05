use data_encoding::BASE32;
use minotp::{GenerateOtp, GenerateOtpDefault, Hotp, Totp, COMMON_INTERVAL};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;

// Helper macros

macro_rules! test_hotp {
    ($fn_name:ident, $alg:ty, $secret:expr, $counter:expr, $call:ident, $exp:expr $(, params: [$($param:expr),*])?) => {
        #[test]
        fn $fn_name() {
            let hotp = Hotp::<$alg>::from_bytes($secret, $counter).unwrap();

            assert_eq!(hotp.$call($($($param,)*)?), $exp);
        }
    };
}

// HOTP

test_hotp!(hotp_sha1_digit4_default, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen_4, 7126);
test_hotp!(hotp_sha1_digit4_default_str, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen_4_str, "7126");

test_hotp!(hotp_sha1_digit6_default, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen_6, 147126);
test_hotp!(hotp_sha1_digit6_default_str, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen_6_str, "147126");

test_hotp!(hotp_sha1_digit8_default, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen_8, 97147126);
test_hotp!(hotp_sha1_digit8_default_str, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen_8_str, "97147126");

test_hotp!(hotp_sha1_digit8_generic, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen, 97147126, params: [8]);
test_hotp!(hotp_sha1_digit10_generic, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen, 997147126, params: [10]);

test_hotp!(hotp_sha1_digit10_str_leading_zeroes, Sha1, b"98u9U9u(bu(*u(*y89b(b8g", 0x45EE, gen_str, "0997147126", params: [10]);

test_hotp!(hotp_sha256_digit6_default, Sha256, b"111111111111111111111111111", 0xAAAA, gen_6, 646199);

test_hotp!(hotp_sha512_digit8_default, Sha512, b"111111111111111111111111111", 0xAAAA, gen_8, 55717069);

test_hotp!(hotp_sha3_256_digit8_default, Sha3_256, b"111111111111111111111111111", 0xAAAA, gen_8, 49753380);

// TOTP

#[test]
fn totp_sha1_digit6_default() {
    let secret_base32 = "MNSTS5LFGEZDQOLF";
    let timestamp = 1707146471;

    // Decode Base32 using `data_encoding` library
    let secret = BASE32.decode(secret_base32.as_bytes()).unwrap();

    let totp = Totp::<Sha1>::new(&secret, COMMON_INTERVAL, timestamp).unwrap();

    assert_eq!(totp.remaining_sec(), 19);
    assert_eq!(totp.gen_6(), 437617);
}

#[test]
fn totp_sha256_digit8_default() {
    let secret_base32 = "K5KEMIDXNB4SA6LPOUQGIZLDN5SGKZBAORUGS4Z7";
    let timestamp = 1707146946;

    let secret = BASE32.decode(secret_base32.as_bytes()).unwrap();

    let totp = Totp::<Sha256>::new(&secret, 75, timestamp).unwrap();

    assert_eq!(totp.remaining_sec(), 54);
    assert_eq!(totp.gen_8(), 58273556);
}
