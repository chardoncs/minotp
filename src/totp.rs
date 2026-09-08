//! TOTP implementation

use hmac::digest::{Digest, InvalidLength, common::BlockSizeUser};

use crate::{
    GenerateOtp, Hotp,
    util::{calc_totp_counter, time_now},
};

/// Interval that is commonly adopted among most TOTP services
///
/// i.e. 30 seconds
pub const COMMON_INTERVAL: u32 = 30;

/// TOTP
///
/// Implementation of TOTP in [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).
///
/// # Examples
///
/// ## Common Usage
///
/// ```
/// use minotp::*;
/// use sha1::Sha1;
///
/// let secret = b"test";
///
/// let totp = Totp::<Sha1>::from_bytes(secret, COMMON_INTERVAL).unwrap();
///
/// // Get remaining seconds
/// let _remaining_seconds = totp.remaining_sec();
///
/// // Get token
/// let _token = totp.generate_6_str();
///
/// // -- snip -- //
/// ```
///
/// ## Base32 secret
///
/// Use a third-party crate (e.g., [`data_encoding`](https://crates.io/crates/data-encoding))
/// to decode your secret if your secret is Base32 encoded.
///
/// ```
/// use data_encoding::BASE32;
/// use minotp::*;
/// use sha1::Sha1;
///
/// let secret_base32_str = "ORSXG5A=";
///
/// let secret = BASE32.decode(secret_base32_str.as_bytes()).unwrap();
///
/// let totp = Totp::<Sha1>::from_bytes(&secret, COMMON_INTERVAL).unwrap();
///
/// let _token = totp.generate_6_str();
///
/// // -- snip -- //
/// ```
pub struct Totp<D: Digest + BlockSizeUser> {
    hotp: Hotp<D>,
    interval: u32,
    remain: u32,
}

impl<D: Digest + BlockSizeUser> Totp<D> {
    /// Instantiate a TOTP instance
    pub fn from_bytes(secret: &[u8], interval: u32) -> Result<Self, InvalidLength> {
        Self::new(secret, interval, time_now())
    }

    /// Instantiate a TOTP instance with custom timestamp
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let interval = 75;
    /// let unix_timestamp = 112345u64;
    ///
    /// let totp = Totp::<Sha1>::new(secret, interval, unix_timestamp).unwrap();
    ///
    /// assert_eq!(totp.generate_6_str(), "677062");
    /// ```
    pub fn new(secret: &[u8], interval: u32, timestamp: u64) -> Result<Self, InvalidLength> {
        let (counter, remain) = calc_totp_counter(interval, timestamp);

        Ok(Self {
            hotp: Hotp::from_bytes(secret, counter)?,
            interval,
            remain,
        })
    }

    /// Interval of current TOTP instance in seconds
    pub fn interval(&self) -> u32 {
        self.interval
    }

    /// Remaining seconds of current token **since instantiated**
    pub fn remaining_sec(&self) -> u32 {
        self.remain
    }
}

impl<D: Digest + BlockSizeUser> GenerateOtp for Totp<D> {
    fn generate(self, digits: u8) -> u32 {
        self.hotp.generate(digits)
    }
}
