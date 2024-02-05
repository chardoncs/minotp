//! HOTP implementation

use hmac::{digest::{
    block_buffer::Eager, core_api::{
        BufferKindUser,
        CoreProxy,
        FixedOutputCore,
        UpdateCore
    },
    crypto_common::BlockSizeUser,
    typenum::{IsLess, Le, NonZero, U256},
    HashMarker,
    InvalidLength,
}, Hmac, Mac};

use crate::{util::truncate, GenerateOtp};

// Direct access of 10 with power of 0~9
const POW10: [u32; 10] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];

/// HOTP
///
/// Implementation of HOTP in [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226).
///
/// # Examples
///
/// ## Common Usage
/// 
/// ```
/// use minotp::*;
/// use sha1::Sha1; // SHA1 library by rust-crypto
///
/// let secret = b"test";
/// let counter = 1;
///
/// // An HOTP instance using HMAC-SHA1
/// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
///
/// let token = hotp.gen_6_str();
///
/// assert_eq!(token, "431881");
/// ```
///
/// Or you can get an integer token
///
/// ```
/// use minotp::*;
/// use sha1::Sha1;
///
/// let secret = b"test";
/// let counter = 1;
///
/// // An HOTP instance using HMAC-SHA1
/// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
///
/// let token = hotp.gen_6();
///
/// assert_eq!(token, 431881);
/// ```
///
/// ## Custom digits
///
/// Besides 6-digit token that is commonly used.
/// You may generate tokens in other digit counts.
///
/// Other than "default" methods for common digits (i.e. 4, 6, and 8).
/// You may specify a digit.
///
/// ```
/// use minotp::*;
/// use sha1::Sha1;
///
/// let secret = b"test";
/// let counter = 1;
///
/// // An HOTP instance using HMAC-SHA1
/// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
///
/// // Or specify a digit you want
/// assert_eq!(hotp.gen_str(2), "81");
/// ```
pub struct Hotp<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    hmac: Hmac<D>,
}

impl<D> Hotp<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Instantiate an HOTP instance
    ///
    /// # Note
    /// 
    /// The secret here is raw bytes, not a Base32.
    ///
    /// Use an encoding crate to convert a Base32 secret
    /// if you have to deal with such problem.
    /// 
    /// For example, you may use [`data-encoding`](https://crates.io/crates/data-encoding)
    /// as below.
    ///
    /// ```
    /// use data_encoding::BASE32;
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret_base32_str = "ORSXG5A=";
    /// let counter = 0x3131;
    ///
    /// let secret = BASE32.decode(secret_base32_str.as_bytes()).unwrap();
    /// 
    /// let hotp = Hotp::<Sha1>::from_bytes(&secret, counter).unwrap();
    ///
    /// assert_eq!(hotp.gen_6(), 521347);
    /// ```
    pub fn from_bytes(secret: &[u8], counter: u64) -> Result<Self, InvalidLength>
    where
        Self: Sized,
    {
        let mut hmac = Hmac::<D>::new_from_slice(secret)?;
        hmac.update(&counter.to_be_bytes());

        Ok(Self { hmac })
    }
}

impl<D> GenerateOtp for Hotp<D>
where
    D: CoreProxy,
    D::Core: HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn gen(self, digits: u8) -> u32 {
        let mut c = truncate(&self.hmac.finalize().into_bytes());

        if digits < 10 {
            c %= POW10[digits as usize];
        }

        c
    }
}

