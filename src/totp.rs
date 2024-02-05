//! TOTP implementation

use hmac::digest::{
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
};

use crate::{util::{calc_totp_counter, time_now}, GenerateOtp, Hotp};

/// Interval that is commonly adopted among most TOTP services
///
/// i.e. 30 seconds
pub const COMMON_INTERVAL: u32 = 30;

/// TOTP (wrapper of HOTP with counter replaced by datetime)
pub struct Totp<D>
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
    hotp: Hotp<D>,
    interval: u32,
    remain: u32,
}

impl<D> Totp<D>
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
    /// Instantiate a TOTP instance
    ///
    /// Params:
    ///
    /// - secret: Secret as bytes (**NOT Base32**)
    /// - interval: Interval in seconds
    pub fn from_bytes(secret: &[u8], interval: u32) -> Result<Self, InvalidLength>
    where
        Self: Sized,
    {
        Self::new(secret, interval, time_now())
    }

    /// Instantiate a TOTP instance
    ///
    /// Params:
    ///
    /// - secret: Secret
    /// - interval: Interval in sec
    /// - timestamp: Specified UNIX timestamp
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

impl<D> GenerateOtp for Totp<D>
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
        self.hotp.gen(digits)
    }
}

