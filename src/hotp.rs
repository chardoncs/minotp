//! HOTP implementation

use hmac::{digest::{
    block_buffer::Eager, core_api::{
        BufferKindUser,
        CoreProxy,
        FixedOutputCore,
        UpdateCore
    }, crypto_common::BlockSizeUser, typenum::{IsLess, Le, NonZero, U256}, HashMarker, InvalidLength
}, Hmac, Mac};

use crate::{util::truncate, GenerateOtp};

// Direct access of 10 with power of 0~9
const POW10: [u32; 10] = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000];

/// HOTP
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
    /// Parameters:
    ///
    /// - secret: Secret of HOTP as bytes (**NOT Base32**)
    /// - counter: Counter
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

