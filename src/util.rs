use std::time::{SystemTime, UNIX_EPOCH};

const ENS_BIT: usize = 8;

const SIZE: usize = 4;

pub(crate) fn truncate(hash: &[u8]) -> u32 {
    let offset: u8 = hash.last().or(Some(&0)).unwrap() & 0xF;

    let mut output = 0u32;

    for i in 0..SIZE {
        output <<= ENS_BIT;
        output |= hash[offset as usize + i] as u32;
    }

    output << 1 >> 1
}

/// Calculate TOTP counter
///
/// Returns:
///
/// (counter, remaining seconds until expiration)
pub(crate) fn calc_totp_counter(interval: u32) -> (u64, u32) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("[minotp::Totp] FATAL: Your system time is probably incorrectly set.")
        .as_millis() as u64;
    
    let interval = interval as u64;

    (timestamp / interval, (interval - timestamp % interval) as u32)
}
