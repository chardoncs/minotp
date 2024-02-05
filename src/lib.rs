//! mintop

mod hotp;

mod totp;

mod util;

pub use hotp::Hotp;
pub use totp::Totp;

pub use totp::COMMON_INTERVAL;

/// Generate OTP
pub trait GenerateOtp {
    /// Generate OTP as an unsigned number
    fn gen(self, digits: u8) -> u32;
    
    fn gen_str(self, digits: u8) -> String
    where
        Self: Sized,
    {
        let s = self.gen(digits).to_string();
        "0".repeat(digits as usize - s.len()) + &s
    }
}

/// Default generation options
pub trait GenerateOtpDefault {
    /// Generate 4-digit OTP as an unsigned number
    fn gen_4(self) -> u16;

    fn gen_6(self) -> u32;

    fn gen_8(self) -> u32;

    fn gen_4_str(self) -> String;

    fn gen_6_str(self) -> String;

    fn gen_8_str(self) -> String;
}

impl<T> GenerateOtpDefault for T
where
    T: GenerateOtp,
{
    #[inline]
    fn gen_4(self) -> u16 {
        self.gen(4) as u16
    }

    #[inline]
    fn gen_6(self) -> u32 {
        self.gen(6) as u32
    }

    #[inline]
    fn gen_8(self) -> u32 {
        self.gen(8) as u32
    }

    #[inline]
    fn gen_4_str(self) -> String {
        self.gen_str(4)
    }

    #[inline]
    fn gen_6_str(self) -> String {
        self.gen_str(6)
    }

    #[inline]
    fn gen_8_str(self) -> String {
        self.gen_str(8)
    }
}

