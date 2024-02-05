//! minotp
//!
//! Dead simple OTP library for Rust.
//!
//! License: MIT or Apache-2.0

mod hotp;

mod totp;

mod util;

pub use hotp::Hotp;
pub use totp::Totp;

pub use totp::COMMON_INTERVAL;

/// Generate OTP
pub trait GenerateOtp {
    /// Generate an OTP token as an unsigned number
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen(6); // <- here
    ///
    /// // You will get a 6-digit token as an integer
    /// assert_eq!(token, 431881);
    /// ```
    fn gen(self, digits: u8) -> u32;
    
    /// Generate an OTP token as a string
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen_str(6); // <- here
    ///
    /// // You will get a 6-digit token as a string
    /// assert_eq!(token, "431881");
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen_4(); // <- here
    ///
    /// // You will get a 4-digit token
    /// assert_eq!(token, 1881);
    /// ```
    fn gen_4(self) -> u16;

    /// Generate 6-digit OTP as an unsigned number
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen_6(); // <- here
    ///
    /// // You will get a 6-digit token
    /// assert_eq!(token, 431881);
    /// ```
    fn gen_6(self) -> u32;

    /// Generate 8-digit OTP as an unsigned number
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen_8(); // <- here
    ///
    /// // You will get an 8-digit token
    /// assert_eq!(token, 65431881);
    /// ```
    fn gen_8(self) -> u32;

    /// Generate 4-digit OTP as a string
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen_4_str(); // <- here
    ///
    /// // You will get a 4-digit token
    /// assert_eq!(token, "1881");
    /// ```
    fn gen_4_str(self) -> String;

    /// Generate 6-digit OTP as a string
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen_6_str(); // <- here
    ///
    /// // You will get a 6-digit token
    /// assert_eq!(token, "431881");
    /// ```
    fn gen_6_str(self) -> String;

    /// Generate 8-digit OTP as a string
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// let token = hotp.gen_8_str(); // <- here
    ///
    /// // You will get an 8-digit token
    /// assert_eq!(token, "65431881");
    /// ```
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

/// Verify the input token
pub trait Verify {
    /// Verify the input token as a u32
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// assert!(hotp.verify(431881, 6)); // <- here
    /// ```
    fn verify(self, input: u32, digits: u8) -> bool;

    /// Verify a token as a string slice
    ///
    /// # Examples
    ///
    /// ```
    /// use minotp::*;
    /// use sha1::Sha1;
    ///
    /// let secret = b"test";
    /// let counter = 1;
    ///
    /// let hotp = Hotp::<Sha1>::from_bytes(secret, counter).unwrap();
    ///
    /// assert!(hotp.verify_str("431881", 6)); // <- here
    /// ```
    fn verify_str(self, input: &str, digits: u8) -> bool;
}

impl<T> Verify for T
where
    T: GenerateOtp,
{

    fn verify(self, input: u32, digits: u8) -> bool {
        self.gen(digits) == input
    }

    fn verify_str(self, input: &str, digits: u8) -> bool {
        self.gen_str(digits) == input
    }
}
