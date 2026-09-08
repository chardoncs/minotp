//! minotp

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
    /// let token = hotp.generate(6); // <- here
    ///
    /// // You will get a 6-digit token as an integer
    /// assert_eq!(token, 431881);
    /// ```
    ///
    /// # Note
    ///
    /// Renamed from `gen` since `gen` became a reserved keyword
    /// in the Rust 2024 edition.
    /// Other `gen_*` methods of this crate were renamed to
    /// `generate_*` accordingly.
    fn generate(self, digits: u8) -> u32;

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
    /// let token = hotp.generate_str(6); // <- here
    ///
    /// // You will get a 6-digit token as a string
    /// assert_eq!(token, "431881");
    /// ```
    fn generate_str(self, digits: u8) -> String
    where
        Self: Sized,
    {
        let s = self.generate(digits).to_string();
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
    /// let token = hotp.generate_4(); // <- here
    ///
    /// // You will get a 4-digit token
    /// assert_eq!(token, 1881);
    /// ```
    fn generate_4(self) -> u16;

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
    /// let token = hotp.generate_6(); // <- here
    ///
    /// // You will get a 6-digit token
    /// assert_eq!(token, 431881);
    /// ```
    fn generate_6(self) -> u32;

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
    /// let token = hotp.generate_8(); // <- here
    ///
    /// // You will get an 8-digit token
    /// assert_eq!(token, 65431881);
    /// ```
    fn generate_8(self) -> u32;

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
    /// let token = hotp.generate_4_str(); // <- here
    ///
    /// // You will get a 4-digit token
    /// assert_eq!(token, "1881");
    /// ```
    fn generate_4_str(self) -> String;

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
    /// let token = hotp.generate_6_str(); // <- here
    ///
    /// // You will get a 6-digit token
    /// assert_eq!(token, "431881");
    /// ```
    fn generate_6_str(self) -> String;

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
    /// let token = hotp.generate_8_str(); // <- here
    ///
    /// // You will get an 8-digit token
    /// assert_eq!(token, "65431881");
    /// ```
    fn generate_8_str(self) -> String;
}

impl<T> GenerateOtpDefault for T
where
    T: GenerateOtp,
{
    #[inline]
    fn generate_4(self) -> u16 {
        self.generate(4) as u16
    }

    #[inline]
    fn generate_6(self) -> u32 {
        self.generate(6)
    }

    #[inline]
    fn generate_8(self) -> u32 {
        self.generate(8)
    }

    #[inline]
    fn generate_4_str(self) -> String {
        self.generate_str(4)
    }

    #[inline]
    fn generate_6_str(self) -> String {
        self.generate_str(6)
    }

    #[inline]
    fn generate_8_str(self) -> String {
        self.generate_str(8)
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
        self.generate(digits) == input
    }

    fn verify_str(self, input: &str, digits: u8) -> bool {
        self.generate_str(digits) == input
    }
}
