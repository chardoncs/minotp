# minotp

![GitHub Release](https://img.shields.io/github/v/release/chardon55/minotp)

Simple OTP library for Rust.

## Usage

### Installation

Add `minotp` into your project.

```bash
cargo add minotp@1
```

Also all hash libraries you want (e.g., SHA1 of [Rust Crypto](https://github.com/RustCrypto)).

```bash
cargo add sha1
```

### TOTP (commonly used)

```rust
use minotp::*;
use sha1::Sha1;

let secret = b"test";

let totp = Totp::<Sha1>::from_bytes(secret, 30).unwrap();

// Get remaining seconds
let _remaining_seconds = totp.remaining_sec();

// Get token as a 6-digit owned string
let _token = totp.gen_6_str();

// -- snip -- //
```

Use an encoding crate to decode a Base32 encoded secret
if you have to deal with one.

For example, using [`data_encoding`](https://crates.io/crates/data-encoding).

```rust
use data_encoding::BASE32;
use minotp::*;
use sha1::Sha1;

let secret_base32_str = "ORSXG5A=";

let secret = BASE32.decode(secret_base32_str.as_bytes()).unwrap();

let totp = Totp::<Sha1>::from_bytes(&secret, 30).unwrap();

let _token = totp.gen_6_str();

// -- snip -- //
```

## Found any bug?

~~You must be kidding.~~ Fire an issue right now if you found one!
