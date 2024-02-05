# minotp

Dead simple OTP library for Rust.

License: MIT or Apache-2.0

## Usage

### Installation

Add `minotp` into your project.

```bash
cargo add minotp
```

Also the hash you want (e.g., SHA1).

```bash
cargo add sha1
```

### TOTP (commonly used)

```rust
use minotp::*;
use sha1::Sha1;

let secret = b"test";

let totp = Totp::<Sha1>::from_bytes(secret, COMMON_INTERVAL).unwrap();

// Get remaining seconds
let _remaining_seconds = totp.remaining_sec();

// Get token
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

let totp = Totp::<Sha1>::from_bytes(&secret, COMMON_INTERVAL).unwrap();

let _token = totp.gen_6_str();

// -- snip -- //
```

## Find any bug?

~~You must be kidding.~~ Fire an issue right now if you find one!
