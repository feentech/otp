use data_encoding::{DecodeError, BASE32_NOPAD};
use ring::hmac;
use std::array::TryFromSliceError;
use std::{time::SystemTime, time::SystemTimeError};

fn decode_secret(secret: &str) -> Result<Vec<u8>, DecodeError> {
    BASE32_NOPAD.decode(secret.as_bytes())
}

fn calc_digest(secret: &[u8], counter: u64) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    hmac::sign(&key, &counter.to_be_bytes())
}

/// this will panic if the digest provided is empty
fn encode_digest(digest: &[u8]) -> Result<u32, TryFromSliceError> {
    let offset = (digest.last().unwrap() & 0xf) as usize;
    let code_bytes: [u8; 4] = match digest[offset..offset + 4].try_into() {
        Ok(bytes) => bytes,
        Err(e) => return Err(e),
    };

    let code = u32::from_be_bytes(code_bytes);
    Ok((code & 0x7fffffff) % 1_000_000)
}

/// represent the TOTP
pub struct Totp {
    secret: String,
    time_step: u64,
    skew: i64,
}

/// possible errors returned by ```now``` and ```verify```
#[derive(Debug)]
pub enum OtpError {
    Time(SystemTimeError),
    Decode(DecodeError),
    Encode(TryFromSliceError),
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtpError::Time(t) => write!(f, "{}", t),
            OtpError::Decode(d) => write!(f, "{}", d),
            OtpError::Encode(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for OtpError {}

impl Totp {
    /// create a new ```Totp``` struct
    pub fn new(secret: String, time_step: u64, skew: i64) -> Self {
        Totp {
            secret,
            time_step,
            skew,
        }
    }

    /// get the TOTP at the provided time
    pub fn at(&self, time: SystemTime) -> Result<u32, OtpError> {
        let now = match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(t) => t.as_secs(),
            Err(e) => return Err(OtpError::Time(e)),
        };

        let counter = ((now as i64 + self.skew) as u64) / self.time_step;
        let decoded = match decode_secret(&self.secret) {
            Ok(d) => d,
            Err(e) => return Err(OtpError::Decode(e)),
        };

        let digest = calc_digest(decoded.as_slice(), counter);
        let totp = match encode_digest(digest.as_ref()) {
            Ok(totp) => totp,
            Err(e) => return Err(OtpError::Encode(e)),
        };

        Ok(totp)
    }

    /// get the TOTP at the current time
    pub fn now(&self) -> Result<u32, OtpError> {
        self.at(SystemTime::now())
    }

    /// check that the provided TOTP is correct
    pub fn verify(&self, totp_0: u32) -> Result<bool, OtpError> {
        match self.now() {
            Ok(totp_1) => Ok(totp_0 == totp_1),
            Err(e) => Err(e),
        }
    }
}
