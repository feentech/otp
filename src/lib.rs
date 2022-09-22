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
fn encode_digest(digest: &[u8]) -> Result<u32, OtpError> {
    let offset = (digest.last().unwrap() & 0xf) as usize;
    let code_bytes: [u8; 4] = match digest[offset..offset + 4].try_into() {
        Ok(bytes) => bytes,
        Err(e) => return Err(OtpError::Encode(e)),
    };

    let code = u32::from_be_bytes(code_bytes);
    Ok((code & 0x7fffffff) % 1_000_000)
}

pub struct Totp {
    secret: String,
    time_step: u64,
    skew: i64,
}

pub enum OtpError {
    Time(SystemTimeError),
    Decode(DecodeError),
    Encode(TryFromSliceError),
}

impl Totp {
    pub fn new(secret: String, time_step: u64, skew: i64) -> Self {
        Totp {
            secret,
            time_step,
            skew,
        }
    }

    pub fn now(&self) -> Result<u32, OtpError> {
        let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(t) => t.as_secs(),
            Err(e) => return Err(OtpError::Time(e)),
        };

        let counter = ((now as i64 + self.skew) as u64) / self.time_step;
        let decoded = match decode_secret(&self.secret) {
            Ok(d) => d,
            Err(e) => return Err(OtpError::Decode(e)),
        };

        let totp = match encode_digest(calc_digest(decoded.as_slice(), counter).as_ref()) {
            Ok(totp) => totp,
            Err(e) => return Err(e),
        };

        Ok(totp)
    }

    pub fn verify(&self, totp_0: u32) -> Result<bool, OtpError> {
        match self.now() {
            Ok(totp_1) => Ok(totp_0 == totp_1),
            Err(e) => Err(e),
        }
    }
}
