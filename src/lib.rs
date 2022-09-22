use data_encoding::BASE32_NOPAD;
use ring::hmac;
use std::time::SystemTime;

fn decode_secret(secret: &str) -> Vec<u8> {
    let secret = secret.as_bytes();
    BASE32_NOPAD.decode(secret).unwrap()
}

fn calc_digest(secret: &[u8], counter: u64) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    hmac::sign(&key, &counter.to_be_bytes())
}

fn encode_digest(digest: &[u8]) -> u32 {
    let offset = (digest.last().unwrap() & 0xf) as usize;
    let code_bytes: [u8; 4] = digest[offset..offset + 4].try_into().unwrap();
    let code = u32::from_be_bytes(code_bytes);

    (code & 0x7fffffff) % 1_000_000
}

pub struct Totp {
    secret: String,
    time_step: u64,
    skew: i64,
}

impl Totp {
    pub fn new(secret: &str, time_step: u64, skew: i64) -> Self {
        Totp {
            secret: secret.to_string(),
            time_step,
            skew,
        }
    }

    pub fn generate(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let counter = ((now as i64 + self.skew) as u64) / self.time_step;

        // generate HOTP with time based counter...
        let decoded = decode_secret(&self.secret[..]);
        encode_digest(calc_digest(decoded.as_slice(), counter).as_ref())
    }
}
