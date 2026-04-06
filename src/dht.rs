//! `dht.rs` — минимальный DHT-слой (локальный кэш/паблиш) с TTL.

use crate::PlexError;

pub const MAX_DHT_KEY_LEN: usize = 128;
pub const MAX_DHT_VALUE_LEN: usize = 64 * 1024;
pub const MAX_DHT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

pub fn validate_key(key: &str) -> Result<(), PlexError> {
    if key.trim().is_empty() {
        return Err(PlexError::Validation {
            msg: "DHT key must not be empty".into(),
        });
    }
    if key.len() > MAX_DHT_KEY_LEN {
        return Err(PlexError::Validation {
            msg: format!("DHT key too long: {} > {}", key.len(), MAX_DHT_KEY_LEN),
        });
    }
    Ok(())
}

pub fn validate_value(value: &[u8]) -> Result<(), PlexError> {
    if value.len() > MAX_DHT_VALUE_LEN {
        return Err(PlexError::Validation {
            msg: format!(
                "DHT value too large: {} > {}",
                value.len(),
                MAX_DHT_VALUE_LEN
            ),
        });
    }
    Ok(())
}

pub fn validate_ttl(ttl_secs: u64) -> Result<(), PlexError> {
    if ttl_secs == 0 {
        return Err(PlexError::Validation {
            msg: "DHT TTL must be greater than 0".into(),
        });
    }
    if ttl_secs > MAX_DHT_TTL_SECS {
        return Err(PlexError::Validation {
            msg: format!("DHT TTL too large: {} > {}", ttl_secs, MAX_DHT_TTL_SECS),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation_works() {
        assert!(validate_key("username:alice").is_ok());
        assert!(validate_key("").is_err());
    }

    #[test]
    fn value_validation_works() {
        assert!(validate_value(&vec![1u8; 1024]).is_ok());
        assert!(validate_value(&vec![0u8; MAX_DHT_VALUE_LEN + 1]).is_err());
    }

    #[test]
    fn ttl_validation_works() {
        assert!(validate_ttl(60).is_ok());
        assert!(validate_ttl(0).is_err());
        assert!(validate_ttl(MAX_DHT_TTL_SECS + 1).is_err());
    }
}
