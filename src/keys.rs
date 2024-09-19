use std::str::FromStr;

use base64::Engine;

use crate::WgConfError;

/// WG private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPrivateKey {
    key: String,
}

impl ToString for WgPrivateKey {
    fn to_string(&self) -> String {
        self.key.clone()
    }
}

impl FromStr for WgPrivateKey {
    type Err = WgConfError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        WgPrivateKey::validate(s)?;

        Ok(WgPrivateKey { key: s.to_owned() })
    }
}

impl Default for WgPrivateKey {
    fn default() -> Self {
        Self {
            key: "".to_string(),
        }
    }
}

impl WgPrivateKey {
    /// Validates if input string is WG private key
    pub fn validate(input: &str) -> Result<(), WgConfError> {
        // WG private keys should be 44 characters long (32 bytes base64-encoded).
        if input.len() != 44 {
            return Err(WgConfError::ValidationFailed(
                "invalid encoded private key length".to_string(),
            ));
        }

        let decoded_key = base64::prelude::BASE64_STANDARD
            .decode(input)
            .map_err(|_| {
                WgConfError::ValidationFailed("private key is not valid base64".to_string())
            })?;

        // decoded key should has 32 byte length
        if decoded_key.len() != 32 {
            return Err(WgConfError::ValidationFailed(
                "private key is not valid base64".to_string(),
            ));
        }

        Ok(())
    }
}
