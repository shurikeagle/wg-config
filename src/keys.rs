use std::str::FromStr;

use base64::Engine;

use crate::WgConfError;

/// WG key (private, public or preshared)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgKey {
    key: String,
}

impl ToString for WgKey {
    fn to_string(&self) -> String {
        self.key.clone()
    }
}

impl FromStr for WgKey {
    type Err = WgConfError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        WgKey::validate(s)?;

        Ok(WgKey { key: s.to_owned() })
    }
}

impl Default for WgKey {
    fn default() -> Self {
        Self {
            key: "".to_string(),
        }
    }
}

impl WgKey {
    /// Validates if input string is WG key
    pub fn validate(input: &str) -> Result<(), WgConfError> {
        // WG keys should be 44 characters long (32 bytes base64-encoded).
        if input.len() != 44 {
            return Err(WgConfError::ValidationFailed(
                "invalid encoded WG key length".to_string(),
            ));
        }

        let decoded_key = base64::prelude::BASE64_STANDARD
            .decode(input)
            .map_err(|_| WgConfError::ValidationFailed("WG key is not valid base64".to_string()))?;

        // decoded key should has 32 byte length
        if decoded_key.len() != 32 {
            return Err(WgConfError::ValidationFailed(
                "WG key is not valid base64".to_string(),
            ));
        }

        Ok(())
    }
}
