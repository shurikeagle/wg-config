use std::str::FromStr;
#[cfg(feature = "wg_engine")]
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

use base64::Engine;

use crate::WgConfError;

/// WG key (private, public or preshared)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgKey {
    pub(crate) key: String,
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

    /// Generates private key using WG
    ///
    /// **Note**, this function requires WG installed
    #[cfg(feature = "wg_engine")]
    pub fn generate_private_key() -> Result<WgKey, WgConfError> {
        generate_key(false)
    }

    /// Generates preshared key using WG
    ///
    /// **Note**, this function requires WG installed
    #[cfg(feature = "wg_engine")]
    pub fn generate_preshared_key() -> Result<WgKey, WgConfError> {
        generate_key(true)
    }

    /// Generates public key from private using WG
    ///
    /// **Note**, this function requires WG installed
    #[cfg(feature = "wg_engine")]
    pub fn generate_public_key(private_key: &WgKey) -> Result<WgKey, WgConfError> {
        let mut pubkey_proc = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| couldnt_generate_pub_key(err.to_string()))?;

        // write private key into stdin
        pubkey_proc
            .stdin
            .take()
            .unwrap() // we've always have it as we've spawned it above
            .write_all(private_key.to_string().as_bytes())
            .map_err(|err| couldnt_generate_pub_key(err.to_string()))?;

        let pubkey_output = pubkey_proc
            .wait_with_output()
            .map_err(|err| couldnt_generate_pub_key(err.to_string()))?;

        check_stderr(&pubkey_output)?;

        parse_key(&pubkey_output.stdout)
    }
}

#[cfg(feature = "wg_engine")]
fn check_stderr(output: &Output) -> Result<(), WgConfError> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        return Err(WgConfError::WgEngineError(stderr.to_string()));
    }

    Ok(())
}

#[cfg(feature = "wg_engine")]
fn parse_key(key_bytes: &Vec<u8>) -> Result<WgKey, WgConfError> {
    String::from_utf8_lossy(key_bytes)
        .trim()
        .to_string()
        .parse()
}

#[cfg(feature = "wg_engine")]
fn couldnt_generate_pub_key(details: String) -> WgConfError {
    WgConfError::WgEngineError(format!("Couldn't generate public key: {}", details))
}

#[cfg(feature = "wg_engine")]
fn generate_key(genpsk: bool) -> Result<WgKey, WgConfError> {
    let (cmd, err_msg) = match genpsk {
        true => ("genpsk", "preshared"),
        false => ("genkey", "private"),
    };

    let genkey_output = Command::new("wg").arg(cmd).output().map_err(|err| {
        WgConfError::WgEngineError(format!(
            "Couldn't generate {} key: {}",
            err.to_string(),
            err_msg
        ))
    })?;

    check_stderr(&genkey_output)?;

    parse_key(&genkey_output.stdout)
}

#[cfg(test)]
#[cfg(feature = "wg_engine")]
mod tests {
    use super::*;

    #[test]
    fn generate_private_key() {
        let pkey = WgKey::generate_private_key();

        assert!(pkey.is_ok())
    }

    #[test]
    fn generate_preshared_key() {
        let psk = WgKey::generate_preshared_key();

        assert!(psk.is_ok())
    }

    #[test]
    fn generate_public_key() {
        let pkey: WgKey = "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
            .parse()
            .unwrap();
        let pubkey = WgKey::generate_public_key(&pkey);

        assert!(pubkey.is_ok())
    }
}
