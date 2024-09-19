use std::{collections::HashMap, str::FromStr};

use ipnetwork::IpNetwork;

use crate::{WgConfError, WgPrivateKey};

/// Interface tag
pub const TAG: &'static str = "[Interface]";

/// Represents WG [Interface] section
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgInterface {
    private_key: WgPrivateKey,
    address: IpNetwork,
    listen_port: u16,
    post_up: String,
    post_down: String,
}

impl WgInterface {
    /// Creates new [`WgInterface`]
    ///
    /// Note, that WG address is address with mask (e.g. 10.0.0.1/8)
    pub fn new(
        private_key: String,
        address: String,
        listen_port: u16,
        post_up: String,
        post_down: String,
    ) -> Result<WgInterface, WgConfError> {
        let private_key: WgPrivateKey = private_key.parse()?;

        let address: IpNetwork = address.parse().map_err(|_| {
            WgConfError::ValidationFailed(format!(
                "address must be address with mask (e.g. 10.0.0.1/8)"
            ))
        })?;

        if listen_port == 0 {
            return Err(WgConfError::ValidationFailed("port can't be 0".to_string()));
        }

        Ok(WgInterface {
            private_key,
            address,
            listen_port,
            post_up,
            post_down,
        })
    }

    pub(crate) fn from_raw_key_values(
        raw_key_values: HashMap<String, String>,
    ) -> Result<WgInterface, WgConfError> {
        let mut private_key = String::new();
        let mut address = String::new();
        let mut listen_port: u16 = 0;
        let mut post_up = String::new();
        let mut post_down = String::new();

        for (k, v) in raw_key_values {
            match k {
                _ if k == "PrivateKey" => private_key = v,
                _ if k == "Address" => address = v,
                _ if k == "ListenPort" => {
                    let port: u16 = v.parse().map_err(|_| {
                        WgConfError::ValidationFailed("invalid port raw value".to_string())
                    })?;
                    listen_port = port
                }
                _ if k == "PostUp" => post_up = v,
                _ if k == "PostDown" => post_down = v,
                _ => continue,
            }
        }

        todo!();
        Err(WgConfError::ConfFileClosed)
    }
}
