use std::{collections::HashMap, net::IpAddr, str::FromStr};

use ipnetwork::IpNetwork;

use crate::{WgConfError, WgKey};

/// Interface tag
pub const INTERFACE_TAG: &'static str = "[Interface]";

// Fields
const PRIVATE_KEY: &'static str = "PrivateKey";
const ADDRESS: &'static str = "Address";
const LISTEN_PORT: &'static str = "ListenPort";
const DNS: &'static str = "DNS";
const POST_UP: &'static str = "PostUp";
const POST_DOWN: &'static str = "PostDown";

/// Represents WG \[Interface\] section
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgInterface {
    pub(crate) private_key: WgKey,
    pub(crate) address: IpNetwork,
    pub(crate) listen_port: u16,
    pub(crate) dns: Option<IpAddr>,
    pub(crate) post_up: Option<String>,
    pub(crate) post_down: Option<String>,
}

impl ToString for WgInterface {
    fn to_string(&self) -> String {
        let dns = match &self.dns {
            Some(val) => format!("\n{} = {}", DNS, val.to_string()),
            None => "".to_string(),
        };

        let post_up = match self.post_up.as_deref() {
            Some(val) => format!("\n{} = {}", POST_UP, val),
            None => "".to_string(),
        };

        let post_down = match self.post_down.as_deref() {
            Some(val) => format!("\n{} = {}", POST_DOWN, &val),
            None => "".to_string(),
        };

        format!(
            "{}
{} = {}
{} = {}
{} = {}{}{}{}
",
            INTERFACE_TAG,
            PRIVATE_KEY,
            self.private_key.to_string(),
            ADDRESS,
            self.address.to_string(),
            LISTEN_PORT,
            self.listen_port,
            dns,
            post_up,
            post_down
        )
    }
}

impl WgInterface {
    /// Creates new [`WgInterface`]
    pub fn new(
        private_key: WgKey,
        address: IpNetwork,
        listen_port: u16,
        dns: Option<IpAddr>,
        post_up: Option<String>,
        post_down: Option<String>,
    ) -> Result<WgInterface, WgConfError> {
        if listen_port == 0 {
            return Err(WgConfError::ValidationFailed("port can't be 0".to_string()));
        }

        Ok(WgInterface {
            private_key,
            address,
            listen_port,
            dns,
            post_up,
            post_down,
        })
    }

    /// Creates new [`WgInterface`] from raw String values
    ///
    /// Note, that WG address is address with mask (e.g. 10.0.0.1/8)
    pub fn from_raw_values(
        private_key: String,
        address: String,
        listen_port: String,
        dns: Option<String>,
        post_up: Option<String>,
        post_down: Option<String>,
    ) -> Result<WgInterface, WgConfError> {
        let private_key: WgKey = private_key.parse()?;

        let address: IpNetwork = address.parse().map_err(|_| {
            WgConfError::ValidationFailed(
                "address must be address with mask (e.g. 10.0.0.1/8)".to_string(),
            )
        })?;

        let listen_port: u16 = listen_port
            .parse()
            .map_err(|_| WgConfError::ValidationFailed("invalid port raw value".to_string()))?;

        if listen_port == 0 {
            return Err(WgConfError::ValidationFailed("port can't be 0".to_string()));
        }

        let dns = dns
            .map(|dns| {
                IpAddr::from_str(&dns).map_err(|_| {
                    WgConfError::ValidationFailed("dns must be an ip address".to_string())
                })
            })
            .transpose()?;

        Ok(WgInterface {
            private_key,
            address,
            listen_port,
            dns,
            post_up,
            post_down,
        })
    }

    // getters
    pub fn private_key(&self) -> &WgKey {
        &self.private_key
    }
    pub fn address(&self) -> &IpNetwork {
        &self.address
    }
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }
    pub fn dns(&self) -> Option<IpAddr> {
        self.dns
    }
    pub fn post_up(&self) -> Option<&str> {
        self.post_up.as_deref()
    }
    pub fn post_down(&self) -> Option<&str> {
        self.post_down.as_deref()
    }

    pub(crate) fn from_raw_key_values(
        raw_key_values: HashMap<String, String>,
    ) -> Result<WgInterface, WgConfError> {
        let mut private_key = String::new();
        let mut address = String::new();
        let mut listen_port: String = String::new();
        let mut dns: Option<String> = None;
        let mut post_up: Option<String> = None;
        let mut post_down: Option<String> = None;

        for (k, v) in raw_key_values {
            match k {
                _ if k == PRIVATE_KEY => private_key = v,
                _ if k == ADDRESS => address = v,
                _ if k == LISTEN_PORT => listen_port = v,
                _ if k == DNS => dns = Some(v),
                _ if k == POST_UP => post_up = Some(v),
                _ if k == POST_DOWN => post_down = Some(v),
                _ => continue,
            }
        }

        WgInterface::from_raw_values(private_key, address, listen_port, dns, post_up, post_down)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wg_interface_0_to_string_0_all_fields() {
        // Assert
        let interface = WgInterface::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .parse()
                .unwrap(),
            "192.168.130.131/25".parse().unwrap(),
            8082,
            Some(IpAddr::from_str("8.8.8.8").unwrap()),
            Some("some-script".to_string()),
            Some("some-other-script".to_string()),
        )
        .unwrap();

        // Act
        let interf_raw = interface.to_string();

        // Assert
        assert_eq!(
            "[Interface]
PrivateKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
Address = 192.168.130.131/25
ListenPort = 8082
DNS = 8.8.8.8
PostUp = some-script
PostDown = some-other-script
",
            &interf_raw
        )
    }

    #[test]
    fn wg_interface_0_to_string_0_empty_optionals() {
        // Assert
        let interface = WgInterface::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .parse()
                .unwrap(),
            "192.168.130.131/25".parse().unwrap(),
            8082,
            None,
            None,
            None,
        )
        .unwrap();

        // Act
        let interf_raw = interface.to_string();

        // Assert
        assert_eq!(
            "[Interface]
PrivateKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
Address = 192.168.130.131/25
ListenPort = 8082
",
            &interf_raw
        )
    }
}
