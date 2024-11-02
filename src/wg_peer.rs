use std::{collections::HashMap, fmt::Debug, net::SocketAddr};

use ipnetwork::IpNetwork;

use crate::{WgConfError, WgKey};

/// Peer tag
pub const PEER_TAG: &'static str = "[Peer]";

// Fields
const PUBLIC_KEY: &'static str = "PublicKey";
const ALLOWED_IPS: &'static str = "AllowedIPs";
const ENDPOINT: &'static str = "Endpoint";
const PRESHARED_KEY: &'static str = "PresharedKey";
const PERSISTENT_KEEPALIVE: &'static str = "PersistentKeepalive";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddrExt {
    Socket(SocketAddr),
    Domain(String)    
}

impl std::str::FromStr for SocketAddrExt {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = input.parse::<SocketAddr>() {
            return Ok(Self::Socket(ip));
        }
        Ok(Self::Domain(input.to_string()))
    }
}

impl ToString for SocketAddrExt {
    fn to_string(&self) -> String {
        match self {
            SocketAddrExt::Socket(socket_addr) => socket_addr.to_string(),
            SocketAddrExt::Domain(domain_url) => domain_url.clone(),
        }
    }
}

/// Represents WG \[Peer\] section
#[derive(Clone, PartialEq, Eq)]
pub struct WgPeer {
    pub(crate) public_key: WgKey,
    pub(crate) allowed_ips: Vec<IpNetwork>,
    pub(crate) endpoint: Option<SocketAddrExt>,
    pub(crate) preshared_key: Option<WgKey>,
    pub(crate) persistent_keepalive: Option<u16>,
}

impl Debug for WgPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeer")
            .field("public_key", &self.public_key)
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("preshared_key", &"***")
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

impl ToString for WgPeer {
    fn to_string(&self) -> String {
        let mut allowed_ips_raw = String::new();
        for (i, ip) in self.allowed_ips.iter().enumerate() {
            allowed_ips_raw += &ip.to_string();
            if i != self.allowed_ips.len() - 1 {
                allowed_ips_raw += ", ";
            }
        }

        let endpoint = match &self.endpoint {
            Some(val) => format!("\n{} = {}", ENDPOINT, val.to_string()),
            None => "".to_string(),
        };

        let preshared_key = match &self.preshared_key {
            Some(val) => format!("\n{} = {}", PRESHARED_KEY, val.to_string()),
            None => "".to_string(),
        };

        let keepalive = match self.persistent_keepalive {
            Some(val) => format!("\n{} = {}", PERSISTENT_KEEPALIVE, &val),
            None => "".to_string(),
        };

        format!(
            "{}
{} = {}
{} = {}{}{}{}
",
            PEER_TAG,
            PUBLIC_KEY,
            self.public_key.to_string(),
            ALLOWED_IPS,
            allowed_ips_raw,
            endpoint,
            preshared_key,
            keepalive
        )
    }
}

impl WgPeer {
    /// Creates new [`WgPeer`]
    pub fn new(
        public_key: WgKey,
        allowed_ips: Vec<IpNetwork>,
        endpoint: Option<SocketAddrExt>,
        preshared_key: Option<WgKey>,
        persistent_keepalive: Option<u16>,
    ) -> WgPeer {
        WgPeer {
            public_key,
            allowed_ips,
            endpoint,
            preshared_key,
            persistent_keepalive,
        }
    }

    pub fn from_raw_values(
        public_key: String,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
        preshared_key: Option<String>,
        persistent_keepalive: Option<String>,
    ) -> Result<WgPeer, WgConfError> {
        let public_key: WgKey = public_key.parse()?;

        let allowed_ips: Result<Vec<IpNetwork>, WgConfError> = allowed_ips
            .iter()
            .map(|ip| {
                ip.parse::<IpNetwork>().map_err(|_| {
                    WgConfError::ValidationFailed(
                        "allowed IPs must be addresses with mask (e.g. 10.0.0.1/8)".to_string(),
                    )
                })
            })
            .collect();
        let allowed_ips = allowed_ips?;

        let endpoint: Option<SocketAddrExt> = endpoint
            .map(|endpoint| {
                endpoint.parse().map_err(|_| {
                    WgConfError::ValidationFailed("invalid endpoint raw value".to_string())
                })
            })
            .transpose()?;

        let preshared_key: Option<WgKey> = preshared_key
            .map(|key| {
                key.parse().map_err(|_| {
                    WgConfError::ValidationFailed("invalid preshared key raw value".to_string())
                })
            })
            .transpose()?;

        let persistent_keepalive: Option<u16> = persistent_keepalive
            .map(|p| {
                p.parse().map_err(|_| {
                    WgConfError::ValidationFailed(
                        "invalid persistent keepalive raw value".to_string(),
                    )
                })
            })
            .transpose()?;

        Ok(WgPeer::new(
            public_key,
            allowed_ips,
            endpoint,
            preshared_key,
            persistent_keepalive,
        ))
    }

    // getters
    pub fn public_key(&self) -> &WgKey {
        &self.public_key
    }
    pub fn allowed_ips(&self) -> &[IpNetwork] {
        &self.allowed_ips
    }
    pub fn endpoint(&self) -> Option<&SocketAddrExt> {
        self.endpoint.as_ref()
    }
    pub fn preshared_key(&self) -> Option<&WgKey> {
        self.preshared_key.as_ref()
    }
    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.persistent_keepalive
    }

    pub(crate) fn from_raw_key_values(
        raw_key_values: HashMap<String, String>,
    ) -> Result<WgPeer, WgConfError> {
        let mut public_key = String::new();
        let mut allowed_ips = Vec::<String>::new();
        let mut endpoint: Option<String> = None;
        let mut preshared_key: Option<String> = None;
        let mut persistent_keepalive: Option<String> = None;

        for (k, v) in raw_key_values {
            match k {
                _ if k == PUBLIC_KEY => public_key = v,
                _ if k == ALLOWED_IPS => {
                    let ips: Vec<&str> = v.split(", ").collect();
                    for ip in ips {
                        allowed_ips.push(ip.to_string());
                    }
                }
                _ if k == ENDPOINT => endpoint = Some(v),
                _ if k == PRESHARED_KEY => preshared_key = Some(v),
                _ if k == PERSISTENT_KEEPALIVE => persistent_keepalive = Some(v),
                _ => continue,
            }
        }

        WgPeer::from_raw_values(
            public_key,
            allowed_ips,
            endpoint,
            preshared_key,
            persistent_keepalive,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wg_peer_0_to_string_0_all_fields() {
        // Arrange
        let peer = WgPeer::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .parse()
                .unwrap(),
            vec![
                "10.0.0.1/32".parse().unwrap(),
                "10.0.0.2/32".parse().unwrap(),
            ],
            Some("127.0.0.2:8080".parse().unwrap()),
            Some(
                "6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8="
                    .parse()
                    .unwrap(),
            ),
            Some(25),
        );

        // Act
        let peer_raw = peer.to_string();

        // Assert
        assert_eq!(
            "[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32, 10.0.0.2/32
Endpoint = 127.0.0.2:8080
PresharedKey = 6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8=
PersistentKeepalive = 25
",
            peer_raw
        );
    }

    #[test]
    fn wg_peer_0_to_string_0_single_ip() {
        // Arrange
        let peer = WgPeer::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .parse()
                .unwrap(),
            vec!["10.0.0.1/32".parse().unwrap()],
            Some("127.0.0.2:8080".parse().unwrap()),
            Some(
                "6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8="
                    .parse()
                    .unwrap(),
            ),
            Some(25),
        );

        // Act
        let peer_raw = peer.to_string();

        // Assert
        assert_eq!(
            "[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32
Endpoint = 127.0.0.2:8080
PresharedKey = 6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8=
PersistentKeepalive = 25
",
            peer_raw
        );
    }

    #[test]
    fn wg_peer_0_to_string_0_empty_optionals() {
        // Arrange
        let peer = WgPeer::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .parse()
                .unwrap(),
            vec![
                "10.0.0.1/32".parse().unwrap(),
                "10.0.0.2/32".parse().unwrap(),
            ],
            None,
            None,
            None,
        );

        // Act
        let peer_raw = peer.to_string();

        // Assert
        assert_eq!(
            "[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32, 10.0.0.2/32
",
            peer_raw
        );
    }
}
