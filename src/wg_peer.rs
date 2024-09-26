use std::net::IpAddr;

use ipnetwork::IpNetwork;

use crate::{WgConfError, WgKey};

/// Peer tag
pub const PEER_TAG: &'static str = "[Peer]";

// Fields
const PUBLIC_KEY: &'static str = "PublicKey";
const ALLOWED_IPS: &'static str = "AllowedIPs";
const PRESHARED_KEY: &'static str = "PresharedKey";
const PERSISTENT_KEEPALIVE: &'static str = "PersistentKeepalive";
const DNS: &'static str = "DNS";

/// Represents WG \[Peer\] section
pub struct WgPeer {
    pub(crate) public_key: WgKey,
    pub(crate) allowed_ips: Vec<IpNetwork>,
    pub(crate) preshared_key: Option<WgKey>,
    pub(crate) persistent_keepalive: Option<u16>,
    pub(crate) dns: Option<IpAddr>,
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

        let preshared_key = match &self.preshared_key {
            Some(val) => format!("\n{} = {}", PRESHARED_KEY, val.to_string()),
            None => "".to_string(),
        };

        let keepalive = match self.persistent_keepalive {
            Some(val) => format!("\n{} = {}", PERSISTENT_KEEPALIVE, &val),
            None => "".to_string(),
        };

        let dns = match &self.dns {
            Some(val) => format!("\n{} = {}", DNS, &val),
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
            preshared_key,
            keepalive,
            dns
        )
    }
}

impl WgPeer {
    /// Creates new [`WgPeer`]
    pub fn new(
        public_key: WgKey,
        allowed_ips: Vec<IpNetwork>,
        preshared_key: Option<WgKey>,
        persistent_keepalive: Option<u16>,
        dns: Option<IpAddr>,
    ) -> WgPeer {
        WgPeer {
            public_key,
            allowed_ips,
            preshared_key,
            persistent_keepalive,
            dns,
        }
    }

    pub fn from_raw_values(
        public_key: String,
        allowed_ips: Vec<String>,
        preshared_key: Option<String>,
        persistent_keepalive: Option<String>,
        dns: Option<String>,
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

        let dns: Option<IpAddr> = dns
            .map(|dns| {
                dns.parse().map_err(|_| {
                    WgConfError::ValidationFailed("dns must have ip address format".to_string())
                })
            })
            .transpose()?;

        Ok(WgPeer::new(
            public_key,
            allowed_ips,
            preshared_key,
            persistent_keepalive,
            dns,
        ))
    }

    // getters
    pub fn public_key(&self) -> &WgKey {
        &self.public_key
    }
    pub fn allowed_ips(&self) -> &[IpNetwork] {
        &self.allowed_ips
    }
    pub fn preshared_key(&self) -> Option<&WgKey> {
        self.preshared_key.as_ref()
    }
    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.persistent_keepalive
    }
    pub fn dns(&self) -> Option<&IpAddr> {
        self.dns.as_ref()
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
            Some(
                "6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8="
                    .parse()
                    .unwrap(),
            ),
            Some(25),
            Some("8.8.8.8".parse().unwrap()),
        );

        // Act
        let peer_raw = peer.to_string();

        // Assert
        assert_eq!(
            "[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32, 10.0.0.2/32
PresharedKey = 6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8=
PersistentKeepalive = 25
DNS = 8.8.8.8
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
            Some(
                "6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8="
                    .parse()
                    .unwrap(),
            ),
            Some(25),
            Some("8.8.8.8".parse().unwrap()),
        );

        // Act
        let peer_raw = peer.to_string();

        // Assert
        assert_eq!(
            "[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32
PresharedKey = 6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8=
PersistentKeepalive = 25
DNS = 8.8.8.8
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
            Some("8.8.8.8".parse().unwrap()),
        );

        // Act
        let peer_raw = peer.to_string();

        // Assert
        assert_eq!(
            "[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32, 10.0.0.2/32
DNS = 8.8.8.8
",
            peer_raw
        );
    }
}
