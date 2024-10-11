use crate::{WgInterface, WgPeer};

/// Represents WG client configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgClientConf {
    pub(crate) interface: WgInterface,
    pub(crate) peers: Vec<WgPeer>,
}

impl ToString for WgClientConf {
    fn to_string(&self) -> String {
        let mut str = self.interface().to_string();

        for peer in self.peers() {
            str = str + "\n" + &peer.to_string();
        }

        str
    }
}

impl WgClientConf {
    /// Creates new [`WgClientConf`]
    pub fn new(interface: WgInterface, peers: Vec<WgPeer>) -> WgClientConf {
        WgClientConf { interface, peers }
    }

    // getters
    pub fn interface(&self) -> &WgInterface {
        &self.interface
    }
    pub fn peers(&self) -> &[WgPeer] {
        &self.peers
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use super::*;

    #[test]
    fn to_string() {
        // Assert
        let interface = WgInterface::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .parse()
                .unwrap(),
            "192.168.130.131/25".parse().unwrap(),
            Some(8082),
            Some(IpAddr::from_str("8.8.8.8").unwrap()),
            Some("some-script".to_string()),
            Some("some-other-script".to_string()),
        )
        .unwrap();

        let peer1 = WgPeer::new(
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

        let peer2 = WgPeer::new(
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

        let client_conf = WgClientConf::new(interface, vec![peer1, peer2]);

        // Act
        let conf_raw = client_conf.to_string();

        // Assert
        assert_eq!(
            "[Interface]
PrivateKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
Address = 192.168.130.131/25
ListenPort = 8082
DNS = 8.8.8.8
PostUp = some-script
PostDown = some-other-script

[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32, 10.0.0.2/32
Endpoint = 127.0.0.2:8080
PresharedKey = 6FyM4Sq5zanp+9UOXIygLJQBYvlLsfF5lYcrSoa3CX8=
PersistentKeepalive = 25

[Peer]
PublicKey = 6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=
AllowedIPs = 10.0.0.1/32, 10.0.0.2/32
",
            &conf_raw
        )
    }
}
