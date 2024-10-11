use crate::{WgInterface, WgPeer};

/// Represents WG client configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgClientConf {
    pub(crate) interface: WgInterface,
    pub(crate) peers: Vec<WgPeer>,
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
