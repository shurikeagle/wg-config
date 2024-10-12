# wg-config
Current crate provides WireGuard .conf files management (creation and edition) for 'server' and 'client' peers' generation. This crate <u>doesn't</u> provide the functionality of WireGuard itself except key generation. Key generation in fact uses WireGuard CLI commands to avoid insecure self implementation, so, it requires WireGuard installed (applicable for Windows too). Key generation is enabled with `wg_engine` default feature. 

The crate may be used in utils to simplify WireGuard management or in web apps that provide interface for WG.

[crates.io](https://crates.io/crates/wg-config)

### WgConf entity
The 'entrypoint' of this crate is [WgConf](https://docs.rs/wg-config/latest/wg_config/struct.WgConf.html) which represents 'server' .conf file. Almost all the functionality of the crate is provided with this entity. 

### WgConf Peers
`WgConf` has `peers()` method which returns [WgConfPeers](https://docs.rs/wg-config/latest/wg_config/struct.WgConfPeers.html) iterator which is more optimal in case of many peers in server's config. After using this iterator one should to check if `WgConfPeer.err()` is None or `== WgConfErrKind::EOF`. Yes, it may look a bit uncomfortable, but it much better in case of filtering predicats to check `WgPeer` itself intead of `Result<WgPeer, WgConfError>`

### Parallel access
Now there aren't any thread and process safety mechanism for accessing `WgConf` yet, meanwhile it should be for consistency, e.g. in web apps where a few administrators may edit conf file in parallel. Some kind of optimistic-like blocking will be implemented in time, but now, it's crate consumer's app responsibility to implement them if required. 

### Errors
This crate in case of errors returns different types of [WgConfError](https://docs.rs/wg-config/latest/wg_config/enum.WgConfError.html). The error may be checked with `.kind()` method which returns [WgConfErrKind](https://docs.rs/wg-config/latest/wg_config/enum.WgConfErrKind.html).

### Examples 
Examples of usage and logic restrictions may be viewed in tests and also in `Quick start` below

#### Quick start
Remember, all the functions which are using key generation (includes `generate_peer`) require WireGuard installed.

```rust
// Generate private key for server
let private_key = WgKey::generate_private_key().unwrap();

// Create server's interface
let interface = WgInterface::new(
            private_key,
            "10.0.0.1/24".parse().unwrap(), // 10.0.0.1-255 network
            Some(8082), // listen port
            None, // no default dns for peers
            Some("ufw allow 8082/udp".to_string()), // allow 8082 when WG is started
            Some("ufw delete allow 8082/udp".to_string()),
        )
        .unwrap();

// Create wg0.conf file
let wg_conf = WgConf::create("/etc/wireguard/wg0.conf", interface, None); // None as we haven't got peers yet

// Generate new peer (which will be added to wg0.conf file straightaway on generation)
let wg_client_conf = wg_conf.generate_peer(
            "10.0.0.2".parse().unwrap(), // 10.0.0.2/32 will be used for this peer
            "192.168.130.131".parse().unwrap(), // public endpoint of server
            vec!["0.0.0.0/0".parse().unwrap()], // all the traffic will be sent through the server
            Some("192.168.130.131".parse().unwrap()), // server is also DNS
            true, // generate preshared key for additional security
            Some(20), // 20 sec persistent keep alive
        ).unwrap();

// Client's configuration which may be saved as file, sent with email, etc.
let raw_client_conf = wg_client_conf.to_string();

// Get added peer from conf file
let wg_peer = wg_conf.peers().first().unwrap();

// Remove peer
let remove_res = wg_conf.remove_peer_by_pub_key(wg_peer.public_key());
```
