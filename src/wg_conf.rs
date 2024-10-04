use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{self, BufRead, BufReader, Lines, Seek, SeekFrom, Write},
    path::Path,
};

use crate::{
    error::WgConfError,
    fileworks::{self, open_file_w_all_permissions},
    wg_interface, wg_peer, WgConfErrKind, WgInterface, WgKey, WgPeer,
};

const CONF_EXTENSION: &'static str = "conf";

// TODO: Add process-safety mechanism (think about some optimistic concurrency approach or add OS lock at least)

/// Represents WG configuration file
#[derive(Debug)]
pub struct WgConf {
    conf_file_name: String,
    conf_file: File,
    cache: WgConfCache,
}

#[derive(Debug)]
struct WgConfCache {
    interface: Option<WgInterface>,
    peer_start_pos: Option<u64>,
}

impl WgConf {
    /// Initializes [`WgConf``] from existing file
    ///
    /// Returns [`WgConfError::ValidationFailed`] if file validation is failed or [`WgConfError::Unexpected`] with details if other (fs) error occurred
    ///
    /// **Note**, that [`WgConf`] always keeps the underlying config file open till the end of ownership
    /// or untill drop() or WgConf.close() invoked
    pub fn open(file_name: &str) -> Result<WgConf, WgConfError> {
        let mut file = fileworks::open_file_w_all_permissions(file_name)?;

        check_if_wg_conf(file_name, &mut file)?;

        Ok(WgConf {
            conf_file_name: file_name.to_owned(),
            conf_file: file,
            cache: WgConfCache {
                interface: None,
                peer_start_pos: None,
            },
        })
    }

    /// Creates new [`WgConf``] with underlying file
    ///
    /// **Note**, that [`WgConf`] always keeps the underlying config file open till the end of ownership
    /// or untill drop() or WgConf.close() invoked
    pub fn create(
        file_name: &str,
        interface: WgInterface,
        peers: Option<Vec<WgPeer>>,
    ) -> Result<WgConf, WgConfError> {
        {
            let _ = File::create_new(file_name).map_err(|err| match err.kind() {
                io::ErrorKind::AlreadyExists => {
                    WgConfError::AlreadyExists(format!("WG config file '{}'", file_name))
                }
                _ => WgConfError::Unexpected(format!("Couldn't create WG config file: {}", err)),
            })?;
        }

        let mut conf_file = open_file_w_all_permissions(file_name).map_err(|err| {
            let _ = fs::remove_file(file_name);

            err
        })?;

        let peer_start_pos = write_interface_to_file(&mut conf_file, file_name, &interface)
            .map_err(|err| {
                let _ = fs::remove_file(file_name);

                err
            })?;

        if let Some(peers) = peers {
            write_peers_to_file(&mut conf_file, file_name, peers).map_err(|err| {
                let _ = fs::remove_file(file_name);

                err
            })?;
        }

        let _ = fileworks::seek_to_start(&mut conf_file, "");

        Ok(WgConf {
            conf_file,
            conf_file_name: file_name.to_owned(),
            cache: WgConfCache {
                interface: Some(interface),
                peer_start_pos: Some(peer_start_pos),
            },
        })
    }

    /// Gets Interface settings from [`WgConf``] file
    ///
    /// Note all the not related to \[Interface\] key-values and duplications will be ignored (the last duplication value will be got) without errors
    pub fn interface(&mut self) -> Result<WgInterface, WgConfError> {
        if let Some(interface) = &self.cache.interface {
            return Ok(interface.clone());
        }

        let interface_key_values = self.interface_key_values_from_file()?;

        let interface = WgInterface::from_raw_key_values(interface_key_values)?;
        self.cache.interface = Some(interface.clone());

        Ok(interface)
    }

    /// Updates \[Interface\] section in [`WgConf`] file
    pub fn update_interface(self, new_inteface: WgInterface) -> Result<WgConf, WgConfError> {
        if let Some(cached_interface) = &self.cache.interface {
            if *cached_interface == new_inteface {
                return Ok(self);
            }
        }

        self.update_interface_in_file(new_inteface)
    }

    /// Returns iterator over WG config Peers
    pub fn peers(&mut self) -> Result<WgConfPeers, WgConfError> {
        let peer_start_position = self.peer_start_position(false)?;

        self.conf_file
            .seek(SeekFrom::Start(peer_start_position))
            .map_err(|err| {
                WgConfError::Unexpected(format!(
                    "Couldn't set cursor to [Peer] start position: {err}"
                ))
            })?;

        Ok(WgConfPeers {
            err: None,
            lines: BufReader::new(&mut self.conf_file).lines(),
            next_peer_exist: false,
            first_iteration: true,
            peer_start_position,
            cur_position: peer_start_position,
            cur_peer_start_position: None,
            cur_peer_end_position: None,
        })
    }

    /// Adds \[Peer\] to WG config file
    pub fn add_peer(&mut self, peer: WgPeer) -> Result<(), WgConfError> {
        self.conf_file.seek(SeekFrom::End(0)).map_err(|err| {
            WgConfError::Unexpected(format!("Couldn't set cursor to the end of the file: {err}"))
        })?;

        // Check peer with provided peer is not exist
        let mut peers = self.peers()?;
        let existing_peer = peers.find(|p| p.public_key() == peer.public_key());
        peers.check_err()?;
        if let Some(_) = existing_peer {
            return Err(WgConfError::AlreadyExists(format!(
                "Peer with public key '{}'",
                &peer.public_key.to_string()
            )));
        }

        let content = peer.to_string() + "\n";
        self.conf_file
            .write_all(content.as_bytes())
            .map_err(|err| {
                WgConfError::Unexpected(format!("Couldn't write peer to the file: {err}"))
            })?;

        Ok(())
    }

    pub fn remove_peer_by_pub_key(mut self, public_key: &WgKey) -> Result<WgConf, WgConfError> {
        let mut peers = self.peers()?;

        // find target peer
        let target_peer = peers.find(|p| p.public_key() == public_key);
        peers.check_err()?;
        if let None = target_peer {
            return Err(WgConfError::NotFound(format!(
                "Peer with public key '{}'",
                public_key.to_string()
            )));
        }

        // as target peer found, iterator sets current peer's start & end positions
        let start_peer_pos = peers
            .cur_peer_start_position
            .ok_or(WgConfError::Unexpected(
                "Couldn't define target peer start position".to_string(),
            ))?;
        let end_peer_pos = peers.cur_peer_end_position.ok_or(WgConfError::Unexpected(
            "Couldn't define target peer end position".to_string(),
        ))?;

        drop(peers);

        let (tmp_file_name, mut tmp_file) = fileworks::create_tmp_file(&self.conf_file_name)?;

        let _ = fileworks::copy_bytes_except(
            &mut self.conf_file,
            &mut tmp_file,
            start_peer_pos,
            end_peer_pos,
            "Couldn't copy config file to tmp",
        )
        .map_err(|err| {
            let _ = fs::remove_file(&tmp_file_name);

            err
        })?;

        let new_wg_conf_file = fileworks::replace_file(
            tmp_file,
            &tmp_file_name,
            self.conf_file,
            &self.conf_file_name,
        )
        .map_err(|err| {
            // keep tmp file if main file was already deleted
            if err.kind() != WgConfErrKind::CriticalKeepTmp {
                let _ = fs::remove_file(&tmp_file_name);
            }

            err
        })?;

        self.conf_file = new_wg_conf_file;

        Ok(self)
    }

    /// Closes [`WgConf`] underlying file
    pub fn close(self) {
        // nothing happens, just moving the variable like in a drop func
    }

    fn interface_key_values_from_file(&mut self) -> Result<HashMap<String, String>, WgConfError> {
        fileworks::seek_to_start(&mut self.conf_file, "Couldn't get interface section")?;

        let mut raw_key_values: HashMap<String, String> = HashMap::with_capacity(10);

        let mut lines_iter = BufReader::new(&mut self.conf_file).lines();

        let mut cur_position: usize = 0;
        while let Some(line) = lines_iter.next() {
            match line {
                Ok(line) => {
                    cur_position += line.len() + 1; // +1 for EOL

                    let line = line.trim().to_owned();
                    // Skip comments and empty lines
                    if line == "" || line.starts_with("#") || line == wg_interface::INTERFACE_TAG {
                        continue;
                    }

                    // Stop when the first [Peer] will be reached
                    if line == wg_peer::PEER_TAG {
                        cur_position = cur_position - wg_peer::PEER_TAG.len() - 1; // -1 for EOL
                        break;
                    }

                    let (k, v) = key_value_from_raw_string(&line)?;
                    let _ = raw_key_values.insert(k, v);
                }
                Err(err) => {
                    let _ = fileworks::seek_to_start(
                        &mut self.conf_file,
                        "Couldn't get interface section",
                    );
                    return Err(WgConfError::Unexpected(format!(
                        "Couldn't read interface: {err}"
                    )));
                }
            }
        }

        self.cache.peer_start_pos = Some(cur_position as u64);

        let _ = fileworks::seek_to_start(&mut self.conf_file, "");

        Ok(raw_key_values)
    }

    fn update_interface_in_file(mut self, interface: WgInterface) -> Result<WgConf, WgConfError> {
        let (tmp_file_name, mut tmp_file) = fileworks::create_tmp_file(&self.conf_file_name)?;

        // write new interface section into tmp
        let updated_peer_start_pos =
            write_interface_to_file(&mut tmp_file, &tmp_file_name, &interface)?;

        // copy peers from current conf file to dst
        self.copy_peers(&mut tmp_file).map_err(|err| {
            let _ = fs::remove_file(&tmp_file_name);

            err
        })?;

        // replace conf by tmp
        let new_wg_conf_file = fileworks::replace_file(
            tmp_file,
            &tmp_file_name,
            self.conf_file,
            &self.conf_file_name,
        )
        .map_err(|err| {
            // keep tmp file if main file was already deleted
            if err.kind() != WgConfErrKind::CriticalKeepTmp {
                let _ = fs::remove_file(&tmp_file_name);
            }

            err
        })?;

        self.conf_file = new_wg_conf_file;
        self.cache.interface = Some(interface);
        self.cache.peer_start_pos = Some(updated_peer_start_pos);

        Ok(self)
    }

    fn copy_peers(&mut self, mut dst_file: &File) -> Result<(), WgConfError> {
        // define start position in src to copy
        let src_peer_start_pos = self.peer_start_position(false)?;

        // set position to copy only Peer section
        self.conf_file
            .seek(SeekFrom::Start(src_peer_start_pos))
            .map_err(|err| {
                WgConfError::Unexpected(format!("Couldn't copy peers to tmp: {}", err.to_string()))
            })?;

        // copy to dst
        io::copy(&mut self.conf_file, &mut dst_file).map_err(|err| {
            WgConfError::Unexpected(format!("Couldn't copy peers to tmp: {}", err.to_string()))
        })?;

        Ok(())
    }

    fn peer_start_position(&mut self, ingore_cache: bool) -> Result<u64, WgConfError> {
        if let Some(start_pos) = self.cache.peer_start_pos {
            if !ingore_cache {
                return Ok(start_pos);
            }
        }

        fileworks::seek_to_start(&mut self.conf_file, "Couldn't get peer start position")?;

        let mut lines_iter = BufReader::new(&mut self.conf_file).lines();

        let mut cur_position: usize = 0;
        while let Some(line) = lines_iter.next() {
            match line {
                Ok(line) => {
                    cur_position += line.len() + 1; // +1 for EOL

                    // Stop when the first [Peer] will be reached
                    if line == wg_peer::PEER_TAG {
                        cur_position = cur_position - wg_peer::PEER_TAG.len() - 1; // -1 for EOL
                        break;
                    }
                }
                Err(err) => {
                    let _ = fileworks::seek_to_start(
                        &mut self.conf_file,
                        "Couldn't get peer start position",
                    );
                    return Err(WgConfError::Unexpected(format!(
                        "Couldn't read up to peer start position: {err}"
                    )));
                }
            }
        }

        let cur_position = cur_position as u64;
        self.cache.peer_start_pos = Some(cur_position);

        let _ = fileworks::seek_to_start(&mut self.conf_file, "");

        Ok(cur_position)
    }
}

/// Iterator over WgConf \[Peer\]s.
///
/// **Note** that iterator returns `None` if any error occurred, so,
/// one should to invoke `self.check_err()` to ensure that iterations were successfull while using the iterator
pub struct WgConfPeers<'a> {
    err: Option<WgConfError>,
    lines: Lines<BufReader<&'a mut File>>,
    next_peer_exist: bool,
    first_iteration: bool,
    peer_start_position: u64,
    cur_position: u64,
    cur_peer_start_position: Option<u64>,
    cur_peer_end_position: Option<u64>,
}

impl Iterator for WgConfPeers<'_> {
    type Item = WgPeer;

    /// Note all the not related to \[Peer\] key-values and duplications will be ignored (the last duplication value will be got) without errors
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(_) = &self.err {
            return None;
        }

        // If we realized, that the next peer is not exist during the previous
        // iteration, return None
        if !self.first_iteration && !self.next_peer_exist {
            return None;
        }

        match self.next_peer_key_values() {
            Ok(raw_key_values) => {
                if raw_key_values.len() == 0 {
                    return None;
                }

                match WgPeer::from_raw_key_values(raw_key_values) {
                    Ok(peer) => Some(peer),
                    Err(err) => {
                        self.err = Some(err);

                        return None;
                    }
                }
            }
            Err(err) => {
                self.err = Some(err);

                None
            }
        }
    }
}

impl WgConfPeers<'_> {
    /// Returns iterator's error
    ///
    /// May be EOF which is successfull case
    pub fn err(&mut self) -> Option<WgConfError> {
        self.err.clone()
    }

    /// Ensures that iterator hasn't got any error except [WgConfError::EOF]
    pub fn check_err(&mut self) -> Result<(), WgConfError> {
        if let Some(err) = &self.err {
            if err.kind() != WgConfErrKind::EOF {
                return Err(err.clone());
            }
        }

        Ok(())
    }

    fn next_peer_key_values(&mut self) -> Result<HashMap<String, String>, WgConfError> {
        let mut raw_key_values: HashMap<String, String> = HashMap::with_capacity(10);

        self.next_peer_exist = false;

        if !self.first_iteration {
            self.cur_peer_start_position =
                Some(self.cur_position - wg_peer::PEER_TAG.len() as u64 - 1);
        }

        while let Some(line) = self.lines.next() {
            match line {
                Ok(line) => {
                    self.cur_position += line.len() as u64 + 1; // +1 for EOL

                    let line = line.trim().to_owned();
                    // Skip comments and empty lines
                    if line == "" || line.starts_with("#") {
                        continue;
                    }

                    if line == wg_peer::PEER_TAG {
                        // current section's peer tag will be found only in the first iteration,
                        // in the next iteration the coursor position will be after it as it was read in the prev iteration,
                        // so, in all iterations except the frst one peer tag means the end of the current iteration
                        if self.first_iteration {
                            self.cur_peer_start_position = Some(self.peer_start_position);
                            continue;
                        } else {
                            self.cur_peer_end_position =
                                Some(self.cur_position - wg_peer::PEER_TAG.len() as u64 - 1); // -1 for EOL
                            self.next_peer_exist = true;
                            break;
                        }
                    }

                    self.first_iteration = false;

                    match key_value_from_raw_string(&line) {
                        Ok((k, v)) => {
                            let _ = raw_key_values.insert(k, v);
                        }
                        Err(err) => {
                            self.err = Some(err.clone());

                            return Err(err);
                        }
                    }
                }
                Err(err) => {
                    let err = WgConfError::Unexpected(format!("Couldn't read next peer: {err}"));
                    self.err = Some(err.clone());

                    return Err(err);
                }
            }
        }

        if !self.next_peer_exist {
            self.cur_peer_end_position = Some(self.cur_position);
            self.err = Some(WgConfError::EOF);
        }

        Ok(raw_key_values)
    }
}

/// Checks if provided file is WG config
///
/// Returns [`WgConfError::NotWgConfig`] if checks failed
pub fn check_if_wg_conf(file_name: &str, file: &mut File) -> Result<(), WgConfError> {
    const ERR_MSG: &'static str = "Couldn't define if file is WG config";

    if Path::new(file_name).extension().unwrap_or(&OsStr::new("")) != CONF_EXTENSION {
        return Err(WgConfError::NotWgConfig("invalid extension".to_string()));
    }

    fileworks::seek_to_start(file, ERR_MSG)?;

    let mut lines_iter = BufReader::new(&mut *file).lines();
    let res = match lines_iter.next() {
        Some(first_line) => {
            if first_line.map_err(|err| {
                WgConfError::Unexpected(format!("{}: {}", ERR_MSG, err.to_string()))
            })? == wg_interface::INTERFACE_TAG
            {
                Ok(())
            } else {
                Err(WgConfError::NotWgConfig(
                    "couldn't find [Interface] section".to_string(),
                ))
            }
        }
        None => Err(WgConfError::NotWgConfig("file is empty".to_string())),
    };

    fileworks::seek_to_start(file, ERR_MSG)?;

    res
}

fn key_value_from_raw_string(raw_string: &str) -> Result<(String, String), WgConfError> {
    if !raw_string.contains('=') {
        return Err(WgConfError::Unexpected(format!(
            "'{raw_string}' is not key-value string"
        )));
    }

    let key_value: Vec<&str> = raw_string.splitn(2, '=').collect();
    let key = key_value[0].trim();
    let mut value = "";
    if key_value.len() == 2 {
        value = key_value[1].trim();
    }

    return Ok((key.to_owned(), value.to_owned()));
}

/// Returns peer start position
fn write_interface_to_file(
    file: &mut File,
    file_name: &str,
    interface: &WgInterface,
) -> Result<u64, WgConfError> {
    let interface_to_write = interface.to_string() + "\n";
    file.write_all(interface_to_write.as_bytes())
        .map_err(|err| {
            let _ = fs::remove_file(file_name);

            WgConfError::Unexpected(format!(
                "Couldn't write interface into {}: {}",
                file_name,
                err.to_string()
            ))
        })?;

    // define new Peer position to set it into the cache if update will be successfull
    Ok(interface_to_write.len() as u64)
}

fn write_peers_to_file(
    file: &mut File,
    file_name: &str,
    peers: Vec<WgPeer>,
) -> Result<(), WgConfError> {
    let peer_len = peers.len();
    if peer_len == 0 {
        return Ok(());
    }

    // TODO: May be dangerous for big files, it's better to implement batch logic
    let approximate_cap = peer_len * 200;
    let mut peers_str = String::with_capacity(approximate_cap);

    for peer in peers.iter() {
        let peer_str = peer.to_string() + "\n";
        peers_str.push_str(&peer_str);
    }

    file.write_all(peers_str.as_bytes()).map_err(|err| {
        let _ = fs::remove_file(file_name);

        WgConfError::Unexpected(format!(
            "Couldn't write peers into {}: {}",
            file_name,
            err.to_string()
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::error::WgConfErrKind;

    use super::*;
    use std::{fs, io::Write, net::IpAddr, str::FromStr};

    const INTERFACE_CONTENT: &'static str = "[Interface]
PrivateKey = 4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=
Address = 10.0.0.1/24
ListenPort = 8080
PostUp = ufw allow 8080/udp
PostDown = ufw delete allow 8080/udp
";

    const PEER_CONTENT: &'static str = "[Peer]
PublicKey = LyXP6s7mzMlrlcZ5STONcPwTQFOUJuD8yQg6FYDeTzE=
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4=
AllowedIPs = 10.0.0.3/32, 10.0.0.4/32
PresharedKey = 4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=
PersistentKeepalive = 25
DNS = 8.8.8.8
";

    struct Deferred(pub Box<dyn Fn() -> ()>);

    impl Drop for Deferred {
        fn drop(&mut self) {
            let _ = (self.0)();
        }
    }

    #[test]
    fn open_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg1.conf";
        let _cleanup = prepare_test_conf(TEST_CONF_FILE, INTERFACE_CONTENT);

        // Act
        let wg_conf = WgConf::open(TEST_CONF_FILE);

        // Assert
        assert!(wg_conf.is_ok())
    }

    #[test]
    fn open_0_unexistent_file_0_returns_not_found() {
        // Arrange
        const TEST_CONF_FILE: &str = "unexistent";

        // Act
        let wg_conf = WgConf::open(TEST_CONF_FILE);

        // Assert
        assert!(wg_conf.is_err());
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::NotFound)
    }

    #[test]
    fn open_0_invalid_extension_0_returns_not_wg_conf() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg2.cong";
        let _cleanup = prepare_test_conf(TEST_CONF_FILE, INTERFACE_CONTENT);

        // Act
        let wg_conf = WgConf::open(TEST_CONF_FILE);

        // Assert
        assert!(wg_conf.is_err());
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::NotWgConfig)
    }

    #[test]
    fn open_0_bad_interface_tag_0_returns_not_wg_conf() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg3.conf";
        let _cleanup = prepare_test_conf(TEST_CONF_FILE, "[Interfacece]");

        // Act
        let wg_conf = WgConf::open(TEST_CONF_FILE);

        // Assert
        assert!(wg_conf.is_err());
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::NotWgConfig)
    }

    #[test]
    fn interface_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg4.conf";
        let _cleanup = prepare_test_conf(TEST_CONF_FILE, INTERFACE_CONTENT);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // Act
        let interface = wg_conf.interface();

        // Assert
        assert!(interface.is_ok());
        let interface = interface.unwrap();
        assert_eq!(
            "4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=",
            interface.private_key.to_string()
        );
        assert_eq!("10.0.0.1/24", interface.address.to_string());
        assert_eq!(8080, interface.listen_port);
        assert_eq!(Some("ufw allow 8080/udp"), interface.post_up());
        assert_eq!(Some("ufw delete allow 8080/udp"), interface.post_down());
        assert!(wg_conf.cache.interface.is_some());
        assert!(wg_conf.cache.peer_start_pos.is_some());
    }

    #[test]
    fn interface_0_empty_double_not_interface_kv_0_returns_ok() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg5.conf";
        const CONTENT: &str = "[Interface]
    ttt = eee
PrivateKey = 4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=

Address = 10.0.0.1/24
ListenPort = 8080
Address = 10.0.0.1/24


# ttst
abctest = def
PostUp = ufw allow 8080/udp";
        let _cleanup = prepare_test_conf(TEST_CONF_FILE, CONTENT);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // Act
        let interface = wg_conf.interface();

        // Assert
        assert!(interface.is_ok());
        let interface = interface.unwrap();
        assert_eq!(
            "4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=",
            interface.private_key.to_string()
        );
        assert_eq!("10.0.0.1/24", interface.address.to_string());
        assert_eq!(8080, interface.listen_port);
        assert_eq!(Some("ufw allow 8080/udp"), interface.post_up());
        assert_eq!(None, interface.post_down());
    }

    #[test]
    fn interface_0_not_key_value_lines_0_returns_unexpected_err() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg6.conf";
        const CONTENT: &str = "[Interface]
    ttt = eee
PrivateKey
";
        let _cleanup = prepare_test_conf(TEST_CONF_FILE, CONTENT);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // Act
        let interface = wg_conf.interface();

        // Assert
        assert!(interface.is_err());
        let err = interface.unwrap_err();
        assert!(err.kind() == WgConfErrKind::Unexpected);
        assert!(err.to_string().contains("not key-value"));
    }

    #[test]
    fn update_interface_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg7.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT;

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // invoke to set peer start position cache
        let _ = wg_conf.interface();
        let old_peer_pos = wg_conf.cache.peer_start_pos.unwrap();

        let new_interface = WgInterface::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .to_string()
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
        let updated_conf = wg_conf.update_interface(new_interface.clone());
        assert!(updated_conf.is_ok());
        let mut updated_conf = updated_conf.unwrap();
        let interface_by_method = updated_conf.interface();

        // Assert
        let cur_peer_start_pos = updated_conf.cache.peer_start_pos.unwrap();
        assert_ne!(old_peer_pos, cur_peer_start_pos);
        assert!(interface_by_method.is_ok());
        let interface_by_method = interface_by_method.unwrap();
        assert_eq!(new_interface, interface_by_method);
        assert_eq!(2, updated_conf.peers().unwrap().count());
    }

    #[test]
    fn peers_iter_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg8.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT;

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();
        let mut peers_iter = wg_conf.peers().unwrap();

        // Act
        let peer1 = peers_iter.next();
        let peer2 = peers_iter.next();
        let peer3 = peers_iter.next();

        // Assert
        match peer1 {
            Some(peer) => {
                assert!(peers_iter.check_err().is_ok());

                assert_eq!(
                    "LyXP6s7mzMlrlcZ5STONcPwTQFOUJuD8yQg6FYDeTzE=",
                    peer.public_key.to_string()
                );
                assert_eq!(1, peer.allowed_ips.len());
                assert_eq!("10.0.0.2/32", peer.allowed_ips[0].to_string());
                assert!(peer.preshared_key.is_none());
                assert!(peer.persistent_keepalive.is_none());
                assert!(peer.dns.is_none());
            }
            None => panic!("Couldn't get the first peer"),
        }

        match peer2 {
            Some(peer) => {
                assert!(peers_iter.check_err().is_ok());

                assert_eq!(
                    "Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4=",
                    peer.public_key.to_string()
                );
                assert_eq!(2, peer.allowed_ips.len());
                assert_eq!("10.0.0.3/32", peer.allowed_ips[0].to_string());
                assert_eq!("10.0.0.4/32", peer.allowed_ips[1].to_string());
                assert!(peer.preshared_key.is_some());
                assert_eq!(
                    "4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=",
                    peer.preshared_key.unwrap().to_string()
                );
                assert!(peer.persistent_keepalive.is_some());
                assert_eq!(25, peer.persistent_keepalive.unwrap());
                assert!(peer.dns.is_some());
                assert_eq!("8.8.8.8", peer.dns.unwrap().to_string());
            }
            None => panic!("Couldn't get the second peer"),
        }

        assert_eq!(WgConfErrKind::EOF, peers_iter.err().unwrap().kind());
        assert!(peer3.is_none());
    }

    #[test]
    fn peers_iter_0_no_peers_0_returns_no_err() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg9.conf";
        let content = INTERFACE_CONTENT.to_string();

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();
        let mut peers_iter = wg_conf.peers().unwrap();

        // Act
        let peer = peers_iter.next();

        // Assert
        assert!(peer.is_none());
    }

    #[test]
    fn peers_iter_0_every_iter_0_keeps_same_error() {
        // Arrange
        const BAD_AND_GOOD_PEER_CONTENT: &'static str = "[Peer]
PublicKey = NotWGkey=
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4=
AllowedIPs = 10.0.0.3/32, 10.0.0.4/32
PresharedKey = 4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=
PersistentKeepalive = 25
DNS = 8.8.8.8
";
        const TEST_CONF_FILE: &str = "wg10.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + BAD_AND_GOOD_PEER_CONTENT;

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();
        let mut peers_iter = wg_conf.peers().unwrap();

        // Act & Assert
        let peer1 = peers_iter.next();
        assert!(peer1.is_none());
        assert_eq!(
            WgConfErrKind::ValidationFailed,
            peers_iter.check_err().unwrap_err().kind()
        );

        let peer2 = peers_iter.next();
        assert!(peer2.is_none());
        assert_eq!(
            WgConfErrKind::ValidationFailed,
            peers_iter.check_err().unwrap_err().kind()
        );
    }

    #[test]
    fn add_peer_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg11.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT + "\n";

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

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // Act
        let res = wg_conf.add_peer(peer.clone());
        let count = wg_conf.peers().unwrap().count();
        let peers_iter = wg_conf.peers().unwrap();
        let last_peer = peers_iter.last();

        // Assert
        assert!(res.is_ok());
        assert_eq!(3, count);
        assert!(last_peer.is_some());
        let last_peer = last_peer.unwrap();
        assert_eq!(peer, last_peer);
    }

    #[test]
    fn add_peer_0_already_exists() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg12.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT + "\n";
        let peer = WgPeer::new(
            "Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4="
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

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // Act
        let res = wg_conf.add_peer(peer);

        // Assert
        assert_eq!(WgConfErrKind::AlreadyExists, res.err().unwrap().kind());
    }

    #[test]
    fn remove_peer_by_pub_key_0_first_peer() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg13.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT + "\n";

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();
        let target_key: WgKey = "LyXP6s7mzMlrlcZ5STONcPwTQFOUJuD8yQg6FYDeTzE="
            .parse()
            .unwrap();

        // Act & Assert
        let res = wg_conf.remove_peer_by_pub_key(&target_key);
        assert!(res.is_ok());

        let mut wg_conf = res.unwrap();

        let mut peers_iter = wg_conf.peers().unwrap();
        let existing_peer = peers_iter.next();
        match existing_peer {
            Some(peer) => {
                assert!(peers_iter.check_err().is_ok());

                assert_eq!(
                    "Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4=",
                    peer.public_key.to_string()
                );
                assert_eq!(2, peer.allowed_ips.len());
                assert_eq!("10.0.0.3/32", peer.allowed_ips[0].to_string());
                assert_eq!("10.0.0.4/32", peer.allowed_ips[1].to_string());
                assert!(peer.preshared_key.is_some());
                assert_eq!(
                    "4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=",
                    peer.preshared_key.unwrap().to_string()
                );
                assert!(peer.persistent_keepalive.is_some());
                assert_eq!(25, peer.persistent_keepalive.unwrap());
                assert!(peer.dns.is_some());
                assert_eq!("8.8.8.8", peer.dns.unwrap().to_string());
            }
            None => panic!("Couldn't get peer after removing the previous one"),
        }

        assert!(peers_iter.next().is_none());
    }

    #[test]
    fn remove_peer_by_pub_key_0_last_peer() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg14.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT + "\n";

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();
        let target_key: WgKey = "Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4="
            .parse()
            .unwrap();

        // Act & Assert
        let res = wg_conf.remove_peer_by_pub_key(&target_key);
        assert!(res.is_ok());

        let mut wg_conf = res.unwrap();

        let mut peers_iter = wg_conf.peers().unwrap();
        let existing_peer = peers_iter.next();
        match existing_peer {
            Some(peer) => {
                assert!(peers_iter.check_err().is_ok());

                assert_eq!(
                    "LyXP6s7mzMlrlcZ5STONcPwTQFOUJuD8yQg6FYDeTzE=",
                    peer.public_key.to_string()
                );
                assert_eq!(1, peer.allowed_ips.len());
                assert_eq!("10.0.0.2/32", peer.allowed_ips[0].to_string());
                assert!(peer.preshared_key.is_none());
                assert!(peer.persistent_keepalive.is_none());
                assert!(peer.dns.is_none());
            }
            None => panic!("Couldn't get peer after removing the previous one"),
        }

        assert!(peers_iter.next().is_none());
    }

    #[test]
    fn remove_peer_by_pub_key_0_middle_peer() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg15.conf";

        const ADDITIONAL_PEER: &str = "[Peer]
PublicKey = 4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=
AllowedIPs = 10.0.0.5/32
PersistentKeepalive = 10
DNS = 0.0.0.0
";
        let content =
            INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT + "\n" + ADDITIONAL_PEER + "\n";

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();
        let target_key: WgKey = "4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c="
            .parse()
            .unwrap();

        // Act & Assert
        let res = wg_conf.remove_peer_by_pub_key(&target_key);
        assert!(res.is_ok());

        let mut wg_conf = res.unwrap();

        let mut peers_iter = wg_conf.peers().unwrap();

        let peer1 = peers_iter.next();
        match peer1 {
            Some(peer) => {
                assert!(peers_iter.check_err().is_ok());

                assert_eq!(
                    "LyXP6s7mzMlrlcZ5STONcPwTQFOUJuD8yQg6FYDeTzE=",
                    peer.public_key.to_string()
                );
                assert_eq!(1, peer.allowed_ips.len());
                assert_eq!("10.0.0.2/32", peer.allowed_ips[0].to_string());
                assert!(peer.preshared_key.is_none());
                assert!(peer.persistent_keepalive.is_none());
                assert!(peer.dns.is_none());
            }
            None => panic!("Couldn't get peer after removing the previous one"),
        }

        let peer2 = peers_iter.next();
        match peer2 {
            Some(peer) => {
                assert!(peers_iter.check_err().is_ok());

                assert_eq!(
                    "Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4=",
                    peer.public_key.to_string()
                );
                assert_eq!(2, peer.allowed_ips.len());
                assert_eq!("10.0.0.3/32", peer.allowed_ips[0].to_string());
                assert_eq!("10.0.0.4/32", peer.allowed_ips[1].to_string());
                assert!(peer.preshared_key.is_some());
                assert_eq!(
                    "4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=",
                    peer.preshared_key.unwrap().to_string()
                );
                assert!(peer.persistent_keepalive.is_some());
                assert_eq!(25, peer.persistent_keepalive.unwrap());
                assert!(peer.dns.is_some());
                assert_eq!("8.8.8.8", peer.dns.unwrap().to_string());
            }
            None => panic!("Couldn't get peer after removing the previous one"),
        }

        let peer3 = peers_iter.next();
        assert_eq!(WgConfErrKind::EOF, peers_iter.err().unwrap().kind());
        assert!(peer3.is_none());
    }

    #[test]
    fn remove_peer_by_pub_key_0_unexistent() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg16.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT + "\n";

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();
        let target_key: WgKey = "Rrr2pT8pOvcEKdp1KptvUi8OO/fYIWnkVcnXJ3dtUE4="
            .parse()
            .unwrap();

        // Act
        let res = wg_conf.remove_peer_by_pub_key(&target_key);

        // Assert
        assert_eq!(WgConfErrKind::NotFound, res.unwrap_err().kind());
    }

    #[test]
    fn create_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg17.conf";
        let interface = WgInterface::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .to_string()
                .parse()
                .unwrap(),
            "192.168.130.131/25".parse().unwrap(),
            8082,
            None,
            Some("some-script".to_string()),
            Some("some-other-script".to_string()),
        )
        .unwrap();

        let peers = vec![
            WgPeer::new(
                "Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4="
                    .parse()
                    .unwrap(),
                vec!["10.0.0.1/32".parse().unwrap()],
                Some(
                    "LyXP6s7mzMlrlcZ5STONcPwTQFOUJuD8yQg6FYDeTzE="
                        .parse()
                        .unwrap(),
                ),
                Some(25),
                Some("8.8.8.8".parse().unwrap()),
            ),
            WgPeer::new(
                "4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c="
                    .parse()
                    .unwrap(),
                vec!["10.0.0.1/32".parse().unwrap()],
                None,
                None,
                None,
            ),
        ];

        let cleanup_fn = || {
            let _ = fs::remove_file(TEST_CONF_FILE.to_owned());
        };

        let _cleanup = Deferred(Box::new(cleanup_fn));

        // Act
        let wg_conf = WgConf::create(TEST_CONF_FILE, interface, Some(peers));

        // Assert
        assert!(wg_conf.is_ok());
        let wg_conf = wg_conf.unwrap();
        assert!(wg_conf.cache.interface.is_some());
        assert!(wg_conf.cache.peer_start_pos.is_some());
        assert!(fs::exists(TEST_CONF_FILE).unwrap());
        let mut lines =
            BufReader::new(open_file_w_all_permissions(TEST_CONF_FILE).unwrap()).lines();
        assert!(lines.any(|l| l.is_ok()
            && l.unwrap()
                .contains("6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=")));
        assert!(lines.any(|l| l.is_ok()
            && l.unwrap()
                .contains("Rrr2pT8pOvcEKdp1KpsvUi8OO/fYIWnkVcnXJ3dtUE4=")));
        assert!(lines.any(|l| l.is_ok()
            && l.unwrap()
                .contains("4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=")));
    }

    #[test]
    fn create_0_doesnt_overwrite() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg18.conf";
        let content = INTERFACE_CONTENT.to_string();
        let interface = WgInterface::new(
            "6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8="
                .to_string()
                .parse()
                .unwrap(),
            "192.168.130.131/25".parse().unwrap(),
            8082,
            None,
            Some("some-script".to_string()),
            Some("some-other-script".to_string()),
        )
        .unwrap();

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);

        // Act
        let wg_conf = WgConf::create(TEST_CONF_FILE, interface, None);

        // Assert
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::AlreadyExists);
        let mut lines =
            BufReader::new(open_file_w_all_permissions(TEST_CONF_FILE).unwrap()).lines();
        assert!(lines.any(|l| l.is_ok()
            && l.unwrap()
                .contains("4DIjxC8pEzYZGvLLEbzHRb2dCxiyAOAfx9dx/NMlL2c=")));
        assert!(!lines.any(|l| l.is_ok()
            && l.unwrap()
                .contains("6FyM4Sq5zanp+9UPXIygLJQBYvlLsfF5lYcrSoa3CX8=")));
    }

    fn prepare_test_conf(conf_name: &'static str, content: &str) -> Deferred {
        {
            let mut file = fs::File::create(conf_name).unwrap();
            file.write_all(content.as_bytes()).unwrap();
        }

        let cleanup_fn = || {
            let _ = fs::remove_file(conf_name.to_owned());
        };

        Deferred(Box::new(cleanup_fn))
    }
}
