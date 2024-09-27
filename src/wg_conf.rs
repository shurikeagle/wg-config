use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, ErrorKind, Lines, Seek, SeekFrom, Write},
    path::Path,
};

use crate::{error::WgConfError, wg_interface, wg_peer, WgConfErrKind, WgInterface, WgPeer};

const CONF_EXTENSION: &'static str = "conf";

// TODO: Add mutex maybe (one need to think about some better solution)

/// Represents WG configuration file
#[derive(Debug)]
pub struct WgConf {
    file_name: String,
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
    /// Note, that [`WgConf`] always keeps the underlying config file open till the end of ownership
    /// or untill drop() or WgConf.close() invoked
    pub fn open(file_name: &str) -> Result<WgConf, WgConfError> {
        let mut file = open_conf_file(file_name)?;

        check_if_wg_conf(file_name, &mut file)?;

        Ok(WgConf {
            file_name: file_name.to_owned(),
            conf_file: file,
            cache: WgConfCache {
                interface: None,
                peer_start_pos: None,
            },
        })
    }

    /// Gets Interface settings from [`WgConf``] file
    ///
    /// Note all the invalid lines and duplications will be ignored (the last duplication value will be got) without errors
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
        let peer_start_pos = self.peer_start_position(false)?;

        self.conf_file
            .seek(SeekFrom::Start(peer_start_pos))
            .map_err(|err| {
                WgConfError::Unexpected(format!(
                    "Couldn't set cursor to [Peer] start position: {err}"
                ))
            })?;

        Ok(WgConfPeers {
            lines: BufReader::new(&mut self.conf_file).lines(),
            next_peer_exist: false,
            first_iteration: true,
            last_err: None,
        })
    }

    /// Closes [`WgConf`] underlying file
    pub fn close(self) {
        // nothing happens, just moving the variable like in a drop func
    }

    fn interface_key_values_from_file(&mut self) -> Result<HashMap<String, String>, WgConfError> {
        seek_to_start(&mut self.conf_file, "Couldn't get interface section")?;

        let mut raw_key_values: HashMap<String, String> = HashMap::with_capacity(10);

        let mut lines_iter = BufReader::new(&mut self.conf_file).lines();

        let mut cur_position: usize = 0;
        while let Some(line) = lines_iter.next() {
            match line {
                Ok(line) => {
                    cur_position += line.len();

                    let line = line.trim().to_owned();
                    // Skip comments and empty lines
                    if line == "" || line.starts_with("#") || line == wg_interface::INTERFACE_TAG {
                        continue;
                    }

                    // Stop when the first [Peer] will be reached
                    if line == wg_peer::PEER_TAG {
                        cur_position = cur_position - wg_peer::PEER_TAG.len() - 1;
                        break;
                    }

                    let (k, v) = key_value_from_raw_string(&line)?;
                    let _ = raw_key_values.insert(k, v);
                }
                Err(err) => {
                    let _ = seek_to_start(&mut self.conf_file, "Couldn't get interface section");
                    return Err(WgConfError::Unexpected(format!(
                        "Couldn't read interface: {err}"
                    )));
                }
            }
        }

        self.cache.peer_start_pos = Some(cur_position as u64);

        let _ = seek_to_start(&mut self.conf_file, "");

        Ok(raw_key_values)
    }

    fn update_interface_in_file(mut self, interface: WgInterface) -> Result<WgConf, WgConfError> {
        let conf_file_name = self.file_name.clone();
        let tmp_file_name = conf_file_name + ".tmp";
        let mut tmp_file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&tmp_file_name)
            .map_err(|err| {
                WgConfError::Unexpected(format!(
                    "Couldn't create {}: {}",
                    &tmp_file_name,
                    err.to_string()
                ))
            })?;

        // write new interface section into tmp
        tmp_file
            .write_all(interface.to_string().as_bytes())
            .map_err(|err| {
                let _ = fs::remove_file(&tmp_file_name);

                WgConfError::Unexpected(format!(
                    "Couldn't write interface into {}: {}",
                    &tmp_file_name,
                    err.to_string()
                ))
            })?;

        // define new Peer position to set it into the cache if update will be successfull
        let updated_peer_start_pos = interface.to_string().len() as u64;

        // copy peers from current conf file to dst
        self.copy_peers(&mut tmp_file).map_err(|err| {
            let _ = fs::remove_file(&tmp_file_name);

            err
        })?;

        // replace conf by tmp
        let mut updated_conf = self
            .replace_conf_file(tmp_file, &tmp_file_name)
            .map_err(|err| {
                // keep tmp file if main file was already deleted
                if err.kind() != WgConfErrKind::CriticalKeepTmp {
                    let _ = fs::remove_file(&tmp_file_name);
                }

                err
            })?;
        updated_conf.cache.interface = Some(interface);
        updated_conf.cache.peer_start_pos = Some(updated_peer_start_pos);

        Ok(updated_conf)
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

    fn replace_conf_file(
        mut self,
        new_conf_file: File,
        new_conf_file_tmp_name: &str,
    ) -> Result<WgConf, WgConfError> {
        drop(self.conf_file);
        drop(new_conf_file);

        fs::remove_file(&self.file_name).map_err(|err| {
            WgConfError::Unexpected(format!(
                "Couldn't replace {} by tmp: {}",
                &self.file_name,
                err.to_string()
            ))
        })?;

        fs::rename(new_conf_file_tmp_name, &self.file_name).map_err(|err| {
            WgConfError::CriticalKeepTmp(format!("Couldn't rename tmp file: {}", err.to_string()))
        })?;

        let new_file = open_conf_file(&self.file_name)?;
        self.conf_file = new_file;

        Ok(self)
    }

    fn peer_start_position(&mut self, ingore_cache: bool) -> Result<u64, WgConfError> {
        if let Some(start_pos) = self.cache.peer_start_pos {
            if !ingore_cache {
                return Ok(start_pos);
            }
        }

        seek_to_start(&mut self.conf_file, "Couldn't get peer start position")?;

        let mut lines_iter = BufReader::new(&mut self.conf_file).lines();

        let mut cur_position: usize = 0;
        while let Some(line) = lines_iter.next() {
            match line {
                Ok(line) => {
                    cur_position += line.len();

                    // Stop when the first [Peer] will be reached
                    if line == wg_peer::PEER_TAG {
                        cur_position = cur_position - wg_peer::PEER_TAG.len() - 1;
                        break;
                    }
                }
                Err(err) => {
                    let _ = seek_to_start(&mut self.conf_file, "Couldn't get peer start position");
                    return Err(WgConfError::Unexpected(format!(
                        "Couldn't read up to peer start position: {err}"
                    )));
                }
            }
        }

        let cur_position = cur_position as u64;
        self.cache.peer_start_pos = Some(cur_position);

        let _ = seek_to_start(&mut self.conf_file, "");

        Ok(cur_position)
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

    seek_to_start(file, ERR_MSG)?;

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

    seek_to_start(file, ERR_MSG)?;

    res
}

/// Iterator over WgConf \[Peer\]s
pub struct WgConfPeers<'a> {
    lines: Lines<BufReader<&'a mut File>>,
    next_peer_exist: bool,
    first_iteration: bool,
    last_err: Option<WgConfError>,
}

impl Iterator for WgConfPeers<'_> {
    type Item = Result<WgPeer, WgConfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(err) = &self.last_err {
            return Some(Err(err.to_owned()));
        }

        // If we realized, that the next peer is not exist during the previous
        // iteration, return None
        if !self.first_iteration && !self.next_peer_exist {
            return None;
        }

        match self.next_peer_key_values() {
            Ok(raw_key_values) => match WgPeer::from_raw_key_values(raw_key_values) {
                Ok(peer) => Some(Ok(peer)),
                Err(err) => {
                    self.last_err = Some(err.clone());

                    return Some(Err(err));
                }
            },
            Err(err) => {
                self.last_err = Some(err.clone());

                Some(Err(err))
            }
        }
    }
}

impl WgConfPeers<'_> {
    fn next_peer_key_values(&mut self) -> Result<HashMap<String, String>, WgConfError> {
        let mut raw_key_values: HashMap<String, String> = HashMap::with_capacity(10);

        self.next_peer_exist = false;

        while let Some(line) = self.lines.next() {
            match line {
                Ok(line) => {
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
                            continue;
                        } else {
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
                            self.last_err = Some(err.clone());

                            return Err(err);
                        }
                    }
                }
                Err(err) => {
                    let err = WgConfError::Unexpected(format!("Couldn't read next peer: {err}"));
                    self.last_err = Some(err.clone());

                    return Err(err);
                }
            }
        }

        Ok(raw_key_values)
    }
}

fn open_conf_file(file_name: &str) -> Result<File, WgConfError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .open(file_name)
        .map_err(|err| match err.kind() {
            ErrorKind::NotFound => WgConfError::NotFound(file_name.to_string()),
            _ => WgConfError::Unexpected(err.to_string()),
        })
}

fn seek_to_start(file: &mut File, err_msg: &str) -> Result<(), WgConfError> {
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|err| WgConfError::Unexpected(format!("{}: {}", err_msg, err.to_string())))?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use crate::error::WgConfErrKind;

    use super::*;
    use std::{fs, io::Write};

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
    }

    #[test]
    fn peers_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg8.conf";
        let content = INTERFACE_CONTENT.to_string() + "\n" + PEER_CONTENT;

        let _cleanup = prepare_test_conf(TEST_CONF_FILE, &content);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // Act & Assert
        let peers_iter = wg_conf.peers();
        assert!(peers_iter.is_ok());

        let mut peers_iter = peers_iter.unwrap();

        let next_peer = peers_iter.next();
        match next_peer {
            Some(peer) => {
                assert!(peer.is_ok());
                let peer = peer.unwrap();

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
            None => panic!("Couldn't find the first peer"),
        }
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
