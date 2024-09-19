use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Seek},
    path::Path,
};

use crate::{error::WgConfError, wg_interface, wg_peer, WgInterface};

const CONF_EXTENSION: &'static str = "conf";

// TODO: Add mutex

/// Represents WG configuration file
#[derive(Debug)]
pub struct WgConf {
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
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open(file_name)
            .map_err(|err| match err.kind() {
                ErrorKind::NotFound => WgConfError::NotFound(file_name.to_string()),
                _ => WgConfError::Unexpected(err.to_string()),
            })?;

        check_if_wg_conf(file_name, &mut file)?;

        Ok(WgConf {
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

        WgInterface::from_raw_key_values(interface_key_values)
    }

    /// Closes [`WgConf`] underlying file
    pub fn close(self) {
        // nothing happens, just moving the variable like in a drop func
    }

    fn interface_key_values_from_file(&mut self) -> Result<HashMap<String, String>, WgConfError> {
        seek_to_start(&mut self.conf_file, "Couldn't get interface section")?;

        let mut kv: HashMap<String, String> = HashMap::with_capacity(10);
        let mut has_peers = false;

        let mut lines_iter = BufReader::new(&mut self.conf_file).lines();
        for line in lines_iter.next() {
            match line {
                Ok(mut line) => {
                    line = line.trim().to_owned();
                    if line == "" || line.starts_with("#") || line == wg_interface::TAG {
                        continue;
                    }

                    // Stop when first [Peer] will be reached
                    if line == wg_peer::TAG {
                        has_peers = true;
                        break;
                    }

                    let (k, v) = key_value_from_raw_string(&line)?;
                    let _ = kv.insert(k, v);
                }
                Err(err) => {
                    let _ = seek_to_start(&mut self.conf_file, "Couldn't get interface section");
                    return Err(WgConfError::Unexpected(format!(
                        "Couldn't read interface: {err}"
                    )));
                }
            }
        }

        if let Ok(mut peer_start_pos) = self.conf_file.stream_position() {
            if has_peers {
                peer_start_pos = peer_start_pos - wg_peer::TAG.len() as u64 - 1;
                self.cache.peer_start_pos = Some(peer_start_pos);
            }
        }

        let _ = seek_to_start(&mut self.conf_file, "");

        Ok(kv)
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
            })? == wg_interface::TAG
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

    struct Cleanup<'a>(&'a dyn Fn() -> ());

    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = (self.0)();
        }
    }

    #[test]
    fn open_0_common_scenario() {
        // Arrange
        let test_conf_file = "wg1.conf";
        {
            let mut file = fs::File::create(test_conf_file).unwrap();
            file.write_all(INTERFACE_CONTENT.as_bytes()).unwrap();
        }

        let cleanup_fn = || {
            let _ = fs::remove_file(test_conf_file);
        };
        let _cleanup = Cleanup(&cleanup_fn);

        // Act
        let wg_conf = WgConf::open(&test_conf_file);

        // Assert
        assert!(wg_conf.is_ok())
    }

    #[test]
    fn open_0_unexistent_file_0_returns_not_found() {
        // Arrange
        let test_conf_file = "unexistent";

        // Act
        let wg_conf = WgConf::open(&test_conf_file);

        // Assert
        assert!(wg_conf.is_err());
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::NotFound)
    }

    #[test]
    fn open_0_invalid_extension_0_returns_not_wg_conf() {
        // Arrange
        let test_conf_file = "wg2.cong";
        {
            let mut file = fs::File::create(test_conf_file).unwrap();
            file.write_all(INTERFACE_CONTENT.as_bytes()).unwrap();
        }
        let cleanup_fn = || {
            let _ = fs::remove_file(test_conf_file);
        };
        let _cleanup = Cleanup(&cleanup_fn);

        // Act
        let wg_conf = WgConf::open(&test_conf_file);

        // Assert
        assert!(wg_conf.is_err());
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::NotWgConfig)
    }

    #[test]
    fn open_0_bad_interface_tag_0_returns_not_wg_conf() {
        // Arrange
        let test_conf_file = "wg3.conf";
        {
            let mut file = fs::File::create(test_conf_file).unwrap();
            file.write_all("[Interfacece]".as_bytes()).unwrap();
        }
        let cleanup_fn = || {
            let _ = fs::remove_file(test_conf_file);
        };
        let _cleanup = Cleanup(&cleanup_fn);

        // Act
        let wg_conf = WgConf::open(&test_conf_file);

        // Assert
        assert!(wg_conf.is_err());
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::NotWgConfig)
    }
}
