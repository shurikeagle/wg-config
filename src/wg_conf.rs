use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Seek},
    path::Path,
};

use crate::{error::WgConfError, wg_interface, wg_peer, WgInterface};

const CONF_EXTENSION: &'static str = "conf";

// TODO: Add mutex maybe (one need to think about better solution)

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

        let interface = WgInterface::from_raw_key_values(interface_key_values)?;
        self.cache.interface = Some(interface.clone());

        Ok(interface)
    }

    /// Closes [`WgConf`] underlying file
    pub fn close(self) {
        // nothing happens, just moving the variable like in a drop func
    }

    fn interface_key_values_from_file(&mut self) -> Result<HashMap<String, String>, WgConfError> {
        seek_to_start(&mut self.conf_file, "Couldn't get interface section")?;

        let mut kv: HashMap<String, String> = HashMap::with_capacity(10);

        let mut lines_iter = BufReader::new(&mut self.conf_file).lines();

        let mut cur_position: u64 = 0;
        while let Some(line) = lines_iter.next() {
            match line {
                Ok(mut line) => {
                    cur_position += line.len() as u64;

                    line = line.trim().to_owned();
                    if line == "" || line.starts_with("#") || line == wg_interface::TAG {
                        continue;
                    }

                    // Stop when the first [Peer] will be reached
                    if line == wg_peer::TAG {
                        cur_position = cur_position - wg_peer::TAG.len() as u64 - 1;
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

        self.cache.peer_start_pos = Some(cur_position);

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

[Peer]
PostUp = ufw allow 8080/udp
PostDown = ufw delete allow 8080/udp
";

    struct Cleanup(Box<dyn Fn() -> ()>);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = (self.0)();
        }
    }

    #[test]
    fn open_0_common_scenario() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg1.conf";
        let _cleanup = prepare_test_conf(&TEST_CONF_FILE, INTERFACE_CONTENT);

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
        let wg_conf = WgConf::open(&TEST_CONF_FILE);

        // Assert
        assert!(wg_conf.is_err());
        assert!(wg_conf.unwrap_err().kind() == WgConfErrKind::NotFound)
    }

    #[test]
    fn open_0_invalid_extension_0_returns_not_wg_conf() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg2.cong";
        let _cleanup = prepare_test_conf(&TEST_CONF_FILE, INTERFACE_CONTENT);

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
        let _cleanup = prepare_test_conf(&TEST_CONF_FILE, INTERFACE_CONTENT);
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
        assert_eq!("ufw allow 8080/udp", interface.post_up);
        assert_eq!("ufw delete allow 8080/udp", interface.post_down);
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
PostDown = ufw delete allow 8080/udp
Address = 10.0.0.1/24


# ttst
abctest = def
PostUp = ufw allow 8080/udp";
        let _cleanup = prepare_test_conf(&TEST_CONF_FILE, CONTENT);
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
        assert_eq!("ufw allow 8080/udp", interface.post_up);
        assert_eq!("ufw delete allow 8080/udp", interface.post_down);
    }

    #[test]
    fn interface_0_not_key_value_lines_0_returns_unexpected_err() {
        // Arrange
        const TEST_CONF_FILE: &str = "wg6.conf";
        const CONTENT: &str = "[Interface]
    ttt = eee
PrivateKey
";
        let _cleanup = prepare_test_conf(&TEST_CONF_FILE, CONTENT);
        let mut wg_conf = WgConf::open(TEST_CONF_FILE).unwrap();

        // Act
        let interface = wg_conf.interface();

        // Assert
        assert!(interface.is_err());
        let err = interface.unwrap_err();
        assert!(err.kind() == WgConfErrKind::Unexpected);
        assert!(err.to_string().contains("not key-value"));
    }

    fn prepare_test_conf(conf_name: &'static str, content: &str) -> Cleanup {
        {
            let mut file = fs::File::create(conf_name).unwrap();
            file.write_all(content.as_bytes()).unwrap();
        }

        let cleanup_fn = || {
            let _ = fs::remove_file(conf_name.to_owned());
        };

        Cleanup(Box::new(cleanup_fn))
    }
}
