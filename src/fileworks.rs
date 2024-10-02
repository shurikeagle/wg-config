use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Seek, SeekFrom},
};

use crate::WgConfError;

/// Copies from `src` to `dst` all the bytes except the interval `except_from` - `except_to`
pub(crate) fn copy_bytes_except(
    src: &mut File,
    dst: &mut File,
    except_from: u64,
    except_to: u64,
    parent_err_msg: &str,
) -> Result<(), WgConfError> {
    seek_to_start(src, parent_err_msg)?;

    let mut all_up_to_peer = src.take(except_from);
    let _ = std::io::copy(&mut all_up_to_peer, dst).map_err(|err| {
        WgConfError::Unexpected(format!(
            "Couldn't copy config file to tmp: {}",
            err.to_string()
        ))
    })?;

    src.seek(SeekFrom::Start(except_to)).map_err(|err| {
        WgConfError::Unexpected(format!(
            "Couldn't copy config file to tmp: {}",
            err.to_string()
        ))
    })?;

    std::io::copy(src, dst).map_err(|err| {
        WgConfError::Unexpected(format!(
            "Couldn't copy config file to tmp: {}",
            err.to_string()
        ))
    })?;

    Ok(())
}

/// Replaces `dst` file by `src`. Keep `dst` name
pub(crate) fn replace_file(
    src: File,
    src_name: &str,
    dst: File,
    dst_name: &str,
) -> Result<File, WgConfError> {
    drop(dst);
    drop(src);

    fs::remove_file(dst_name).map_err(|err| {
        WgConfError::Unexpected(format!(
            "Couldn't replace {} by tmp: {}",
            dst_name,
            err.to_string()
        ))
    })?;

    fs::rename(src_name, dst_name).map_err(|err| {
        WgConfError::CriticalKeepTmp(format!("Couldn't rename tmp file: {}", err.to_string()))
    })?;

    let new_file = open_file_w_all_permissions(dst_name)?;

    Ok(new_file)
}

pub(crate) fn open_file_w_all_permissions(file_name: &str) -> Result<File, WgConfError> {
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

pub(crate) fn create_tmp_file(base_name: &str) -> Result<(String, File), WgConfError> {
    let tmp_file_name = base_name.to_owned() + ".tmp";

    let file = OpenOptions::new()
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

    Ok((tmp_file_name, file))
}

pub(crate) fn seek_to_start(file: &mut File, err_msg: &str) -> Result<(), WgConfError> {
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|err| WgConfError::Unexpected(format!("{}: {}", err_msg, err.to_string())))?;

    Ok(())
}
