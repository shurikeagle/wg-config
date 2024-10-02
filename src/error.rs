use std::fmt::Display;

#[derive(Debug, PartialEq, Eq)]
pub enum WgConfErrKind {
    Unexpected,
    AlreadyExists,
    NotFound,
    NotWgConfig,
    ConfFileClosed,
    ValidationFailed,
    CouldntUpdateInterface,
    CriticalKeepTmp,
    EOF,
}

#[derive(Debug)]
pub enum WgConfError {
    /// Unexpected error occurred
    Unexpected(String),
    /// Instance already exists
    AlreadyExists(String),
    /// Instance not found
    NotFound(String),
    /// Provided file is not WG config
    NotWgConfig(String),
    /// Validation failed
    ValidationFailed(String),
    /// Couldn't update interface for some reason
    CouldntUpdateInterface(String),
    /// Some critical error occurred, config file was lost, actual config data is kept in .tmp file
    CriticalKeepTmp(String),
    // End of file reached
    EOF,
}

impl Clone for WgConfError {
    fn clone(&self) -> Self {
        match self {
            Self::Unexpected(arg0) => Self::Unexpected(arg0.clone()),
            Self::AlreadyExists(arg0) => Self::AlreadyExists(arg0.clone()),
            Self::NotFound(arg0) => Self::NotFound(arg0.clone()),
            Self::NotWgConfig(arg0) => Self::NotWgConfig(arg0.clone()),
            Self::ValidationFailed(arg0) => Self::ValidationFailed(arg0.clone()),
            Self::CouldntUpdateInterface(arg0) => Self::CouldntUpdateInterface(arg0.clone()),
            Self::CriticalKeepTmp(arg0) => Self::CriticalKeepTmp(arg0.clone()),
            Self::EOF => Self::EOF,
        }
    }
}

impl WgConfError {
    pub fn kind(&self) -> WgConfErrKind {
        match self {
            WgConfError::Unexpected(_) => WgConfErrKind::Unexpected,
            WgConfError::AlreadyExists(_) => WgConfErrKind::AlreadyExists,
            WgConfError::NotFound(_) => WgConfErrKind::NotFound,
            WgConfError::NotWgConfig(_) => WgConfErrKind::NotWgConfig,
            WgConfError::ValidationFailed(_) => WgConfErrKind::ValidationFailed,
            WgConfError::CouldntUpdateInterface(_) => WgConfErrKind::CouldntUpdateInterface,
            WgConfError::CriticalKeepTmp(_) => WgConfErrKind::CriticalKeepTmp,
            WgConfError::EOF => WgConfErrKind::EOF,
        }
    }
}

impl Display for WgConfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WgConfError::Unexpected(err) => write!(f, "Unexpected error occurred: {err}"),
            WgConfError::AlreadyExists(object_name) => write!(f, "{object_name} already exists"),
            WgConfError::NotFound(object_name) => write!(f, "{object_name} not found"),
            WgConfError::NotWgConfig(details) => {
                write!(f, "File is not a valid WG config: {details}")
            }
            WgConfError::ValidationFailed(details) => write!(f, "WG validation failed: {details}"),
            WgConfError::CouldntUpdateInterface(err) => {
                write!(f, "Couldn't update WG interface: {err}")
            }
            WgConfError::CriticalKeepTmp(err) => write!(
                f,
                "Critical error occurred, the correct WG config is kept as .tmp: {err}"
            ),
            WgConfError::EOF => write!(f, "End of file reached"),
        }
    }
}
