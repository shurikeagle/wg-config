use std::fmt::Display;

#[derive(PartialEq, Eq)]
pub enum WgConfErrKind {
    Unexpected,
    NotFound,
    NotWgConfig,
    ConfFileClosed,
    ValidationFailed,
    CouldntUpdateInterface,
    CriticalKeepTmp,
}

#[derive(Debug)]
pub enum WgConfError {
    Unexpected(String),
    NotFound(String),
    NotWgConfig(String),
    ValidationFailed(String),
    CouldntUpdateInterface(String),
    CriticalKeepTmp(String),
}

impl Clone for WgConfError {
    fn clone(&self) -> Self {
        match self {
            Self::Unexpected(arg0) => Self::Unexpected(arg0.clone()),
            Self::NotFound(arg0) => Self::NotFound(arg0.clone()),
            Self::NotWgConfig(arg0) => Self::NotWgConfig(arg0.clone()),
            Self::ValidationFailed(arg0) => Self::ValidationFailed(arg0.clone()),
            Self::CouldntUpdateInterface(arg0) => Self::CouldntUpdateInterface(arg0.clone()),
            Self::CriticalKeepTmp(arg0) => Self::CriticalKeepTmp(arg0.clone()),
        }
    }
}

impl WgConfError {
    pub fn kind(&self) -> WgConfErrKind {
        match self {
            WgConfError::Unexpected(_) => WgConfErrKind::Unexpected,
            WgConfError::NotFound(_) => WgConfErrKind::NotFound,
            WgConfError::NotWgConfig(_) => WgConfErrKind::NotWgConfig,
            WgConfError::ValidationFailed(_) => WgConfErrKind::ValidationFailed,
            WgConfError::CouldntUpdateInterface(_) => WgConfErrKind::CouldntUpdateInterface,
            WgConfError::CriticalKeepTmp(_) => WgConfErrKind::CriticalKeepTmp,
        }
    }
}

impl Display for WgConfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WgConfError::Unexpected(err) => write!(f, "Unexpected error occurred: {err}"),
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
        }
    }
}
