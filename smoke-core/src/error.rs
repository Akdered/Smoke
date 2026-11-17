use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SmokeError {
    #[error("Ошибка ввода-вывода: {0}")]
    Io(#[from] io::Error),

    #[error("Неподдерживаемая версия SOCKS: {0} (ожидалась 5)")]
    UnsupportedVersion(u8),

    #[error("Неподдерживаемая команда SOCKS: {0}")]
    UnsupportedCommand(u8),

    #[error("Неподдерживаемый тип адреса: {0}")]
    UnsupportedAddressType(u8),

    #[error("Некорректное доменное имя")]
    InvalidDomain,

    #[error("Не удалось разрешить адрес: {0}")]
    ResolutionFailed(String),
}

pub type Result<T> = std::result::Result<T, SmokeError>;
