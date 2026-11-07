pub mod config_lines;
pub mod deserializer;
pub mod serializer;

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClamdFormatError {
    #[error("{setting_name} appears more than once but holds a single value")]
    RepeatedSetting { setting_name: String },
    #[error("{setting_value} is not a valid value for {setting_name}")]
    InvalidValue {
        setting_name: String,
        setting_value: String,
    },
    #[error("the line for {setting_name} is longer than clamd reads in one piece")]
    LineTooLong { setting_name: String },
    #[error("{setting_name} can't be changed at runtime")]
    UnknownSetting { setting_name: String },
    #[error("{0}")]
    Message(String),
}

impl serde::de::Error for ClamdFormatError {
    fn custom<Message: fmt::Display>(error_message: Message) -> Self {
        Self::Message(error_message.to_string())
    }
}

impl serde::ser::Error for ClamdFormatError {
    fn custom<Message: fmt::Display>(error_message: Message) -> Self {
        Self::Message(error_message.to_string())
    }
}
