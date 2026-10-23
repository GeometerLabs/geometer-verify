use std::fmt;

/// Decode error classes. The snake_case names are part of the contract: the
/// shared negative vectors name the class every language must report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Syntax,
    DuplicateKey,
    Depth,
    UnknownField,
    MissingField,
    Type,
    Range,
    NonCanonical,
    InvalidId,
    InvalidDigest,
    UnknownVariant,
    Nan,
    FrameTooLarge,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Syntax => "syntax",
            ErrorClass::DuplicateKey => "duplicate_key",
            ErrorClass::Depth => "depth",
            ErrorClass::UnknownField => "unknown_field",
            ErrorClass::MissingField => "missing_field",
            ErrorClass::Type => "type",
            ErrorClass::Range => "range",
            ErrorClass::NonCanonical => "non_canonical",
            ErrorClass::InvalidId => "invalid_id",
            ErrorClass::InvalidDigest => "invalid_digest",
            ErrorClass::UnknownVariant => "unknown_variant",
            ErrorClass::Nan => "nan",
            ErrorClass::FrameTooLarge => "frame_too_large",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub class: ErrorClass,
    pub path: String,
    pub msg: String,
}

impl DecodeError {
    pub fn new(class: ErrorClass, path: &str, msg: impl Into<String>) -> Self {
        DecodeError { class, path: path.to_owned(), msg: msg.into() }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.class.as_str(), self.path, self.msg)
    }
}

impl std::error::Error for DecodeError {}
