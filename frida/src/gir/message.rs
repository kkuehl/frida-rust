/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! A script's messages, parsed: what [`Script::on_message`](crate::gir::Script::on_message)
//! hands its handler.
//!
//! A script's `message` signal carries the message as JSON text. frida-gum writes three
//! kinds: `send` (from the script's `send()`), `log` (from `console.log()` and friends) and
//! `error` (an exception the script did not catch). Anything else, or text that is not
//! JSON, is kept as [`Message::Other`], so that nothing is lost.

use serde_json::Value;

/// A message from a script.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// What the script passed to `send()`.
    Send(MessageSend),
    /// A line the script logged with `console.log()`, `console.warn()` and so on.
    Log(MessageLog),
    /// An exception the script threw and did not catch.
    Error(MessageError),
    /// Any other message, as its JSON value: a string holding the text itself when the
    /// text is not JSON.
    Other(Value),
}

/// What the script passed to `send()`: its first argument. The second, binary data, is
/// handed beside the message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageSend {
    /// The value, as JSON.
    pub payload: Value,
}

/// A line the script logged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageLog {
    /// How it was logged.
    pub level: LogLevel,
    /// The text.
    pub payload: String,
}

/// How a line was logged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LogLevel {
    /// `console.log()` and `console.info()`.
    Info,
    /// `console.debug()`.
    Debug,
    /// `console.warn()`.
    Warning,
    /// `console.error()`.
    Error,
    /// A level this version has no name for, as frida-gum spelled it.
    Other(String),
}

/// An exception the script did not catch.
///
/// Only the description is always there: an exception thrown in a callback, or a thrown
/// value that is not an `Error`, may come without a stack or a location.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageError {
    /// What went wrong, such as `ReferenceError: 'x' is not defined`.
    pub description: String,
    /// The stack trace, if there is one.
    pub stack: Option<String>,
    /// The script file it was thrown in.
    pub file_name: Option<String>,
    /// The line it was thrown at, from 1.
    pub line_number: Option<u32>,
    /// The column it was thrown at, from 1.
    pub column_number: Option<u32>,
}

impl Message {
    /// The message in `json`, as the `message` signal carries it. Never fails: what it
    /// cannot make out becomes [`Message::Other`].
    #[must_use]
    pub fn from_json(json: &str) -> Self {
        match serde_json::from_str::<Value>(json) {
            Ok(value) => Self::from_value(value),
            Err(_) => Self::Other(Value::String(json.to_string())),
        }
    }

    /// The message in a JSON value already parsed. Never fails, as [`Message::from_json`].
    #[must_use]
    pub fn from_value(value: Value) -> Self {
        let Some(object) = value.as_object() else {
            return Self::Other(value);
        };
        match object.get("type").and_then(Value::as_str) {
            Some("send") => match object.get("payload") {
                Some(payload) => Self::Send(MessageSend {
                    payload: payload.clone(),
                }),
                None => Self::Send(MessageSend {
                    payload: Value::Null,
                }),
            },
            Some("log") => {
                let (Some(level), Some(payload)) = (
                    object.get("level").and_then(Value::as_str),
                    object.get("payload").and_then(Value::as_str),
                ) else {
                    return Self::Other(value);
                };
                Self::Log(MessageLog {
                    level: LogLevel::from_name(level),
                    payload: payload.to_string(),
                })
            }
            Some("error") => {
                let Some(description) = object.get("description").and_then(Value::as_str) else {
                    return Self::Other(value);
                };
                let text = |key: &str| object.get(key).and_then(Value::as_str).map(String::from);
                let number = |key: &str| {
                    object
                        .get(key)
                        .and_then(Value::as_u64)
                        .and_then(|n| u32::try_from(n).ok())
                };
                Self::Error(MessageError {
                    description: description.to_string(),
                    stack: text("stack"),
                    file_name: text("fileName"),
                    line_number: number("lineNumber"),
                    column_number: number("columnNumber"),
                })
            }
            _ => Self::Other(value),
        }
    }
}

impl LogLevel {
    fn from_name(name: &str) -> Self {
        match name {
            "info" => Self::Info,
            "debug" => Self::Debug,
            "warning" => Self::Warning,
            "error" => Self::Error,
            other => Self::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn each_kind_is_parsed() {
        assert_eq!(
            Message::from_json(r#"{"type":"send","payload":{"a":[1,2]}}"#),
            Message::Send(MessageSend {
                payload: json!({"a": [1, 2]})
            })
        );
        assert_eq!(
            Message::from_json(r#"{"type":"log","level":"warning","payload":"careful"}"#),
            Message::Log(MessageLog {
                level: LogLevel::Warning,
                payload: "careful".into()
            })
        );
        assert_eq!(
            Message::from_json(r#"{"type":"log","level":"trace","payload":"x"}"#),
            Message::Log(MessageLog {
                level: LogLevel::Other("trace".into()),
                payload: "x".into()
            })
        );
        assert_eq!(
            Message::from_json(
                r#"{"type":"error","description":"Error: no","stack":"at f","fileName":"/x.js","lineNumber":3,"columnNumber":7}"#
            ),
            Message::Error(MessageError {
                description: "Error: no".into(),
                stack: Some("at f".into()),
                file_name: Some("/x.js".into()),
                line_number: Some(3),
                column_number: Some(7),
            })
        );
    }

    #[test]
    fn an_error_without_a_location_is_still_an_error() {
        assert_eq!(
            Message::from_json(r#"{"type":"error","description":"oops"}"#),
            Message::Error(MessageError {
                description: "oops".into(),
                stack: None,
                file_name: None,
                line_number: None,
                column_number: None,
            })
        );
    }

    #[test]
    fn what_cannot_be_made_out_is_kept() {
        assert_eq!(
            Message::from_json("not json"),
            Message::Other(Value::String("not json".into()))
        );
        assert_eq!(
            Message::from_json(r#"{"type":"mystery","x":1}"#),
            Message::Other(json!({"type": "mystery", "x": 1}))
        );
        assert_eq!(
            Message::from_json(r#"{"type":"log","level":"info"}"#),
            Message::Other(json!({"type": "log", "level": "info"}))
        );
        assert_eq!(Message::from_json("[1]"), Message::Other(json!([1])));
    }
}
