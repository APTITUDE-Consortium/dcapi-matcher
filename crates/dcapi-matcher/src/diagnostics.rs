extern crate alloc;

use crate::error::format_error_chain;
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use android_credman::{
    CredentialEntry, CredentialSet, CredmanApply, CredmanContext, StringIdEntry, credman,
};
use c8str::{C8Str, C8String, c8, c8format};
use core::error::Error as CoreError;
use core::ffi::CStr;
use core::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn as_c8str(&self) -> &'static C8Str {
        match self {
            LogLevel::Error => c8!("ERROR"),
            LogLevel::Warn => c8!("WARN"),
            LogLevel::Info => c8!("INFO"),
            LogLevel::Debug => c8!("DEBUG"),
            LogLevel::Trace => c8!("TRACE"),
        }
    }

    fn as_str(&self) -> &'static str {
        self.as_c8str().as_str()
    }
}

#[derive(Debug, Clone)]
struct LogEntry {
    level: LogLevel,
    message: String,
}

static LOGS: Mutex<Vec<LogEntry>> = Mutex::new(Vec::new());
static LOG_LEVEL: Mutex<Option<LogLevel>> = Mutex::new(Some(LogLevel::Error));
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub fn begin() {
    LOGS.lock().clear();
}

pub fn set_level(level: Option<LogLevel>) {
    *LOG_LEVEL.lock() = level;
}

pub fn debug(message: impl AsRef<str>) {
    push(LogLevel::Debug, message.as_ref());
}

pub fn trace(message: impl AsRef<str>) {
    push(LogLevel::Trace, message.as_ref());
}

pub fn info(message: impl AsRef<str>) {
    push(LogLevel::Info, message.as_ref());
}

pub fn warn(message: impl AsRef<str>) {
    push(LogLevel::Warn, message.as_ref());
}

pub fn error(message: impl AsRef<str>) {
    push(LogLevel::Error, message.as_ref());
}

/// Helper methods that log errors and convert `Result` into `Option`.
pub trait ResultExt<T, E> {
    fn ok_error(self) -> Option<T>;
    fn ok_warn(self) -> Option<T>;
    fn ok_info(self) -> Option<T>;
    fn ok_debug(self) -> Option<T>;
    fn ok_trace(self) -> Option<T>;
}

impl<T, E> ResultExt<T, E> for Result<T, E>
where
    E: CoreError,
{
    fn ok_error(self) -> Option<T> {
        self.inspect_err(|err| err.error()).ok()
    }

    fn ok_warn(self) -> Option<T> {
        self.inspect_err(|err| err.warn()).ok()
    }

    fn ok_info(self) -> Option<T> {
        self.inspect_err(|err| err.info()).ok()
    }

    fn ok_debug(self) -> Option<T> {
        self.inspect_err(|err| err.debug()).ok()
    }

    fn ok_trace(self) -> Option<T> {
        self.inspect_err(|err| err.trace()).ok()
    }
}

/// Helper methods that log an error chain at a chosen level.
pub trait ErrorExt {
    fn error(&self);
    fn warn(&self);
    fn info(&self);
    fn debug(&self);
    fn trace(&self);
}

impl<E> ErrorExt for E
where
    E: CoreError + ?Sized,
{
    fn error(&self) {
        error(format_error_chain(&self));
    }

    fn warn(&self) {
        warn(format_error_chain(&self));
    }

    fn info(&self) {
        info(format_error_chain(&self));
    }

    fn debug(&self) {
        debug(format_error_chain(&self));
    }

    fn trace(&self) {
        trace(format_error_chain(&self));
    }
}

pub fn take() -> Vec<String> {
    let entries = take_entries();
    entries.into_iter().map(format_entry).collect()
}

fn take_entries() -> Vec<LogEntry> {
    let mut logs = LOGS.lock();
    core::mem::take(&mut *logs)
}

pub fn flush_and_apply() {
    let entries = take_entries();
    if entries.is_empty() {
        return;
    }

    let host = credman();
    let ctx = CredmanContext { host };
    let prefix = "dcapi:vp";
    let set_id = cow_cstr_from_c8string(c8format!("{prefix}:logs"));
    let set = CredentialSet::new_cow(set_id).add_entries(entries.iter().map(|entry| {
        let id = next_id();
        let cred_id = cow_cstr_from_c8string(c8format!("{prefix}:log:{id}"));
        let mut cred =
            StringIdEntry::new_cow(cred_id, Cow::Borrowed(entry.level.as_c8str().as_c_str()));
        if !entry.message.is_empty() {
            cred.disclaimer = Some(cow_cstr_from_bytes(entry.message.as_bytes()));
        }
        CredentialEntry::StringId(cred)
    }));
    CredmanApply::apply(&set, ctx);
}

fn push(level: LogLevel, message: &str) {
    if !enabled(level) {
        return;
    }
    LOGS.lock().push(LogEntry {
        level,
        message: message.to_string(),
    });
}

fn enabled(level: LogLevel) -> bool {
    let Some(threshold) = *LOG_LEVEL.lock() else {
        return false;
    };
    level <= threshold
}

fn format_entry(entry: LogEntry) -> String {
    if entry.message.is_empty() {
        entry.level.as_str().to_string()
    } else {
        format!("{}: {}", entry.level.as_str(), entry.message)
    }
}

fn next_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn c8string_from_bytes(bytes: &[u8]) -> C8String {
    let mut bytes = bytes.to_vec();
    bytes.retain(|byte| *byte != 0);
    C8String::from_vec(bytes).unwrap_or_else(|_| C8String::new())
}

fn cow_cstr_from_bytes<'a>(bytes: &[u8]) -> Cow<'a, CStr> {
    cow_cstr_from_c8string(c8string_from_bytes(bytes))
}

fn cow_cstr_from_c8string<'a>(value: C8String) -> Cow<'a, CStr> {
    Cow::Owned(value.into_c_string())
}
