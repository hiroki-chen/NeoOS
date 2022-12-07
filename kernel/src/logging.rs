use core::fmt;

use crate::sync::mutex::SpinLock as Mutex;
use lazy_static::lazy_static;
use log::{self, Level, LevelFilter, Log, Metadata, Record};

lazy_static! {
  // Lock the logger instance.
  static ref LOG_LOCK: Mutex<()> = Mutex::new(());
}

macro_rules! println {
    () => {};
}

macro_rules! error {
    () => {};
}

macro_rules! warning {
    () => {};
}

macro_rules! info {
    () => {};
}

macro_rules! debug {
    () => {};
}

// fixme: Maybe useless.
#[deprecated]
macro_rules! trace {
    () => {};
}
