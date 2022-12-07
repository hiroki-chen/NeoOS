use core::fmt;

use crate::sync::mutex::SpinLock as Mutex;
use lazy_static::lazy_static;
use log::{Level, LevelFilter, Log, Metadata, Record};

lazy_static! {
  // Lock the logger instance.
  static ref LOG_LOCK: Mutex<()> = Mutex::new(());
}

/// From std::println!
///
/// Prints to the standard output, with a newline.
///
/// On all platforms, the newline is the LINE FEED character (`\n`/`U+000A`) alone
/// (no additional CARRIAGE RETURN (`\r`/`U+000D`)).
///
/// This macro uses the same syntax as [`format!`], but writes to the standard output instead.
/// See [`std::fmt`] for more information.
///
/// The `println!` macro will lock the standard output on each call. If you call
/// `println!` within a hot loop, this behavior may be the bottleneck of the loop.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::io::_print($crate::format_args_nl!($($arg)*));
    }};
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        // todo: implement io.
        // $crate::io::_print($crate::format_args!($($arg)*));
    }};
}

pub(crate) fn print(content: fmt::Arguments) {}

pub(crate) fn color_print(content: fmt::Arguments, log_level: Level) {
    let color = log_level_to_color_code(log_level);

    // TODO: lock and print.
    let _ = LOG_LOCK.lock();
    
}

fn log_level_to_color_code(level: Level) -> u8 {
    match level {
        Level::Error => 31,
        Level::Warn => 33,
        Level::Info => 37,
        Level::Debug => 32,
        Level::Trace => 36,
    }
}
