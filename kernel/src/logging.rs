use core::fmt;

use crate::{
    error::{Errno, KResult},
    sync::mutex::SpinLockNoInterrupt as Mutex,
};
use lazy_static::lazy_static;
use log::{Level, LevelFilter, Log, Metadata, Record};

lazy_static! {
  // Lock the logger instance.
  static ref LOG_LOCK: Mutex<()> = Mutex::new(());
}

/// An instance that logs the information into console created by the kernel.
/// This logger cannot be directly manipulated. The kernel must use macros provided
/// by the `log` crate.
struct EnvLogger;

/// Tells how `log` should print the information through `Logger.`
impl Log for EnvLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn flush(&self) {
        // print(format_args!("\n"));
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            color_print(
                format_args!(
                    "[{:^6}][{} #{}] {}\n",
                    record.level(),
                    crate::arch::cpu::cpu_name(64),
                    crate::arch::cpu::cpu_id(),
                    record.args()
                ),
                record.level(),
            );
        }
    }
}

/// Initialize the envrionment logger.
pub fn init_env_logger() -> KResult<()> {
    // Single instance!
    static ENV_LOGGER: EnvLogger = EnvLogger;

    // Register this logger into `log`.
    if log::set_logger(&ENV_LOGGER).is_err() {
        return Err(Errno::EBUSY);
    }

    let log_level = match option_env!("OS_LOG_LEVEL") {
        Some(str) => str,
        None => "",
    }
    .to_lowercase();

    let max_level = match log_level.as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Off,
    };

    log::set_max_level(max_level);

    Ok(())
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
