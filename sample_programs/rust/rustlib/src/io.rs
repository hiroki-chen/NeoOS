//! The I/O interfaces for functionalities like `println!`.

use core::fmt::{Arguments, Error, Result, Write};

use alloc::string::{String, ToString};
use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::sys::sys_write;

static LOGGER: StdOut = StdOut;
static LOG_LEVEL: Option<&'static str> = option_env!("RUST_LOG");

struct StdOut;

impl Write for StdOut {
    fn write_fmt(mut self: &mut Self, args: Arguments<'_>) -> Result {
        self.write_str(&args.to_string())
    }

    fn write_char(&mut self, c: char) -> Result {
        let mut s = String::from(c);
        self.write_str(&s)
    }

    fn write_str(&mut self, s: &str) -> Result {
        if sys_write(1, s.as_ptr(), s.len()).is_negative() {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

impl Log for StdOut {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn flush(&self) {}

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            color_print(
                // TODO: Add more log information.
                format_args!(
                    "[Rust Application][{:>5}] {}\n",
                    record.level(),
                    record.args()
                ),
                record.level(),
            );
        }
    }
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

pub(crate) fn init_logger() {
    log::set_logger(&LOGGER).unwrap_or_default();

    let max_level = match LOG_LEVEL.unwrap_or(&"info") {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Off,
    };
    log::set_max_level(max_level);
}

/// The print function invoked by the macro.
pub fn _print(args: Arguments) {
    StdOut.write_fmt(args).unwrap()
}

/// Prints to the standard output.
///
/// Equivalent to the [`println!`] macro except that a newline is not printed at
/// the end of the message.
///
/// Note that stdout is frequently line-buffered by default so it may be
/// necessary to use [`io::stdout().flush()`][flush] to ensure the output is emitted
/// immediately.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::io::_print(core::format_args!($($arg)*));
    }};
}

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
/// To avoid this, lock stdout with [`io::stdout().lock()`][lock]:
/// ```
/// use std::io::{stdout, Write};
///
/// let mut lock = stdout().lock();
/// writeln!(lock, "hello world").unwrap();
/// ```
///
/// Use `println!` only for the primary output of your program. Use
/// [`eprintln!`] instead to print error and progress messages.
///
/// [`std::fmt`]: crate::fmt
/// [`eprintln!`]: crate::eprintln
/// [lock]: crate::io::Stdout
///
/// # Panics
///
/// Panics if writing to [`io::stdout`] fails.
///
/// Writing to non-blocking stdout can cause an error, which will lead
/// this macro to panic.
///
/// [`io::stdout`]: crate::io::stdout
///
/// # Examples
///
/// ```
/// println!(); // prints just a newline
/// println!("hello there!");
/// println!("format {} arguments", "some");
/// let local_variable = "some";
/// println!("format {local_variable} arguments");
/// ```
#[macro_export]
macro_rules! println {
    ($fmt:expr) => { (print!(concat!($fmt, "\n"))); };
    ($fmt:expr, $($arg:tt)*) => {{ (print!(concat!($fmt, "\n"), $($arg)*)); }};
}

/// Construct format argument with colored output.
macro_rules! add_color {
    ($args: ident, $color: ident) => {{
        format_args!("\u{1B}[{}m{}\u{1B}[0m", $color, $args)
    }};
}

pub(crate) fn color_print(args: Arguments, log_level: Level) {
    let color = log_level_to_color_code(log_level);

    _print(add_color!(args, color));
}
