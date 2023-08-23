//! Implement logger instance. This currently only sends output to the serial port!
//! Framebuffer-based logging is to be implemented.

use crate::{
    arch::io::writefmt,
    error::{Errno, KResult},
    sync::mutex::SpinLockNoInterrupt as Mutex,
    time::SystemTime,
    LOG_LEVEL,
};
use alloc::vec::Vec;
use core::fmt;
use lazy_static::lazy_static;
use log::{Level, LevelFilter, Log, Metadata, Record};
use ringbuf::HeapRb;
use spin::RwLock;

pub const BANNER: &str = include_str!("./banner.txt");
pub const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");
pub const META: &str = include_str!("../meta");
pub const RING_BUF_LEN: usize = u16::MAX as _;

lazy_static! {
    /// Lock the logger instance.
    static ref LOG_LOCK: Mutex<()> = Mutex::new(());
    /// The kernel ring buffer for storing the kernel messages after the kernel is successfully booted.
    /// Useful for the `dmesg` command.
    pub static ref RING_BUFFER: RwLock<HeapRb<u8>> = RwLock::new(HeapRb::new(RING_BUF_LEN));
}

/// An instance that logs the information into console created by the kernel.
/// This logger cannot be directly manipulated. The kernel must use macros provided
/// by the `log` crate.
struct EnvLogger;

/// Tells how `log` should print the information througÏh `Logger.`
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
                    "{} [{:>5}][#{}] {}\n",
                    SystemTime::now(),
                    record.level(),
                    crate::arch::cpu::cpu_id(),
                    record.args()
                ),
                record.level(),
            );
        }
    }
}

/// Initializes the envrionment logger.
///
/// The logger relies on the [log](https://crates.io/crates/log) crate for providing all the logging macros.
pub fn init_env_logger() -> KResult<()> {
    static ENV_LOGGER: EnvLogger = EnvLogger;
    // Register this logger into `log`.
    if log::set_logger(&ENV_LOGGER).is_err() {
        return Err(Errno::EBUSY);
    }

    let max_level = match LOG_LEVEL.as_str() {
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

/// Prints the name of the function that invokes this macro.
#[macro_export]
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            core::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
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
        print!("\n")
    };
    ($($arg:tt)*) => {{
        print!("{}", format_args_nl!($($arg)*));
    }};
}

#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => {{
        log::info!("[{}@L{}] {}", function!(), line!(), format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! kerror {
    ($($arg:tt)*) => {{
        log::error!("[{}@L{}] {}", function!(), line!(), format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! kdebug {
    ($($arg:tt)*) => {{
        log::debug!("[{}@L{}] {}", function!(), line!(), format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! ktrace {
    ($($arg:tt)*) => {{
        log::trace!("[{}@L{}] {}", function!(), line!(), format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! kwarn {
    ($($arg:tt)*) => {{
        log::warn!("[{}@L{}] {}", function!(), line!(), format_args!($($arg)*));
    }};
}

pub(crate) fn ringbuf_log_raw(data: &[u8]) {
    use ringbuf::Rb;
    let mut lock = crate::logging::RING_BUFFER.write();
    data.iter().for_each(|d| {
        let _ = lock.push(*d);
    });
}

#[macro_export]
macro_rules! ringbuf_log {
    ($($arg:tt)*) => {{
        let data = format_args!($($arg)*).as_str().unwrap().as_bytes();
        $crate::logging::ringbuf_log_raw(data);
    }};
    () => {{
        $crate::logging::RING_BUFFER.write().push(b'\n');
    }};
}

/// From std::print!
///
/// Prints to the standard output, *without* a newline.
///
/// Similar to its [`println!`] coutnerpart, this macro will also lock the output on each call.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::logging::print(format_args!($($arg)*));
    }};
}

macro_rules! add_color {
    ($args: ident, $color: ident) => {{
        format_args!("\u{1B}[{}m{}\u{1B}[0m", $color, $args)
    }};
}

pub(crate) fn print(args: fmt::Arguments) {
    // Lock and print.
    let _ = LOG_LOCK.lock();
    writefmt(args);
}

pub(crate) fn color_print(args: fmt::Arguments, log_level: Level) {
    let color = log_level_to_color_code(log_level);

    print(add_color!(args, color));
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

/// Prints the kernel banner to the output.
pub fn print_banner() {
    let strs = BANNER.split('\n').collect::<Vec<_>>();

    println!("=====================================================");
    for s in strs {
        println!("{}", s);
    }

    println!("{}", META);
    println!("Kernel version: {}", VERSION.unwrap_or(""));
    println!("Kernel: NeoOS kernel in /esp/efi/boot/kernel.img");
    println!("=====================================================");
}
