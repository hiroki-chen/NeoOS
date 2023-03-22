//! Devfs is an alternative to "real" character and block special devices on your root filesystem. Kernel device
//! drivers can register devices by name rather than major and minor numbers. These devices will appear in devfs
//! automatically, with whatever default ownership and protection the driver specified.

pub mod random;
pub mod tty;
pub mod zero;
