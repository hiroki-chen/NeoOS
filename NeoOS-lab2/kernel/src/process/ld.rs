//! The information is passed on to the user processes by binary loaders which are part of the kernel subsystem
//! itself; either built-in the kernel or a kernel module. Binary loaders convert a binary file, a program, into
//! a process on the system.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

pub const AT_PHDR: u8 = 3;
pub const AT_PHENT: u8 = 4;
pub const AT_PHNUM: u8 = 5;
pub const AT_PAGESZ: u8 = 6;
pub const AT_BASE: u8 = 7;
pub const AT_ENTRY: u8 = 9;

pub struct StackWriter {
    stack: u64,
}

#[derive(Clone, Debug, Default)]
pub struct InitInfo {
    pub args: Vec<String>,
    pub envs: Vec<String>,
    /// ELF auxiliary vectors are a mechanism to transfer certain kernel level information to the user processes.
    pub auxv: BTreeMap<u8, usize>,
}

impl StackWriter {
    pub fn write<T>(&mut self, val: &[T])
    where
        T: Copy,
    {
        self.stack -= (val.len() * core::mem::size_of::<T>()) as u64;
        self.stack -= self.stack % core::mem::align_of::<T>() as u64;

        unsafe {
            core::ptr::copy(val.as_ptr(), self.stack as *mut T, val.len());
        }
    }

    pub fn write_str(&mut self, s: &str) {
        // Must be zero-terminated or the kernel does not know the length.
        self.write(b"\0");
        self.write(s.as_bytes());
    }
}

impl InitInfo {
    /// Pushes itself onto the given stack address.
    /// Returns the stack top.
    pub unsafe fn push_at(&self, stack: u64) -> u64 {
        let mut writer = StackWriter { stack };
        // Push the program name.
        writer.write_str(&self.args[0]);

        // Push environment strings and get their addresses.
        let auxv = self
            .envs
            .iter()
            .map(|env| {
                writer.write_str(env);
                writer.stack
            })
            .collect::<Vec<_>>();
        // Push arguments.
        let argv = self
            .args
            .iter()
            .map(|arg| {
                writer.write_str(arg);
                writer.stack
            })
            .collect::<Vec<_>>();

        let auxv_terminator = [core::ptr::null::<u8>(), core::ptr::null::<u8>()];
        let str_terminator = [core::ptr::null::<u8>()];

        // Auxiliary vectors in ELF loader.
        writer.write(&auxv_terminator);
        self.auxv.iter().for_each(|(key, value)| {
            writer.write(&[*key as usize, *value]);
        });

        // Other pointers.
        writer.write(&str_terminator);
        writer.write(auxv.as_slice());
        writer.write(&str_terminator);
        writer.write(argv.as_slice());
        writer.write(&[argv.len()]);

        writer.stack
    }
}
