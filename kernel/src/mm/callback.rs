//! Implements the underlying operations by `Arena`.

use core::fmt::Debug;

use alloc::boxed::Box;

pub trait ArenaCallback: Debug + Send + Sync + 'static {}

impl Clone for Box<dyn ArenaCallback> {
    fn clone(&self) -> Self {
        todo!()
    }
}
