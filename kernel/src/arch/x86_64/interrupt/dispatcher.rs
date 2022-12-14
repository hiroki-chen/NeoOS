//! This module implementes the interrupt handlers.

use log::{debug, info};

use super::TrapFrame;

/// Defines how the kernel handles the interrupt / exceptions when the control is passed to it.
#[no_mangle]
pub extern "C" fn __trap_dispatcher(tf: &mut TrapFrame) {
    debug!("__trap_dispatcher(): trap type: {:#x}", tf.trap_num);

    // Dispatch based on tf.trap_num.
    match tf.trap_num {
        0x3 => dump_all(tf),

        _ => panic!("__trap_dispatcher(): unrecognized type!"),
    }
}

/// Simply dumps the tf.
#[inline(always)]
fn dump_all(tf: &mut TrapFrame) {
    info!("dump_all(): dumped tf (Not TensorFlow :)) as\n{:#x?}", tf);

    tf.rip += 1;
}
