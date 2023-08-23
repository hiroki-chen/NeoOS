//! Implements the in-memory representation of the APFS B-Tree.
//!
//! The reason why we need to manually implement a B-Tree is that we want to have full access to the internal structure
//! of the B-Tree, while [`alloc::collections::BTreeMap`] does not allow us to access. Note however, that most components
//! of this module are taken from its code to facilitate us.
//!
//! TO BE CONTINUED...

#[cfg(feature = "apfs_write")]
compile_error!("apfs_write is not supported yet!");
