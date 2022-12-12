//! This module implements *highl-level* paging mechanism that is platform-agnostic.
//!
//! The idea is to divide both the virtual and physical memory space into small, fixed-size blocks.
//! The blocks of the virtual memory space are called pages, and the blocks of the physical address
//! space are called frames. Each page can be individually mapped to a frame, which makes it possible
//! to split larger memory regions across non-continuous physical frames.
