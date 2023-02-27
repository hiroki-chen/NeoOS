//! In computing, an inter-processor interrupt (IPI), also known as a shoulder tap, is a special type of interrupt
//! by which one processor may interrupt another processor in a multiprocessor system if the interrupting
//! processor requires action from the other processor. Actions that might be requested include:
//! * flushes of memory management unit caches, such as translation lookaside buffers, on other processors when
//!   memory mappings are changed by one processor;
//! * stopping when the system is being shut down by one processor.
//! * Notify a processor that higher priority work is available.
//! * Notify a processor of work that cannot be done on all processors due to, e.g.,
//! * asymmetric access to I/O channels[1] special features on some processors

