//! Most (all) Intel-MP compliant SMP boards have the so-called ‘IO-APIC’, which is an enhanced interrupt controller. 
//! It enables us to route hardware interrupts to multiple CPUs, or to CPU groups. Without an IO-APIC, interrupts from
//! hardware will be delivered only to the CPU which boots the operating system (usually CPU#0).

