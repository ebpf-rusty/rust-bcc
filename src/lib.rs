//! Rust bindings for the BCC compiler collection to enable eBPF instrumentation
//!
//! # Goals
//! * Provide idiomatic Rust bindings for the BCC compiler collection
//! * Mimic the Python BCC bindings <https://github.com/iovisor/bcc>
//!
//! # Examples
//! * see <https://github.com/rust-bpf/rust-bcc/tree/master/examples>

#[allow(unused_variables, dead_code)]
mod core;
#[allow(unused_variables, dead_code)]
pub mod cpuonline;
#[allow(unused_variables, dead_code)]
mod error;
#[allow(unused_variables, dead_code)]
mod helpers;
#[allow(unused_variables, dead_code)]
mod kprobe;
#[allow(unused_variables, dead_code)]
pub mod perf_event;
#[allow(unused_variables, dead_code)]
mod raw_tracepoint;
#[allow(unused_variables, dead_code)]
pub mod ring_buf;
#[allow(unused_variables, dead_code)]
pub mod symbol;
#[allow(unused_variables, dead_code)]
pub mod table;
#[allow(unused_variables, dead_code)]
mod tracepoint;
#[allow(unused_variables, dead_code)]
mod types;
#[allow(unused_variables, dead_code)]
mod uprobe;
#[allow(unused_variables, dead_code)]
mod xdp;
#[allow(unused_variables, dead_code)]
mod utils;

#[macro_use]
extern crate bitflags;

pub use crate::core::{BPFBuilder, BccDebug, BpfProgType, USDTContext, BPF};
pub use error::BccError;
pub use kprobe::{Kprobe, Kretprobe};
pub use perf_event::{PerfEvent, PerfEventArray, PerfMap};
pub use raw_tracepoint::RawTracepoint;
pub use tracepoint::Tracepoint;
pub use uprobe::{Uprobe, Uretprobe};
pub use xdp::{Mode as XDPMode, XDP};
pub use utils::*;