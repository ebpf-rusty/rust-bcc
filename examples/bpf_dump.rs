use bcc::perf_event::{Event, SoftwareEvent};
use bcc::{BccError, Instructions};
use bcc::{PerfEvent, PerfEventArray, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Arc;
use std::{thread, time};

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let cpus = bcc::cpuonline::get()?.len() as u32;
    let code = format!(
        "{}\n{}",
        format!("#define NUM_CPU {}", cpus),
        include_str!("bpf_dump.c").to_string()
    );
    let mut bpf = BPF::new(&code)?;
    let func_name = CString::new("trace_entry").unwrap();
    let r = bpf.dump_func(func_name).unwrap();
    let r = Instructions::from_vec(r);
    println!("{:?}", r);
    Ok(())
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}
