use bcc::perf_event::{Event, SoftwareEvent};
use bcc::table::Entry;
use bcc::{clear_screen, trace_parse, trace_read, BccError, Kprobe, Kretprobe};
use bcc::{PerfEvent, PerfEventArray, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{io::BufRead, io::BufReader};
use std::{ptr, thread, time};

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("profile")
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .help("trace this PID only")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tid")
                .long("tid")
                .short("t")
                .help("trace this TID only")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("user-stack")
                .long("user-stacks-only")
                .short("U")
                .help("trace user stacks only")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("kernel-stack")
                .long("kernel-stacks-only")
                .short("K")
                .help("trace kernel stacks only")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("frequency")
                .long("frequency")
                .short("F")
                .help("trace frequency")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .short("c")
                .help("sample period, number of events")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("cpu")
                .long("cpu")
                .short("C")
                .help("num cpu to run profile on")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .short("c")
                .help("count connects per src ip and dest ip/port")
                .takes_value(false),
        )
        .get_matches();

    let cpus = bcc::cpuonline::get()?.len() as u32;
    let mut code = format!(
        "{}\n{}",
        format!("#define NUM_CPU {}", cpus),
        include_str!("tcpconnect.c").to_string()
    );
    
    if let Some(pid) = matches.value_of("pid") {
        let target = format!("if (pid != {}) {{ return 0; }}", pid);
        code = code.replace("FILTER_PID", &target);
    }
    if let Some(uid) = matches.value_of("uid") {
        let target = format!("if (uid != {}) {{ return 0; }}", uid);
        code = code.replace("FILTER_UID", &target);
    }
    if let Some(count) = matches.value_of("count") {
        // let r=count_trace_text["ipv6"]
        code = code.replace("IPV4_CODE", COUNT_AND_TRACE_TEXT["ipv4"].count);
        code = code.replace("IPV6_CODE", COUNT_AND_TRACE_TEXT["ipv6"].count);
    } else {
        code = code.replace("IPV4_CODE", COUNT_AND_TRACE_TEXT["ipv4"].trace);
        code = code.replace("IPV6_CODE", COUNT_AND_TRACE_TEXT["ipv6"].trace);
    }

    let mut bpf = BPF::new(&code)?;

    Kprobe::new()
        .function("tcp_v4_connect")
        .handler("trace_connect_entry")
        .attach(&mut bpf)?;


    while runnable.load(Ordering::SeqCst) {
    }
    println!("Detaching...");
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
