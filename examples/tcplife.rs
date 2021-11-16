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

#[repr(C)]
struct ipv4_data_t {
    ts_us: u64,
    pid: u32,
    saddr: u32,
    daddr: u32,
    ports: u64,
    received_bytes: u64,
    acked_bytes: u64,
    span_us: u64,
    task: [u8; 128],
}

#[repr(C)]
struct ipv6_data_t {
    ts_us: u64,
    pid: u32,
    saddr: i128,
    daddr: i128,
    ports: u64,
    received_bytes: u64,
    acked_bytes: u64,
    span_us: u64,
    task: [u8; 128],
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("tcplife")
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .help("trace this PID only")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ipv4")
                .long("ipv4")
                .short("4")
                .help("trace ipv4 only")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("ipv6")
                .long("ipv6")
                .short("6")
                .help("trace ipv6 only")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("localport")
                .long("lport")
                .short("L")
                .help("filter local port")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("remoteport")
                .long("rport")
                .short("R")
                .help("filter remote port")
                .takes_value(false),
        )
        .get_matches();

    let cpus = bcc::cpuonline::get()?.len() as u32;
    let mut code = format!(
        "{}\n{}",
        format!("#define NUM_CPU {}", cpus),
        include_str!("tcplife.c").to_string()
    );
    if let Some(pid) = matches.value_of("pid") {
        let target = format!("if (pid != {}) {{ return 0; }}", pid);
        code = code.replace("FILTER_PID", &target);
    }
    if let Some(dports) = matches.value_of("remoteport") {
        let target = format!("if ({}) {{ birth.delete(&sk); return 0; }}", dports);
        code = code.replace("FILTER_DPORT", &target);
    }
    if let Some(lports) = matches.value_of("localport") {
        let target = format!("if ({}) {{ birth.delete(&sk); return 0; }}", lports);
        code = code.replace("FILTER_LPORT", &target);
    }

    if let Some(_) = matches.value_of("ipv4") {
        code = code.replace("FILTER_FAMILY", "if (family != AF_INET) { return 0; }");
    } else if let Some(_) = matches.value_of("ipv6") {
        code = code.replace("FILTER_FAMILY", "if (family != AF_INET6) { return 0; }");
    }
    code = code.replace("FILTER_PID", "");
    code = code.replace("FILTER_DPORT", "");
    code = code.replace("FILTER_LPORT", "");
    code = code.replace("FILTER_FAMILY", "");

    // bcc will handle the kprobes for us, by the function name we declared
    let mut bpf = BPF::new(&code)?;

    // tcp_set_state is what we declared in the tcplife.c, also act as the attach point
    // let function_name=bpf.fix_syscall_name("__x64_sys_kprobe_tcp_set_state").unwrap();
    // Kprobe::new()
    //     .function("tcp_set_state")
    //     .handler("tcp_set_state")
    //     .attach(&mut bpf)?;

    println!(
        "{:<16} {:<16} {:<10} {:<20} {:<16} {:<20} {:<16} {:<16} {:<16}",
        "PID", "COMM", "VERSION", "SADDR", "DADDR", "PORTS", "RECEIVED", "ACKED", "SPAN"
    );
    let table = bpf.table("ipv4_events")?;
    bpf.init_perf_map(table, print_ipv4_event)?;
    let table = bpf.table("ipv6_events")?;
    bpf.init_perf_map(table, print_ipv6_event)?;

    while runnable.load(Ordering::SeqCst) {
        bpf.perf_map_poll(200);
    }
    println!("Detaching...");
    Ok(())
}

fn print_ipv4_event() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let event = parse_ipv4_struct(x);
        let task = (event.task)
            .iter()
            .map(|&s| s)
            .take_while(|&v| v != 0)
            .collect::<Vec<_>>();
        let task = String::from_utf8(task).unwrap();
        println!(
            "{:<16} {:<16} {:<10} {:<20} {:<16} {:<20} {:<16} {:<16} {:<16} ",
            event.pid,
            &task,
            6,
            event.saddr,
            event.daddr,
            event.ports,
            event.received_bytes,
            event.acked_bytes,
            event.span_us as f64 / 1000.0,
        );
    })
}

fn print_ipv6_event() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let event = parse_ipv6_struct(x);
        let task = &event.task;
        let task = (event.task)
            .iter()
            .map(|&s| s)
            .take_while(|&v| v != 0)
            .collect::<Vec<_>>();
        let task = String::from_utf8(task).unwrap();
        println!(
            "{:<16} {:<16} {:<10} {:<20} {:<16} {:<20} {:<16} {:<16} {:<16}",
            event.pid,
            &task,
            6,
            event.saddr,
            event.daddr,
            event.ports,
            event.received_bytes,
            event.acked_bytes,
            event.span_us as f64 / 1000.0,
        );
    })
}

fn parse_ipv4_struct(x: &[u8]) -> ipv4_data_t {
    unsafe { ptr::read_unaligned(x.as_ptr() as *const ipv4_data_t) }
}

fn parse_ipv6_struct(x: &[u8]) -> ipv6_data_t {
    unsafe { ptr::read_unaligned(x.as_ptr() as *const ipv6_data_t) }
}

fn parse_ipv4_addr(addr: u32) -> IpAddr {
    let a = ((addr >> 24) & 0xff) as u8;
    let b = ((addr >> 16) & 0xff) as u8;
    let c = ((addr >> 8) & 0xff) as u8;
    let d = ((addr >> 0) & 0xff) as u8;
    let r = IpAddr::V4(Ipv4Addr::new(a, b, c, d));
    r
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
