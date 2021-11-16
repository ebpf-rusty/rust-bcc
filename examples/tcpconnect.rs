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

lazy_static! {
    static ref COUNT_AND_TRACE_TEXT: HashMap<&'static str, CountOrTrace> = init_count_trace_text();
}

struct CountOrTrace {
    count: &'static str,
    trace: &'static str,
}

fn init_count_trace_text() -> HashMap<&'static str, CountOrTrace> {
    let mut data = HashMap::new();

    let v4_count = r#"struct ipv4_flow_key_t flow_key = {};
    flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
    flow_key.daddr = skp->__sk_common.skc_daddr;
    flow_key.dport = ntohs(dport);
    ipv4_count.increment(flow_key);"#;

    let v4_trace = r#"struct ipv4_data_t data4 = {.pid = pid };
    data4.uid = bpf_get_current_uid_gid();
    data4.ts_us = bpf_ktime_get_ns() / 1000;
    data4.saddr = skp->__sk_common.skc_rcv_saddr;
    data4.daddr = skp->__sk_common.skc_daddr;
    data4.lport = lport;
    data4.dport = ntohs(dport);
    bpf_get_current_comm(&data4.task, sizeof(data4.task));
    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));"#;

    let v6_count = r#"struct ipv6_flow_key_t flow_key = {};
    bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr),    bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr),        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr),
        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    flow_key.dport = ntohs(dport);
    ipv6_count.increment(flow_key);"#;

    let v6_trace = r#"struct ipv6_data_t data6 = {.pid = pid };
    data6.uid = bpf_get_current_uid_gid();
    data6.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    data6.lport = lport;
    data6.dport = ntohs(dport);
    bpf_get_current_comm(&data6.task, sizeof(data6.task));
    ipv6_events.perf_submit(ctx, &data6, sizeof(data6));"#;

    let ipv4 = CountOrTrace {
        count: v4_count,
        trace: v4_trace,
    };

    let ipv6 = CountOrTrace {
        count: v6_count,
        trace: v6_trace,
    };
    data.insert("ipv4", ipv4);
    data.insert("ipv6", ipv6);
    data
}

#[repr(C)]
struct ipv4_data_t {
    ts_us: u64,
    pid: u32,
    uid: u32,
    saddr: u32,
    daddr: u32,
    // local port
    lport: u16,
    // destination port
    dport: u16,
    task: [u8; 128],
}

#[repr(C)]
struct ipv6_data_t {
    ts_us: u64,
    pid: u32,
    uid: u32,
    saddr: i128,
    daddr: i128,
    lport: u16,
    dport: u16,
    task: [u8; 128],
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("tcpconnect")
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .help("trace this PID only")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("uid")
                .long("uid")
                .short("u")
                .help("trace this UID only")
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
            Arg::with_name("Port")
                .long("Port")
                .short("P")
                .help("comma-separated list of destination ports to trace")
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
    code = code.replace("FILTER_PID", "");
    code = code.replace("FILTER_UID", "");
    code = code.replace("FILTER_PORT", "");
    code = code.replace("FILTER_FAMILY", "");

    let mut bpf = BPF::new(&code)?;

    Kprobe::new()
        .function("tcp_v4_connect")
        .handler("trace_connect_entry")
        .attach(&mut bpf)?;
    Kprobe::new()
        .function("tcp_v6_connect")
        .handler("trace_connect_entry")
        .attach(&mut bpf)?;
    Kretprobe::new()
        .function("tcp_v4_connect")
        .handler("trace_connect_v4_return")
        .attach(&mut bpf)?;
    Kretprobe::new()
        .function("tcp_v6_connect")
        .handler("trace_connect_v4_return")
        .attach(&mut bpf)?;

    println!(
        "{:<10} {:<16} {:<8} {:<20} {:<16} {:<20} {:<16}",
        "PID", "COMM", "VERSION", "SADDR", "LPORT", "DADDR", "DPORT"
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
            "{:<10} {:<16} {:<8} {:<20} {:<16} {:<20} {:<16}",
            event.pid,
            &task,
            4,
            parse_ipv4_addr(event.saddr),
            event.lport,
            parse_ipv4_addr(event.daddr),
            event.dport
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
            "{:<16} {:<16} {:<10} {:<20} {:<16} {:<20} {:<16}",
            // "{:<16} {:<16} {:<16} {:>30} {:>16} {:>30} {:>16}",
            event.pid,
            &task,
            6,
            event.saddr,
            event.lport,
            event.daddr,
            event.dport
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
