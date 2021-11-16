use bcc::perf_event::{Event, SoftwareEvent};
use bcc::table::Entry;
use bcc::{clear_screen, trace_parse, trace_read, BccError, Kprobe};
use bcc::{PerfEvent, PerfEventArray, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{io::BufRead, io::BufReader};
use std::{thread, time};

const LOAD_AVG: &'static str = "/proc/loadavg";
const DISK_STATS: &'static str = "/proc/diskstats";

lazy_static! {
    static ref DISK_LOOKUP: HashMap<String, String> = disklookup();
}

fn disklookup() -> HashMap<String, String> {
    let mut a = HashMap::new();
    let path = Path::new(DISK_STATS);
    let f = File::open(path).unwrap();
    let mut reader = BufReader::new(f);
    let mut buf = String::with_capacity(1024);
    while reader.read_line(&mut buf).is_ok() {
        let infos = buf.split(" ").collect::<Vec<_>>();
        a.insert(
            format!("{},{}", infos[0], infos[1]),
            format!("{}", infos[2]),
        );
    }
    a
}

fn loadstat() -> String {
    let file = File::open("/proc/loadavg").unwrap();
    let mut reader = BufReader::new(file);
    let mut buf = String::with_capacity(1024);
    reader.read_to_string(&mut buf);
    buf
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let cpus = bcc::cpuonline::get()?.len() as u32;
    let code = format!(
        "{}\n{}",
        format!("#define NUM_CPU {}", cpus),
        include_str!("biotop.c").to_string()
    );
    let mut bpf = BPF::new(&code)?;

    // Kprobe::new()
    //     .function("blk_account_io_start")
    //     .handler("trace_pid_start")
    //     .attach(&mut bpf)?;
    Kprobe::new()
        .function("blk_account_io_start")
        .handler("trace_req_start")
        .attach(&mut bpf)?;
    // nothing happen here in most cases
    if let Ok(v) = bpf.get_kprobe_functions("blk_start_request") {
        if v.len() > 0 {
            Kprobe::new()
                .function("blk_start_request")
                .handler("trace_req_start")
                .attach(&mut bpf)?;
        }
    }
    Kprobe::new()
        .function("blk_account_io_done")
        .handler("trace_req_completion")
        .attach(&mut bpf)?;

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));

        println!("{:?} loadavg: {}", std::time::Instant::now(), loadstat());
        println!(
            "{:>6} {:>16} {:>1} {:>3} {:>3} {:>8} {:>5} {:>7} {:>6}",
            "PID", "COMM", "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms"
        );
        let mut table = bpf.table("counts")?;
        let mut snapshot = table.iter().collect::<Vec<_>>();
        snapshot.sort_by(|a, b| a.value[1].cmp(&b.value[1]));
        println!("length:{}", snapshot.len());
        for Entry { key, value } in snapshot.iter() {
            /**
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [8, 0, 0, 0, 0, 0, 0, 0, 20, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
    [0, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 16, 0, 0, 0, 0, 0, 0, 112, 3, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
             */
            println!("{:?}, {:?}", key, value);
        }
        // println!(
        //     "{:>6} {:>16} {:>1} {:>3} {:>3} {:>8} {:>5} {:>7} {:>6}",
        //     "PID", "COMM", "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms"
        // );
        // // println!(
        // //     "%-6d %-16s %1s %-3d %-3d %-8s %5s %7s %6.2f",
        // //     k.pid,
        // //     k.name.decode("utf-8", "replace"),
        // //     if k.rwflag { "W" } else { "R" },
        // //     k.major,
        // //     k.minor,
        // //     diskname,
        // //     v.io,
        // //     v.bytes / 1024,
        // //     avg_ms
        // // );
        table.delete_all();
        clear_screen();
    }
    println!("detaching...");
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
