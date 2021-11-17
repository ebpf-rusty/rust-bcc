use bcc::XDPMode::{XDP_FLAGS_HW_MODE, XDP_FLAGS_SKB_MODE};
use bcc::{BPFBuilder, BccError, XDP, trace_parse, trace_read};
use byteorder::{LittleEndian, ReadBytesExt};
use clap::{App, Arg};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("xdp log")
        .about("Drop incoming packets on XDP layer and count for which protocol type")
        .arg(
            Arg::with_name("device")
                .long("device")
                .short("d")
                .help("Device name to attach the XDP program")
                .default_value("eth0")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("hardware-offload-mode")
                .long("hw-offload-mode")
                .short("h")
                .help("Run the XDP program in hardware offload mode XDP_FLAGS_HW_MODE")
                .takes_value(true),
        )
        .get_matches();

    let hw_offload_mode_enabled = matches.is_present("hw-offload-mode");
    let mode = if hw_offload_mode_enabled {
        XDP_FLAGS_HW_MODE
    } else {
        XDP_FLAGS_SKB_MODE
    };

    let device = matches
        .value_of("device")
        .expect("safe since `device` has a default value");

    let code = include_str!("xdp_log.c");
    let cflags = &["-w", "-DRETURNCODE=XDP_DROP", "-DCTXTYPE=xdp_md"];
    let builder = {
        let builder = BPFBuilder::new(code)?.cflags(cflags)?;
        if hw_offload_mode_enabled {
            builder.device(device)?
        } else {
            builder
        }
    };
    let mut bpf = builder.build()?;

    XDP::new()
        .handler("xdp_raw_parser")
        .device(device)
        .mode(mode)
        .attach(&mut bpf)?;

    println!("print xdp log, hit CTRL+C to stop");
    while runnable.load(Ordering::SeqCst) {
        let r = trace_read();
        match r {
            Ok(s) => {
                let item = trace_parse(s);
                println!("{:?}", item);
            }
            Err(e) => println!("{:?}", e),
        }
    }

    Ok(())
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    if let Err(err) = do_main(runnable) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
