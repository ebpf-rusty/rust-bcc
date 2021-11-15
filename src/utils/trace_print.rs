pub const TRACEFS: &'static str = "/sys/kernel/debug/tracing";
use std::io::Result;
use std::{fs::File, io::BufRead, io::BufReader, path::Path};

#[derive(Clone, Debug)]
pub struct PrintkItem {
    comm: String,
    pid: String,
    cpu: String,
    flags: String,
    timestamp: String,
    msg: String,
}

pub fn trace_read() -> Result<String> {
    let p = format!("{}/trace_pipe", TRACEFS);
    let path = Path::new(&p);
    let f = File::open(path).unwrap();
    let mut reader = BufReader::new(f);
    // we set the buf's capacity to be 2048, because epbf program cannot output big content
    // which is limited by it's stack size
    let mut buf = String::with_capacity(2048);
    reader.read_line(&mut buf)?;
    Ok(buf)
}

pub fn trace_parse(line: String) -> PrintkItem {
    let prefix = bytes_to_string(&line.as_bytes()[..16]);
    // 1. command
    let comm = prefix.trim_start();
    let line = &line[17..];
    let timestamp_end = line.find(":").unwrap();
    let x = (&line[..timestamp_end])
        .split(' ')
        .filter(|&s| s.len() != 0)
        .collect::<Vec<_>>();
    debug_assert!(x.len() == 4);
    // 2. pid 3. cpu 4. flags 5. timestamp
    let (pid, cpu, flags, timestamp) = (x[0], x[1], x[2], x[3]);
    let cpu = &cpu[1..(cpu.len() - 1)];

    let line = &line[(timestamp_end + 1)..];
    let sym_end = line.find(":").unwrap();

    // 6. msg (by bpf kernel space program)
    let msg = &line[sym_end + 2..];

    PrintkItem {
        comm: comm.to_owned(),
        pid: pid.to_owned(),
        cpu: cpu.to_owned(),
        flags: flags.to_owned(),
        timestamp: timestamp.to_owned(),
        msg: msg.to_owned(),
    }
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_owned()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    /// test if the parse is ok
    #[test]
    fn t1() {
        let s =
            "            node-310237  [003] d..3 1047996.565391: bpf_trace_printk: Hello, World!";
        let s = String::from(s);
        let r = trace_parse(s);
        println!("{:?}", r);
    }
}
