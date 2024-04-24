use std::fs;
use crate::error::Result;

const CPU_ONLINE: &str = "/sys/devices/system/cpu/online";

pub fn get() -> Result<Vec<u32>> {
    let buf = fs::read_to_string(CPU_ONLINE).unwrap();
    read_cpu_range(&buf)
}

pub fn read_cpu_range(cpu_range_str: &str) -> Result<Vec<u32>> {
    let mut cpus = Vec::new();
    for cpu_range in cpu_range_str.trim().split(',') {

        let range_op: Vec<&str> = cpu_range.split('-').collect();
        let first: u32 = range_op[0].parse().unwrap();
        if range_op.len() == 1 {
            cpus.push(first);
            continue;
        }
        let last: u32 = range_op[1].parse().unwrap();
        for n in first..=last {
            cpus.push(n);
        }
    }
    Ok(cpus)
}