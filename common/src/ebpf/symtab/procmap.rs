use std::io::{self, BufRead};
use std::str::FromStr;
use crate::ebpf::symtab::proc::ProcTable;


// ProcMapPermissions contains permission settings read from `/proc/[pid]/maps`.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProcMapPermissions {
    read: bool,
    write: bool,
    execute: bool,
    shared: bool,
    private: bool,
}

// ProcMap contains the process memory-mappings of the process
// read from `/proc/[pid]/maps`.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProcMap {
    pub(crate) start_addr: u64,
    pub(crate) end_addr: u64,
    pub(crate) pathname: String,
    pub(crate) offset: i64,
    perms: ProcMapPermissions,
    dev: u64,
    inode: u64,
}


#[derive(PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct File {
    dev:   u64,
    inode: u64,
    path:  String
}

impl ProcMap {
    pub(crate) fn file(&self) -> File {
        File {
            dev: self.dev,
            inode: self.inode,
            path: self.pathname.clone()
        }
    }
}

impl Default for ProcMap {
    fn default() -> Self {
        Self {
            start_addr: 0,
            end_addr: 0,
            pathname: "".to_string(),
            perms: ProcMapPermissions {
                read: false,
                write: false,
                execute: false,
                shared: false,
                private: false,
            },
            offset: 0,
            dev: 0,
            inode: 0,
        }
    }
}

fn parse_proc_map_line(line: &str, executable_only: bool) -> Result<Option<ProcMap>, &'static str> {
    let mut parts = line.split_whitespace();
    let err_msg = "Invalid procmap entry";
    let addrs_str = parts.next().ok_or(err_msg).unwrap();
    let perms_str = parts.next().ok_or(err_msg).unwrap();
    let offset_str = parts.next().ok_or(err_msg).unwrap();
    let device_str = parts.next().ok_or(err_msg).unwrap();
    let inode_str = parts.next().unwrap_or_default();
    let pathname = parts.collect::<Vec<&str>>().join(" ");

    let perms = parse_permissions(perms_str).unwrap();
    if executable_only && !perms.execute {
        return Ok(None);
    }

    let (start_addr, end_addr) = parse_addresses(addrs_str).unwrap();
    let offset = i64::from_str_radix(offset_str, 16).map_err(|_| "Invalid offset").unwrap();
    let dev = parse_device(device_str).unwrap();
    let inode = u64::from_str(inode_str).unwrap_or_default();

    Ok(Some(ProcMap {
        start_addr,
        end_addr,
        perms,
        offset,
        dev,
        inode,
        pathname,
    }))
}

fn parse_proc_maps_executable_modules(proc_maps: &str, executable_only: bool) -> Result<Vec<ProcMap>, &'static str> {
    let mut modules = Vec::new();
    for line in proc_maps.lines() {
        if let Some(proc_map) = parse_proc_map_line(line, executable_only).unwrap() {
            modules.push(proc_map);
        }
    }
    Ok(modules)
}


fn parse_permissions(s: &str) -> Option<ProcMapPermissions> {
    if s.len() < 4 {
        return None;
    }
    Some(ProcMapPermissions {
        read: s.contains('r'),
        write: s.contains('w'),
        execute: s.contains('x'),
        shared: s.contains('s'),
        private: s.contains('p'),
    })
}

fn parse_address(s: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(s, 16)
}

fn parse_device(s: &str) -> Result<u64, io::Error> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(io::Error::new(io::ErrorKind::Other, "Unexpected number of fields"));
    }

    let major = u32::from_str_radix(parts[0], 16).unwrap();
    let minor = u32::from_str_radix(parts[1], 16).unwrap();

    Ok(mkdev(major, minor))
}

fn mkdev(major: u32, minor: u32) -> u64 {
    let dev = ((major & 0x00000fff) as u64) << 8;
    let dev = dev | ((major & 0xfffff000) as u64) << 32;
    let dev = dev | ((minor & 0x000000ff) as u64) << 0;
    let dev = dev | ((minor & 0xffffff00) as u64) << 12;
    dev
}


fn parse_addresses(s: &str) -> Result<(u64, u64), &'static str> {
    let i = s.chars().position(|b| b == b'-').ok_or("Invalid address").unwrap();
    let (saddr_bytes, eaddr_bytes) = s.split_at(i);
    let eaddr_bytes = &eaddr_bytes[1..]; // '-' 다음 바이트로 이동

    let saddr = parse_address(saddr_bytes).unwrap();
    let eaddr = parse_address(eaddr_bytes).unwrap();

    Ok((saddr, eaddr))
}