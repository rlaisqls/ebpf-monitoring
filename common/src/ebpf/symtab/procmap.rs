use std::io::{self, BufRead};
use std::str::FromStr;

#[derive(Debug)]
pub struct ProcMapPermissions {
    read: bool,
    write: bool,
    execute: bool,
    shared: bool,
    private: bool,
}

#[derive(Debug)]
pub struct ProcMap {
    pub(crate) start_addr: u64,
    pub(crate) end_addr: u64,
    perms: ProcMapPermissions,
    offset: i64,
    dev: u64,
    inode: u64,
    pathname: String,
}


fn parse_proc_map_line(line: &str, executable_only: bool) -> Result<Option<ProcMap>, &'static str> {
    let mut parts = line.split_whitespace();
    let err_msg = "Invalid procmap entry";
    let addrs_str = parts.next().ok_or(err_msg)?;
    let perms_str = parts.next().ok_or(err_msg)?;
    let offset_str = parts.next().ok_or(err_msg)?;
    let device_str = parts.next().ok_or(err_msg)?;
    let inode_str = parts.next().unwrap_or_default();
    let pathname = parts.collect::<Vec<&str>>().join(" ");

    let perms = parse_permissions(perms_str)?;
    if executable_only && !perms.execute {
        return Ok(None);
    }

    let (start_addr, end_addr) = parse_addresses(addrs_str)?;
    let offset = i64::from_str_radix(offset_str, 16).map_err(|_| "Invalid offset")?;
    let dev = parse_device(device_str)?;
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
        if let Some(proc_map) = parse_proc_map_line(line, executable_only)? {
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

    let major = u32::from_str_radix(parts[0], 16)?;
    let minor = u32::from_str_radix(parts[1], 16)?;

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
    let i = s.iter().position(|&b| b == b'-').ok_or("Invalid address")?;
    let (saddr_bytes, eaddr_bytes) = s.split_at(i);
    let eaddr_bytes = &eaddr_bytes[1..]; // '-' 다음 바이트로 이동

    let saddr = parse_address(saddr_bytes)?;
    let eaddr = parse_address(eaddr_bytes)?;

    Ok((saddr, eaddr))
}