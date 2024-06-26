use std::io::{self, BufRead};
use std::str::FromStr;

// ProcMapPermissions contains permission settings read from `/proc/[pid]/maps`.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct ProcMapPermissions {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) execute: bool,
    pub(crate) shared: bool,
    pub(crate) private: bool,
}

impl Default for ProcMapPermissions {
    fn default() -> Self {
        ProcMapPermissions {
            read: true,
            write: true,
            execute: true,
            shared: true,
            private: true,
        }
    }
}

// ProcMap contains the process memory-mappings of the process
// read from `/proc/[pid]/maps`.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct ProcMap {
    pub(crate) start_addr: u64,
    pub(crate) end_addr: u64,
    pub(crate) pathname: String,
    pub(crate) offset: i64,
    pub(crate) perms: ProcMapPermissions,
    pub(crate) dev: u64,
    pub(crate) inode: u64,
}


#[derive(PartialEq, PartialOrd, Eq, Ord, Hash, Clone)]
pub struct File {
    pub(crate) dev:   u64,
    pub(crate) inode: u64,
    pub(crate) path:  String
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
    let i = s.chars().position(|b| b == '-').ok_or("Invalid address").unwrap();
    let (saddr_bytes, eaddr_bytes) = s.split_at(i);
    let eaddr_bytes = &eaddr_bytes[1..]; // Move to next byte of '-'

    let saddr = parse_address(saddr_bytes).unwrap();
    let eaddr = parse_address(eaddr_bytes).unwrap();

    Ok((saddr, eaddr))
}