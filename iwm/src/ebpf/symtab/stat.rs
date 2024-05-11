
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "linux")]
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub struct Stat {
    dev: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
impl Stat {
    fn from_file_info(file_info: &fs::Metadata) -> Self {
        let dev = file_info.dev();
        let inode = file_info.ino();
        Stat { dev, inode }
    }
}

#[cfg(target_os = "linux")]
pub fn stat_from_file_info(file_info: &fs::Metadata) -> Stat {
    Stat::from_file_info(file_info)
}

#[cfg(target_os = "macos")]
#[derive(Eq, PartialEq, Clone, Copy, Hash)]
pub struct Stat {
    dev: u64,
    inode: u64,
}

#[cfg(target_os = "macos")]
impl Stat {
    fn from_file_info(file_info: &fs::Metadata) -> Self {
        let dev = file_info.dev();
        let inode = file_info.ino();
        Stat { dev, inode }
    }
}

#[cfg(target_os = "macos")]
pub fn stat_from_file_info(file_info: &fs::Metadata) -> Stat {
    Stat::from_file_info(file_info)
}