use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use crate::ebpf::symtab::table::{Symbol, SymbolTab};
use crate::error::Error::SymbolError;
use crate::error::Result;

const KALLSYMS_MODULE: &str = "kernel";

pub fn new_kallsyms() -> Result<SymbolTab> {
    new_kallsyms_from_file("/proc/kallsyms")
}

fn new_kallsyms_from_file<P: AsRef<Path>>(path: P) -> Result<SymbolTab> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);
    new_kallsyms_from_data(reader)
}

fn new_kallsyms_from_data<B: BufRead>(buf: B) -> Result<SymbolTab> {
    let mut syms = Vec::new();
    let mut all_zeros = true;

    let kernel_addr_space = if cfg!(target_arch = "x86_64") {
        0x00ffffffffffffff
    } else {
        0
    };

    for line in buf.lines() {
        let line = line.unwrap();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let addr_part = parts.next().ok_or(SymbolError("no space found".to_string())).unwrap();
        let typ = parts.next().ok_or(SymbolError("no space found".to_string())).unwrap();
        let name_part = parts.next().unwrap_or(KALLSYMS_MODULE); // Assuming module name is always present after name

        if typ.starts_with('b') || typ.starts_with('B') || typ.starts_with('d') ||
            typ.starts_with('D') || typ.starts_with('r') || typ.starts_with('R') {
            continue;
        }

        let istart = u64::from_str_radix(addr_part, 16).map_err(|e| SymbolError(e.to_string())).unwrap();

        if istart < kernel_addr_space {
            continue;
        }

        let mod_name = if name_part.starts_with('[') && name_part.ends_with(']') {
            &name_part[1..name_part.len() - 1]
        } else {
            name_part
        };

        if istart != 0 {
            all_zeros = false;
        }

        syms.push(Symbol {
            start: istart,
            name: name_part.to_string(),
            module: mod_name.to_string(),
        });
    }

    if all_zeros {
        Ok(SymbolTab::new(Vec::new()))
    } else {
        Ok(SymbolTab::new(syms))
    }
}
