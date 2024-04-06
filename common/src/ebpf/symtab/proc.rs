use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use crate::ebpf::symtab::elf::symbol_table::SymTabDebugInfo;
use crate::ebpf::symtab::elf_module::{ElfTable, ElfTableOptions};
use crate::ebpf::symtab::procmap::ProcMap;
use crate::ebpf::symtab::symtab::SymbolTable;
use crate::ebpf::symtab::table::Symbol;
use crate::ebpf::symtab::gcache::Resource;

pub struct ProcTable {
    ranges: Vec<Arc<ElfRange>>,
    file_to_table: HashMap<File, ElfTable>,
    options: ProcTableOptions,
    root_fs: PathBuf,
    err: Option<anyhow::Error>
}

pub struct ProcTableDebugInfo {
    elf_tables: HashMap<String, SymTabDebugInfo>,
    size: usize,
    pid: i32,
    last_used_round: i32,
}

pub struct ProcTableOptions {
    pub(crate) pid: i32,
    pub(crate) elf_table_options: ElfTableOptions
}

#[derive(Eq, Ord)]
pub struct ElfRange {
    map_range: ProcMap,
    elf_table: Option<ElfTable>,
}

impl Resource for ProcTable {

    fn refresh(&mut self) {
        if self.err.is_some() {
            return;
        }

        let path = format!("/proc/{}/maps", self.options.pid.to_string());
        match fs::read_to_string(&path) {
            Ok(proc_maps) => {
                self.err = Some(self.refresh_proc_map(proc_maps).into());
            },
            Err(e) => {
                self.err = Some(e.into());
            }
        }
    }

    fn cleanup(&mut self) {
        self.file_to_table
            .iter_mut()
            .map(|_, table| table.cleanup() )
            .collect();
    }
}

impl SymbolTable for ProcTable {

    fn resolve(&mut self, pc: u64) -> Symbol {
        if pc == 0xcccccccccccccccc || pc == 0x9090909090909090 {
            return Symbol {
                start: 0,
                name: "end_of_stack".to_string(),
                module: "[unknown]".to_string(),
            };
        }

        let (i, found) = binary_search_func(&self.ranges, pc, binary_search_elf_range);
        if !found {
            return Symbol::default();
        }

        let r = &self.ranges.get_mut(i).unwrap();
        if let Some(mut t) = &r.elf_table {
            let s = t.resolve(pc); // Cannot borrow immutable local variable `t` as mutable
            let module_offset = pc - t.base;
            return if s.is_empty() {
                Symbol {
                    start: module_offset,
                    module: r.map_range.pathname.clone(),
                    ..Default::default()
                }
            } else {
                Symbol {
                    start: module_offset,
                    name: s,
                    module: r.map_range.pathname.clone(),
                }
            }
        }
        Symbol::default()
    }
}

fn binary_search_func<S, E, T, F>(x: &[E], target: T, mut cmp: F) -> (usize, bool)
    where
        S: AsRef<[E]>,
        E: Ord,
        F: FnMut(&E, &T) -> std::cmp::Ordering,
{
    let mut i = 0;
    let mut j = x.len();
    while i < j {
        let h = (i + j) / 2;
        match cmp(&x[h], &target) {
            std::cmp::Ordering::Less => {
                i = h + 1;
            }
            _ => {
                j = h;
            }
        }
    }
    (i, i < x.len() && cmp(&x[i], &target) == std::cmp::Ordering::Equal)
}

fn binary_search_elf_range(e: &ElfRange, pc: u64) -> i32 {
    if pc < e.map_range.start_addr {
        return 1;
    }
    if pc >= e.map_range.end_addr {
        return -1;
    }
    0
}

impl ProcTable {
    pub(crate) fn new(options: ProcTableOptions) -> Self {
        Self {
            ranges: Vec::new(),
            file_to_table: HashMap::new(),
            options,
            root_fs: PathBuf::from(format!("/proc/{}/root", options.pid.to_string())),
            err: None,
        }
    }

    fn refresh_proc_map(&mut self, proc_maps: String) -> Result<(), String> {
        // todo support perf map files
        for range in &mut self.ranges {
            range.elf_table = None;
        }
        self.ranges.clear();

        let mut files_to_keep: HashMap<File, ()> = HashMap::new();
        let maps = match parse_proc_maps_executable_modules(proc_maps.deref(), true) {
            Ok(maps) => maps,
            Err(err) => return Err(err),
        };

        for map in maps {
            let range = ElfRange {
                map_range: map,
                elf_table: None,
            };
            self.ranges.push(range.clone());
            if let Some(elf_table) = self.get_elf_table(&range) {
                self.file_to_table.insert(range.map_range.file(), elf_table);
                files_to_keep.insert(range.map_range.file(), ());
            }
        }

        let files_to_delete: Vec<File> = self
            .file_to_table
            .keys()
            .filter(|f| !files_to_keep.contains_key(*f))
            .cloned()
            .collect();

        for file in files_to_delete {
            self.file_to_table.remove(&file);
        }

        Ok(())
    }
}

fn parse_proc_maps_executable_modules(proc_maps: &str, executable_only: bool) -> Result<Vec<ProcMap>, String> {
    let mut modules = Vec::new();
    let mut remaining = proc_maps;
    while !remaining.is_empty() {
        let nl = remaining.iter().position(|&x| x == b'\n').unwrap_or(remaining.len());
        let (line, rest) = remaining.split_at(nl);
        remaining = if rest.is_empty() { rest } else { &rest[1..] };
        if line.is_empty() {
            continue;
        }
        if let Some(module) = parse_proc_map_line(line, executable_only)? {
            modules.push(module);
        }
    }
    Ok(modules)
}

fn parse_proc_map_line(line: &str, executable_only: bool) -> Result<Option<ProcMap>, String> {
    let line_str = match std::str::from_utf8(line.as_ref()) {
        Ok(s) => s,
        Err(_) => return Err("Error converting byte slice to string".to_string()),
    };
    let fields: Vec<&str> = line_str.split_whitespace().collect();
    if fields.len() < 5 {
        return Ok(None);
    }
    let permissions = fields[1];
    if executable_only && !permissions.contains('x') {
        return Ok(None);
    }
    let addr_parts: Vec<&str> = fields[0].split('-').collect();
    if addr_parts.len() != 2 {
        return Err("Invalid address range format".to_string());
    }
    let start = u64::from_str_radix(addr_parts[0], 16).map_err(|_| "Invalid start address".to_string())?;
    let end = u64::from_str_radix(addr_parts[1], 16).map_err(|_| "Invalid end address".to_string())?;
    Ok(Some(
        ProcMap {
            start_addr: start,
            end_addr: end,
            ..Default::default()
        }
    ))
}

fn token_to_string_unsafe(tok: &[u8]) -> String {
    let ptr = tok.as_ptr();
    let len = tok.len();
    unsafe {
        String::from_utf8_unchecked(Vec::from_raw_parts(ptr as *mut u8, len, len))
    }
}

