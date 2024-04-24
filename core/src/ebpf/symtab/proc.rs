use std::cmp::Ordering::{Equal, Greater, Less};
use std::collections::HashMap;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::ebpf::symtab::elf::symbol_table::SymTabDebugInfo;
use crate::ebpf::symtab::elf_module::{ElfTable, ElfTableOptions};
use crate::ebpf::symtab::procmap::{File, ProcMap};
use crate::ebpf::symtab::symtab::SymbolTable;
use crate::ebpf::symtab::table::Symbol;
use crate::ebpf::symtab::gcache::Resource;
use crate::error::Error::{ProcError};
use crate::error::Result;

pub struct ProcTable {
    ranges: Vec<Arc<Mutex<ElfRange>>>,
    file_to_table: HashMap<File, Arc<Mutex<ElfTable>>>,
    root_fs: PathBuf,
    err: Option<crate::error::Error>,
    pid: i32,
    elf_table_options: ElfTableOptions
}
unsafe impl Sync for ProcTable {}

#[derive(Debug)]
pub struct ProcTableDebugInfo {
    elf_tables: HashMap<String, SymTabDebugInfo>,
    size: usize,
    pid: i32,
    pub(crate) last_used_round: i32,
}

pub struct ElfRange {
    map_range: Arc<Mutex<ProcMap>>,
    elf_table: Arc<Mutex<ElfTable>>
}

impl Resource for ProcTable {
    fn refresh(&mut self) {
        self.refresh()
    }

    fn cleanup(&mut self) {
        self.cleanup()
    }
}

impl SymbolTable for ProcTable {
    fn refresh(&mut self) {
        self.refresh()
    }

    fn cleanup(&mut self) {
        self.cleanup()
    }

    fn resolve(&mut self, pc: u64) -> Option<Symbol> {
        if pc == 0xcccccccccccccccc || pc == 0x9090909090909090 {
            return Some(Symbol {
                start: 0,
                name: "end_of_stack".to_string(),
                module: "[unknown]".to_string(),
            });
        }

        let i = self.ranges.binary_search_by(|e| binary_search_elf_range(e, pc));
        if i.is_err() {
            return Some(Symbol::default());
        }

        let rr = &self.ranges.get_mut(i.unwrap()).unwrap();
        let r = rr.lock().unwrap();
        let mut et = r.elf_table.lock().unwrap();
        let module_offset = pc - et.base;
        return match et.resolve(pc) {
            Some(s) => {
                let mr = r.map_range.lock().unwrap();
                Some(Symbol {
                    start: module_offset,
                    name: s,
                    module: mr.pathname.clone(),
                })
            }
            None => {
                let mr = r.map_range.lock().unwrap();
                Some(Symbol {
                    start: module_offset,
                    name: "".to_string(),
                    module: mr.pathname.clone(),
                })
            }
        };
        Some(Symbol::default())
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
            Less => {
                i = h + 1;
            }
            _ => {
                j = h;
            }
        }
    }
    (i, i < x.len() && cmp(&x[i], &target) == Equal)
}

fn binary_search_elf_range(e: &Arc<Mutex<ElfRange>>, pc: u64) -> std::cmp::Ordering {
    let m = e.lock().unwrap();
    let mr = m.map_range.lock().unwrap();
    if pc < mr.start_addr {
        Greater
    } else if pc >= mr.end_addr {
        Less
    } else {
        Equal
    }
}

impl ProcTable {
    pub(crate) fn new(pid: i32, elf_table_options: ElfTableOptions) -> Self {
        Self {
            ranges: Vec::new(),
            file_to_table: HashMap::new(),
            pid,
            elf_table_options,
            root_fs: PathBuf::from(format!("/proc/{}/root", pid.to_string())),
            err: None,
        }
    }

    fn refresh(&mut self) {
        if self.err.is_some() {
            return;
        }

        let path = format!("/proc/{}/maps", self.pid.to_string());
        match fs::read_to_string(&path) {
            Ok(proc_maps) => {
                match self.refresh_proc_map(proc_maps) {
                    Err(e) => {
                        self.err = Some(e);
                    }
                    _ => {}
                }
            },
            Err(e) => {
                self.err = Some(ProcError(e.to_string()));
            }
        }
    }

    fn cleanup(&mut self) {
        self.file_to_table
            .iter_mut()
            .for_each(|(_, table)| {
                let mut t = table.lock().unwrap();
                t.cleanup()
            })
    }

    fn refresh_proc_map(&mut self, proc_maps: String) -> Result<()> {
        // todo support perf map files
        // for range in &mut self.ranges {
        //     range.elf_table = None;
        // }
        self.ranges.clear();

        let mut files_to_keep: HashMap<File, ()> = HashMap::new();
        let maps = match parse_proc_maps_executable_modules(proc_maps.deref(), true) {
            Ok(maps) => maps,
            Err(err) => return Err(err),
        };

        for map in maps {
            let m = map.lock().unwrap();
            files_to_keep.insert(m.file(), ());
            let elf_table = self.get_elf_table(map.clone()).unwrap().clone();
            self.ranges.push(Arc::new(Mutex::new(ElfRange {
                map_range: map.clone(),
                elf_table,
            })));
        }

        let mut keys_to_remove = Vec::new();
        for (key, _value) in self.file_to_table.iter() {
            if !files_to_keep.contains_key(key) {
                keys_to_remove.push(key.clone());
            }
        }
        for key in keys_to_remove.iter() {
            self.file_to_table.remove(key);
        }
        Ok(())
    }

    pub(crate) fn debug_info(&self) -> ProcTableDebugInfo {
        let mut res = ProcTableDebugInfo {
            pid: self.pid,
            size: self.file_to_table.len(),
            elf_tables: HashMap::new(),
            last_used_round: 0,
        };
        for (file, elf) in &self.file_to_table {
            let e = elf.lock().unwrap();
            let table = e.table.lock().unwrap();
            let d = table.debug_info();
            if d.size != 0 {
                res.elf_tables.insert(format!("{} {} {}", file.dev, file.inode, file.path), d);
            }
        }
        res
    }

    fn get_elf_table(&mut self, rr: Arc<Mutex<ProcMap>>) -> Option<Arc<Mutex<ElfTable>>> {
        let r = rr.lock().unwrap();

        let a = self.file_to_table.get(&r.clone().file());
        if a.is_some() {
            return Some(a.unwrap().clone());
        }

        let b = self.create_elf_table(rr.clone());
        if b.is_some() {
            let bb = b.unwrap();
            self.file_to_table.insert(r.file().clone(), bb.clone());
            return Some(bb.clone());
        }
        None
    }

    fn create_elf_table(&self, m: Arc<Mutex<ProcMap>>) -> Option<Arc<Mutex<ElfTable>>> {
        if !m.lock().unwrap().pathname.starts_with('/') {
            return None;
        }
        Some(Arc::new(Mutex::new(ElfTable::new(
            m,
            self.root_fs.to_str().unwrap().to_string(),
            self.elf_table_options.clone()
        ))))
    }
}

pub fn parse_proc_maps_executable_modules(proc_maps: &str, executable_only: bool) -> Result<Vec<Arc<Mutex<ProcMap>>>> {
    let mut modules = Vec::new();
    let mut remaining = proc_maps;
    while !remaining.is_empty() {
        let nl = remaining.chars().position(|x| x == '\n').unwrap_or(remaining.len());
        let (line, rest) = remaining.split_at(nl);
        remaining = if rest.is_empty() { rest } else { &rest[1..] };
        if line.is_empty() {
            continue;
        }
        if let Some(module) = parse_proc_map_line(line, executable_only).unwrap() {
            modules.push(Arc::new(Mutex::new(module)));
        }
    }
    Ok(modules)
}

fn parse_proc_map_line(line: &str, executable_only: bool) -> Result<Option<ProcMap>> {
    let line_str = match std::str::from_utf8(line.as_ref()) {
        Ok(s) => s,
        Err(_) => return Err(ProcError("Error converting byte slice to string".to_string())),
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
        return Err(ProcError("Invalid address range format".to_string()));
    }
    let start = u64::from_str_radix(addr_parts[0], 16).map_err(|_| "Invalid start address".to_string()).unwrap();
    let end = u64::from_str_radix(addr_parts[1], 16).map_err(|_| "Invalid end address".to_string()).unwrap();
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

