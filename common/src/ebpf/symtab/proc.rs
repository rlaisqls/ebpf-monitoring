use std::collections::HashMap;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use crate::ebpf::symtab::elf::symbol_table::SymTabDebugInfo;
use crate::ebpf::symtab::elf_module::{ElfTable, ElfTableOptions};
use crate::ebpf::symtab::procmap::{File, ProcMap};
use crate::ebpf::symtab::symtab::SymbolTable;
use crate::ebpf::symtab::table::Symbol;
use crate::ebpf::symtab::gcache::Resource;
use crate::error::Error::{ProcError};
use crate::error::Result;

pub struct ProcTable<'a> {
    ranges: Vec<Arc<ElfRange<'a>>>,
    file_to_table: HashMap<File, ElfTable<'a>>,
    root_fs: PathBuf,
    err: Option<crate::error::Error>,
    pid: i32,
    elf_table_options: ElfTableOptions<'a>
}

pub struct ProcTableDebugInfo {
    elf_tables: HashMap<String, SymTabDebugInfo>,
    size: usize,
    pid: i32,
    pub(crate) last_used_round: i32,
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct ElfRange<'a> {
    map_range: ProcMap,
    elf_table: Option<ElfTable<'a>>,
}

impl Resource for ProcTable<'_> {
    fn refresh(&mut self) {
        self.refresh()
    }

    fn cleanup(&mut self) {
       self.cleanup()
    }
}

impl SymbolTable for ProcTable<'_> {
    fn refresh(&mut self) {
        self.refresh()
    }

    fn cleanup(&mut self) {
        self.cleanup()
    }

    fn resolve(&mut self, pc: u64) -> Option<&Symbol> {
        if pc == 0xcccccccccccccccc || pc == 0x9090909090909090 {
            return Some(&Symbol {
                start: 0,
                name: "end_of_stack".to_string(),
                module: "[unknown]".to_string(),
            });
        }

        let (i, found) = binary_search_func(&self.ranges, pc, binary_search_elf_range);
        if !found { return None; }

        let r = &self.ranges.get_mut(i).unwrap();
        if let Some(mut t) = &r.elf_table {
            let module_offset = pc - t.base;
            return match t.resolve(pc) {
                Some(s) => {
                    Some(&Symbol {
                        start: module_offset,
                        name: s,
                        module: r.map_range.pathname.clone(),
                    })
                }
                None => {
                    Some(&Symbol {
                        start: module_offset,
                        module: r.map_range.pathname.clone(),
                        ..Default::default()
                    })
                }
            }
        }
        None
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

impl<'a> ProcTable<'a> {
    pub(crate) fn new(pid: i32, elf_table_options: ElfTableOptions<'a>) -> Self {
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
                self.err = Some(self.refresh_proc_map(proc_maps).into());
            },
            Err(e) => {
                self.err = Some(e.into());
            }
        }
    }

    fn cleanup(&mut self) {
        let _ = self.file_to_table
            .iter_mut()
            .map(|(_, table)| table.cleanup())
            .collect();
    }

    fn refresh_proc_map(&mut self, proc_maps: String) -> Result<()> {
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
            if let Some(_elf_table) = self.get_elf_table(map) {
                files_to_keep.insert(map.file(), ());
                self.ranges.push(Arc::new(ElfRange {
                    map_range: map.clone(),
                    elf_table: None,
                }));
            }
        }

        let files_to_delete: Vec<File> = self
            .file_to_table
            .keys()
            .filter(|f| !files_to_keep.contains_key(*f))
            .collect();

        for file in files_to_delete {
            self.file_to_table.remove(&file);
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
            let d = elf.table.debug_info();
            if d.size != 0 {
                res.elf_tables.insert(format!("{} {} {}", file.dev, file.inode, file.path), d);
            }
        }
        res
    }

    fn get_elf_table(&mut self, r: ProcMap) -> Option<&mut ElfTable> {
        let f = r.file();
        if let Some(e) = self.file_to_table.get_mut(&f) {
            Some(e)
        } else {
            if let Some(e) = self.create_elf_table(r) {
                self.file_to_table.insert(f, e);
            }
            self.file_to_table.get_mut(&f)
        }
    }

    fn create_elf_table(&self, m: ProcMap) -> Option<ElfTable> {
        if !m.pathname.starts_with('/') {
            return None;
        }
        Some(ElfTable::new(
            m,
            self.root_fs.to_str().unwrap().to_string(),
            self.elf_table_options.clone()
        ))
    }
}

impl FromIterator<&File> for Vec<File> {
    fn from_iter<I: for<'a> IntoIterator<Item = &File>>(iter: I) -> Self {
        iter.into_iter().map(|&f| f.clone()).collect()
    }
}

fn parse_proc_maps_executable_modules(proc_maps: &str, executable_only: bool) -> Result<Vec<ProcMap>> {
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
            modules.push(module);
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

