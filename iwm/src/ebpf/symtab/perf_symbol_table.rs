use std::cmp::Ordering::{Equal, Greater, Less};
use std::fs;
use std::ops::Deref;

use crate::ebpf::symtab::gcache::Resource;
use crate::ebpf::symtab::procmap::{ProcMap, ProcMapPermissions};
use crate::ebpf::symtab::symtab::SymbolTable;
use crate::ebpf::symtab::table::Symbol;
use crate::error::Error::ProcError;

pub struct PerfSymbolTable {
	pid: i32,
	err: Option<crate::error::Error>,
	ranges: Vec<ProcMap>
}

impl Resource for PerfSymbolTable {
	fn refresh_resource(&mut self) {
		self.refresh()
	}
	fn cleanup_resource(&mut self) {
		self.cleanup()
	}
}

impl SymbolTable for PerfSymbolTable {

	fn refresh(&mut self) {
		let perf_path = format!("/tmp/perf-{}.map", self.pid);
		match fs::read_to_string(&perf_path) {
			Ok(perf_maps) => {
				//dbg!(&perf_maps);
				match self.push_perf_maps(perf_maps.clone()) {
					Err(e) => { self.err = Some(e); }
					_ => {}
				}
			},
			Err(e) => {
				self.err = Some(ProcError(e.to_string()));
			}
		}
		//dbg!(&self.ranges);
	}
	fn cleanup(&mut self) {}
	fn resolve(&mut self, addr: u64) -> Option<Symbol> {

		let i = self
			.ranges
			.binary_search_by(|e| binary_search_proc_range(e, addr));

		if i.is_err() {
			return Some(Symbol::default());
		}
		let rr = self.ranges.get(i.unwrap()).unwrap();

		Some(Symbol {
			start: rr.start_addr.clone(),
			name: rr.pathname.clone(),
			module: format!("/tmp/perf-{}.map", self.pid),
		})
	}
}

impl PerfSymbolTable {

	pub fn new(pid: i32) -> Self {
		Self {
			pid,
			ranges: Vec::new(),
			err: None,
		}
	}

	fn push_perf_maps(&mut self, proc_maps: String) -> crate::error::Result<()> {
		self.ranges.clear();
		self.ranges = match parse_perf_maps_executable_modules(proc_maps.deref()) {
			Ok(maps) => maps,
			Err(err) => return Err(err),
		};
		Ok(())
	}
}

fn binary_search_proc_range(mr: &ProcMap, pc: u64) -> std::cmp::Ordering {
	if pc < mr.start_addr {
		Greater
	} else if pc >= mr.end_addr {
		Less
	} else {
		Equal
	}
}

pub fn parse_perf_maps_executable_modules(perf_maps: &str) -> crate::error::Result<Vec<ProcMap>> {
	let mut modules = Vec::new();
	let mut remaining = perf_maps;
	while !remaining.is_empty() {
		let nl = remaining
			.chars()
			.position(|x| x == '\n')
			.unwrap_or(remaining.len());
		let (line, rest) = remaining.split_at(nl);
		remaining = if rest.is_empty() { rest } else { &rest[1..] };
		if line.is_empty() {
			continue;
		}
		if let Some(module) = parse_perf_map_line(line) {
			//"{:?}", module);
			modules.push(module);
		}
	}
	Ok(modules)
}

// ffff7c045b40 10c arrayof_jint_disjoint_arraycopy
fn parse_perf_map_line(line: &str) -> Option<ProcMap> {
	let mut parts = line.split(' ');
	let start_addr_bytes = parts.next().unwrap();
	let size = parts.next().unwrap();
	let pathname = line.rsplit(' ').next().unwrap();

	let perms = ProcMapPermissions::default();
	let start_addr = u64::from_str_radix(start_addr_bytes, 16).unwrap();
	let end_addr = start_addr + u64::from_str_radix(size, 16).unwrap();

	let res = ProcMap {
		start_addr,
		end_addr,
		perms,
		offset: 0,
		dev: 0,
		inode: 0,
		pathname: pathname.to_string(),
	};
	Some(res)
}
