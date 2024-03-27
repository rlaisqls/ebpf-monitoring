pub mod metrics;
pub mod symtab;
pub mod sd;
pub mod cpuonline;
pub mod dwarfdump;
pub mod session;
pub mod pprof;
pub mod perf_event;
pub mod sync;
mod kprobe;


pub(crate) const PERF_EVENT_IOC_ENABLE: core::ffi::c_int = 9216;
pub(crate) const PERF_EVENT_IOC_DISABLE: core::ffi::c_int = 9217;
pub(crate) const PERF_EVENT_IOC_SET_BPF: core::ffi::c_int = 1074013192;