pub mod metrics;
pub mod sd;
pub mod cpuonline;
pub mod session;
pub mod pprof;
pub mod sync;
pub mod wait_group;
pub mod reader;
pub mod perf_event;
pub mod epoll;
pub mod symtab;
mod map;

pub(crate) const PERF_EVENT_IOC_ENABLE: core::ffi::c_int = 9216;
pub(crate) const PERF_EVENT_IOC_DISABLE: core::ffi::c_int = 9217;
pub(crate) const PERF_EVENT_IOC_SET_BPF: core::ffi::c_int = 1074013192;
