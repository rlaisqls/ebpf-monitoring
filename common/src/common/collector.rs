use std::sync::{Arc, Mutex, MutexGuard};
use crate::ebpf::pprof::ProfileBuilders;
use crate::ebpf::sd::target::EbpfTarget;
use crate::ebpf::session::Session;
use crate::error::Result;


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SampleType {
    Cpu = 0,
    Mem = 1,
}

pub struct ProfileSample<'a> {
    pub target: &'a EbpfTarget,
    pub pid: u32,
    pub sample_type: SampleType,
    pub aggregation: bool,
    pub stack: Vec<String>,
    pub value: u64,
    pub value2: u64,
}

pub const SAMPLE_TYPE_CPU: SampleType = SampleType::Cpu;
pub const SAMPLE_TYPE_MEM: SampleType = SampleType::Mem;

pub trait SamplesCollector {
    fn collect_profiles<F>(&mut self, callback: F)-> Result<()>
        where F: Fn(ProfileSample);
}

pub fn collect<S>(builders: Arc<Mutex<ProfileBuilders>>, collector: &mut MutexGuard<S>) -> Result<()> where S: SamplesCollector {
    collector.collect_profiles(|sample: ProfileSample| {
        if let Ok(mut b) = builders.lock() {
            b.add_sample(sample);
        }
    }).unwrap();
    Ok(())
}

impl SamplesCollector for Session<'_> {
    fn collect_profiles<F>(&mut self, callback: F) -> Result<()> where F: Fn(ProfileSample) {
        if let Ok(mut sym_cache) = self.sym_cache.lock() {
            sym_cache.next_round();
            self.round_number += 1;
        }
        self.collect_regular_profile(callback).unwrap();
        self.cleanup();
        Ok(())
    }
}