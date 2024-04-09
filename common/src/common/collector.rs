use crate::ebpf::pprof::ProfileBuilders;
use crate::ebpf::sd::target::Target;
use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SampleType {
    Cpu = 0,
    Mem = 1,
}

pub struct ProfileSample<'a> {
    pub target: &'a Target,
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

pub fn collect<S>(builders: &mut ProfileBuilders, mut collector: S) -> Result<()> where S: SamplesCollector {
    collector.collect_profiles(|sample: ProfileSample| {
        builders.add_sample(sample);
    }).unwrap();
    Ok(())
}