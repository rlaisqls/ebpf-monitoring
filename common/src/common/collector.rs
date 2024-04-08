use crate::ebpf::pprof::ProfileBuilders;
use crate::ebpf::sd::target::Target;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    fn collect_profiles<F>(&mut self, callback: F) -> crate::error::Result<()>
        where F: FnMut(ProfileSample);
}
type CollectProfilesCallback = fn(ProfileSample);

pub fn collect(builders: &mut ProfileBuilders, collector: &mut dyn SamplesCollector) -> crate::error::Result<()> {
    collector.collect_profiles(|sample| {
        builders.add_sample(sample);
    })
}